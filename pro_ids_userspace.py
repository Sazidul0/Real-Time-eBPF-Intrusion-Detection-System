#!/usr/bin/python3
import argparse
import json
import logging
import re
import socket
import sys
import threading
import yaml
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from bcc import BPF
from ctypes import (
    Structure, Union, POINTER,
    c_uint, c_uint64, c_uint32, c_ushort,
    c_char, c_uint8, cast
)

RULES = {}
RULES_LOCK = threading.Lock()

class Daddr(Union):
    _fields_ = [("v4_addr", c_uint32), ("v6_addr", c_uint8 * 16)]

class Event(Structure):
    _fields_ = [
        ("type", c_uint), ("timestamp", c_uint64),
        ("pid", c_uint32), ("ppid", c_uint32),
        ("comm", c_char * 16), ("parent_comm", c_char * 16),
        ("filename", c_char * 256),
        ("family", c_ushort), ("dport", c_ushort),
        ("daddr", Daddr),
    ]

def setup_logging(logfile):
    logger = logging.getLogger('IDS')
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        if logfile:
            file_handler = logging.FileHandler(logfile)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    return logger

def load_rules(rule_file):
    global RULES
    try:
        with open(rule_file, 'r') as f:
            new_rules = yaml.safe_load(f)
            for rule in new_rules.get('rules', []):
                if not rule.get('enabled', False): continue
                for key in list(rule.get('match', {}).keys()):
                    if key.endswith('_regex'):
                        rule['match'][key + '_compiled'] = re.compile(rule['match'][key])
                if 'stateful' in rule and 'source_event_match' in rule['stateful']:
                    match_dict = rule['stateful']['source_event_match']
                    for key in list(match_dict.keys()):
                        if key.endswith('_regex'):
                            match_dict[key + '_compiled'] = re.compile(match_dict[key])
            with RULES_LOCK:
                RULES = new_rules
            logger.info(f"Successfully loaded {len(RULES.get('rules', []))} rules from {rule_file}")
    except Exception as e:
        logger.error(f"Failed to load or parse rule file {rule_file}: {e}")

class RuleChangeHandler(FileSystemEventHandler):
    def __init__(self, rule_file):
        self.rule_file = rule_file
        super().__init__()

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(self.rule_file):
            logger.info("Rule file changed. Reloading...")
            load_rules(self.rule_file)

def ip_to_str(addr_union, family):
    if family == socket.AF_INET: return str(IPv4Address(addr_union.v4_addr))
    if family == socket.AF_INET6: return str(IPv6Address(bytes(addr_union.v6_addr)))
    return "unknown"

def log_alert(rule, event, details_str=""):
    alert = {
        "timestamp": datetime.now().isoformat(), "rule_name": rule['name'],
        "severity": rule.get('severity', 'info'), "description": rule['description'],
        "process_name": event.comm.decode('utf-8', 'replace'), "pid": event.pid,
        "parent_process_name": event.parent_comm.decode('utf-8', 'replace'), "ppid": event.ppid,
        "details": details_str
    }
    logger.warning(json.dumps(alert))

def process_event(cpu, data, size):
    try:
        event = cast(data, POINTER(Event)).contents
        if event.type == 0: event_type_str = "EXEC"
        elif event.type == 1: event_type_str = "CONNECT"
        elif event.type == 2:
            handle_open_event(event)
            return
        else: return

        with RULES_LOCK:
            if not RULES: return
            for rule in RULES.get('rules', []):
                if not rule.get('enabled', False): continue
                if not rule.get('stateful') and rule['event'].upper() == event_type_str:
                    check_single_event_rule(rule, event)
                elif rule.get('stateful') and rule['event'].upper() == event_type_str:
                    check_stateful_rule(rule, event)
    except Exception as e:
        logger.error(f"Error processing event: {e}")

def handle_open_event(event):
    tainted_ppids_map = b["tainted_ppids"]
    filename = event.filename.decode('utf-8', 'replace')
    with RULES_LOCK:
        for rule in RULES.get('rules', []):
            if not rule.get('enabled', False) or not rule.get('stateful'):
                continue
            
            source_match = rule['stateful']['source_event_match']
            if source_match['event'].upper() != 'OPEN':
                continue

            if 'filename_regex_compiled' in source_match:
                if source_match['filename_regex_compiled'].search(filename):
                    ppid_key = c_uint32(event.ppid)
                    timestamp = c_uint64(event.timestamp)
                    tainted_ppids_map[ppid_key] = timestamp
                    break

def check_single_event_rule(rule, event):
    match_data = {}
    is_match = True
    if event.type == 0:
        match_data['filename'] = event.filename.decode('utf-8', 'replace')
        match_data['child_process'] = event.comm.decode('utf-8', 'replace')
        match_data['parent_process'] = event.parent_comm.decode('utf-8', 'replace')

    for key, compiled_regex in rule.get('match', {}).items():
        if not key.endswith('_compiled'): continue
        data_key = key.replace('_regex_compiled', '')
        if data_key not in match_data or not compiled_regex.search(match_data[data_key]):
            is_match = False; break
    if is_match:
        details = f"Matched on process: {match_data.get('child_process', 'N/A')}, file: {match_data.get('filename', 'N/A')}"
        log_alert(rule, event, details)

def check_stateful_rule(rule, event):
    tainted_ppids_map = b["tainted_ppids"]
    ppid_key = c_uint32(event.ppid)
    if ppid_key in tainted_ppids_map:
        taint_timestamp_ns = tainted_ppids_map[ppid_key].value
        event_timestamp_ns = event.timestamp
        time_window_ns = rule['stateful']['time_window_seconds'] * 1_000_000_000
        
        if (event_timestamp_ns - taint_timestamp_ns) <= time_window_ns:
            dest_ip = ip_to_str(event.daddr, event.family)
            dest_port = event.dport
            log_alert(rule, event, f"Parent process was tainted. Child made network connection to {dest_ip}:{dest_port}")
            del tainted_ppids_map[ppid_key]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional-Grade eBPF IDS")
    parser.add_argument("-r", "--rules", default="pro_rules.yaml", help="Path to the rule file.")
    parser.add_argument("-l", "--logfile", default="ids_alerts.log", help="Path to the log file.")
    args = parser.parse_args()

    logger = setup_logging(args.logfile)
    load_rules(args.rules)

    observer = None
    if WATCHDOG_AVAILABLE:
        event_handler = RuleChangeHandler(args.rules)
        observer = Observer()
        observer.schedule(event_handler, path='.', recursive=False)
        observer.start()
        logger.info(f"Started watching {args.rules} for changes.")
    else:
        logger.warning("watchdog library not found. Rule reloading is disabled.")

    with open('pro_ids_kernel.c', 'r') as f:
        bpf_text = f.read()

    b = BPF(text=bpf_text)

    # --- CORRECTED ATTACHMENT LOGIC ---
    b.attach_kprobe(event="tcp_connect", fn_name="trace_connect")

    # Attach to the tracepoints using the precise C function names
    b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_exec_entry")
    b.attach_tracepoint(tp="syscalls:sys_enter_open", fn_name="trace_open_entry")
    b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_openat_entry")

    b["events"].open_perf_buffer(process_event)
    logger.info("IDS is running. Monitoring for suspicious activity... Press Ctrl-C to exit.")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("")
    finally:
        if observer:
            observer.stop()
            observer.join()
        logger.info("Shutting down.")
        sys.exit(0)
