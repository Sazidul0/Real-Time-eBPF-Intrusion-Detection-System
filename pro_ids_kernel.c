#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/inet.h>

#define MAX_STRING_SIZE 256
#define TASK_COMM_LEN 16

// Finalized event types
enum event_type_t {
    EVENT_TYPE_EXEC,
    EVENT_TYPE_CONNECT,
    EVENT_TYPE_OPEN,
};

// Finalized event structure
struct event_t {
    enum event_type_t type;
    u64 timestamp;
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    char filename[MAX_STRING_SIZE];
    u16 family;
    u16 dport;
    union {
        u32 v4_addr;
        u8 v6_addr[16];
    } daddr;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(tainted_ppids, u32, u64);
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);

// Helper functions
static __always_inline u32 get_ppid(struct task_struct *task) {
    if (task->real_parent) return task->real_parent->tgid;
    return 0;
}

static __always_inline void get_parent_comm(struct task_struct *task, char *buf) {
    if (task->real_parent) {
        bpf_probe_read_kernel_str(buf, TASK_COMM_LEN, task->real_parent->comm);
    }
}

// --- CORRECTED TRACEPOINT HANDLER for execve ---
int trace_exec_entry(struct tracepoint__syscalls__sys_enter_execve *args) {
    int zero = 0;
    struct event_t *event = scratch.lookup(&zero);
    if (!event) return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __builtin_memset(event, 0, sizeof(*event));

    event->type = EVENT_TYPE_EXEC;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = get_ppid(task);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_parent_comm(task, event->parent_comm);

    // Read filename directly from the tracepoint arguments struct
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), (const char*)args->filename);

    events.perf_submit(args, event, sizeof(*event));
    return 0;
}

// --- KPROBE for connect (still the best method for this) ---
int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    u16 family_val;
    bpf_probe_read_kernel(&family_val, sizeof(family_val), &sk->__sk_common.skc_family);
    if (family_val != AF_INET && family_val != AF_INET6) return 0;

    int zero = 0;
    struct event_t *event = scratch.lookup(&zero);
    if (!event) return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __builtin_memset(event, 0, sizeof(*event));

    event->type = EVENT_TYPE_CONNECT;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = get_ppid(task);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_parent_comm(task, event->parent_comm);

    event->family = family_val;
    bpf_probe_read_kernel(&event->dport, sizeof(event->dport), &sk->__sk_common.skc_dport);
    event->dport = ntohs(event->dport);

    if (family_val == AF_INET) {
        bpf_probe_read_kernel(&event->daddr.v4_addr, sizeof(u32), &sk->__sk_common.skc_daddr);
    } else {
        bpf_probe_read_kernel(&event->daddr.v6_addr, sizeof(event->daddr.v6_addr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// --- Common handler for file open tracepoints ---
static __always_inline int process_open_event(void* ctx, const char __user* filename_ptr) {
    char filename[MAX_STRING_SIZE];
    bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr);

    // KERNEL PRE-FILTER
    if (
        (filename[0] == '/' && filename[1] == 'e' && filename[2] == 't' && filename[3] == 'c' && filename[4] == '/') ||
        (filename[0] == '/' && filename[1] == 'r' && filename[2] == 'o' && filename[3] == 'o' && filename[4] == 't' && filename[5] == '/')
    ) {
        int zero = 0;
        struct event_t *event = scratch.lookup(&zero);
        if (!event) return 0;

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        __builtin_memset(event, 0, sizeof(*event));

        event->type = EVENT_TYPE_OPEN;
        event->timestamp = bpf_ktime_get_ns();
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->ppid = get_ppid(task);
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        get_parent_comm(task, event->parent_comm);
        __builtin_memcpy(event->filename, filename, sizeof(event->filename));

        events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

// CORRECTED TRACEPOINT HANDLER for open
int trace_open_entry(struct tracepoint__syscalls__sys_enter_open *args) {
    return process_open_event(args, (const char __user*)args->filename);
}

// CORRECTED TRACEPOINT HANDLER for openat
int trace_openat_entry(struct tracepoint__syscalls__sys_enter_openat *args) {
    return process_open_event(args, (const char __user*)args->filename);
}
