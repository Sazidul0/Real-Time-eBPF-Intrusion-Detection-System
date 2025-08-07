# Real-Time eBPF Intrusion Detection System

This project implements a professional-grade Intrusion Detection System (IDS) using **eBPF** (extended Berkeley Packet Filter) to monitor system activities in real-time. It captures process executions, file operations, and network connections, applying customizable rules to detect suspicious activities. The system logs alerts to a file and visualizes them through a **Grafana** dashboard powered by **Loki** and **Promtail** for log aggregation and analysis.

## Features
- **Real-Time Monitoring**: Tracks `execve`, `open`, `openat`, and `connect` system calls using eBPF.
- **Rule-Based Detection**: Supports both stateless and stateful rules defined in a YAML configuration file.
- **Customizable Rules**: Detects suspicious activities like executions from temporary directories, web server shell spawning, and potential data exfiltration.
- **Log Visualization**: Integrates with Grafana, Loki, and Promtail for a user-friendly dashboard to visualize alerts by severity, rule, and process details.
- **Dynamic Rule Updates**: Automatically reloads rules when the configuration file changes (requires `watchdog`).
- **Lightweight and Efficient**: Leverages eBPF for low-overhead kernel-level monitoring.

## Project Structure
- **`pro_ids_kernel.c`**: eBPF kernel code to hook system calls and collect events.
- **`pro_ids_userspace.py`**: Python userspace program to process events, apply rules, and log alerts.
- **`pro_rules.yaml`**: Rule configuration file defining detection logic.
- **`IDS Log Dashboard.json`**: Grafana dashboard configuration for visualizing alerts.
- **`ids_alerts.log`**: Sample log file containing generated alerts.
- **`setupUI.sh`**: Script to set up Grafana, Loki, and Promtail containers.
- **`UIStart.sh`**: Script to start/stop the UI containers.
- **`cleanUP.sh`**: Script to clean up Docker containers and network.

## Prerequisites
- **Operating System**: Linux (Ubuntu/Debian recommended) with kernel headers installed.
- **Dependencies**:
  - `build-essential`, `python3-dev`, `python3-pip`
  - `bpfcc-tools`, `libbpfcc-dev`, `linux-headers-$(uname -r)`
  - Python packages: `pyyaml`, `watchdog`
  - Docker (for UI components: Grafana, Loki, Promtail)
- **Privileges**: Root privileges (`sudo`) are required to run the eBPF program.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Sazidul0/Real-Time-eBPF-Intrusion-Detection-System.git
   cd real-time-ebpf-ids
   ```

2. **Install System Dependencies**:
   ```bash
   sudo apt-get update
   sudo apt-get install -y build-essential python3-dev python3-pip
   sudo apt-get install -y bpfcc-tools libbpfcc-dev linux-headers-$(uname -r)
   ```

3. **Install Python Dependencies**:
   ```bash
   pip3 install pyyaml watchdog
   ```

4. **Set Up Docker (for UI)**:
   Ensure Docker is installed and running:
   ```bash
   sudo apt-get install -y docker.io
   sudo systemctl start docker
   sudo systemctl enable docker
   ```

## Usage
### Step 1: Run the IDS
Start the eBPF IDS to monitor system activities and generate logs:
```bash
sudo -E python3 pro_ids_userspace.py --rules pro_rules.yaml --logfile ids_alerts.log
```
- `--rules`: Path to the rule file (default: `pro_rules.yaml`).
- `--logfile`: Path to the output log file (default: `ids_alerts.log`).
- The program monitors system calls and logs alerts based on the defined rules.
- Press `Ctrl+C` to stop the program.

### Step 2: Set Up the UI
1. **Configure the UI Environment**:
   Run the setup script to create Docker containers for Grafana, Loki, and Promtail:
   ```bash
   chmod +x setupUI.sh
   ./setupUI.sh
   ```
   - Provide the absolute path to the `ids_alerts.log` file when prompted.
   - The script creates configuration files and starts the containers.

2. **Start/Stop UI Containers**:
   Use the `UIStart.sh` script to manage the containers:
   ```bash
   chmod +x UIStart.sh
   ./UIStart.sh
   ```
   - Select option `1` to start Grafana, Loki, and Promtail.
   - Select option `2` to stop them.
   - Select option `3` to exit.

3. **Access Grafana**:
   - Open a browser and navigate to `http://localhost:3000`.
   - Log in with default credentials:
     - Username: `admin`
     - Password: `admin` (change the password when prompted).
   - Add a Loki data source:
     - Go to **Configuration** (gear icon) → **Data Sources** → **Add data source**.
     - Select **Loki** and set the URL to `http://loki:3100`.
     - Click **Save & test**.
   - Import the dashboard:
     - Go to **Dashboards** → **Import**.
     - Upload `IDS Log Dashboard.json` or paste its contents.
     - The dashboard displays high/medium/low severity alerts, a severity distribution pie chart, and detailed logs.

### Step 3: Clean Up
To stop and remove Docker containers and the network:
```bash
chmod +x cleanUP.sh
./cleanUP.sh
```

## Rules Configuration
The `pro_rules.yaml` file defines detection rules. Each rule specifies:
- `name`: Rule identifier.
- `description`: Description of the detected activity.
- `enabled`: Whether the rule is active (`true`/`false`).
- `event`: Event type (`exec`, `connect`, etc.).
- `severity`: Alert severity (`high`, `medium`, `low`).
- `match`: Conditions for stateless rules (e.g., regex for filenames or processes).
- `stateful`: Conditions for stateful rules (e.g., tracking file access followed by network activity).

Example rule:
```yaml
- name: "Suspicious Execution From Temp"
  description: "A process was executed from a temporary or world-writable directory."
  enabled: true
  event: "exec"
  severity: "medium"
  match:
    filename_regex: "^/(tmp|var/tmp|dev/shm)/.*"
```

Modify `pro_rules.yaml` to add or customize rules. Changes are automatically reloaded if `watchdog` is installed.

## Dashboard Features
The Grafana dashboard (`IDS Log Dashboard.json`) provides:
- **Severity Panels**: Displays counts of high, medium, and low severity alerts.
- **Severity Distribution**: A pie chart showing the proportion of alerts by severity.
- **Alert Details**: A table with process names, parent processes, and timestamps.
- **Log Stream**: A detailed view of logs with filtering by severity, rule name, and search terms.
![UI](https://github.com/Sazidul0/Real-Time-eBPF-Intrusion-Detection-System.git)

## Example Alerts
Sample alerts from `ids_alerts.log`:
- **Medium Severity**: Execution of `/tmp/test.sh` (rule: Suspicious Execution From Temp).
- **High Severity**: Process accessing `/etc/shadow` followed by a network connection (rule: Potential Data Exfiltration via Network).
- **Low Severity**: Package manager activity (e.g., `apt`, `dpkg`).

## Troubleshooting
- **No Logs in Grafana**: Ensure the `ids_alerts.log` path in `promtail-config.yaml` matches the file specified in `setupUI.sh`.
- **eBPF Errors**: Verify kernel headers and `bpfcc-tools` are installed for the current kernel (`uname -r`).
- **Docker Issues**: Check if Docker is running (`sudo systemctl status docker`) and ports are not in use.
- **Rule Not Triggering**: Confirm the rule is `enabled: true` in `pro_rules.yaml` and matches the event type.

## Contributing
Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
