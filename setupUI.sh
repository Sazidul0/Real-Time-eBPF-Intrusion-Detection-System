
#!/bin/bash

# ==============================================================================
# Bash Script to Automate Grafana, Loki, and Promtail Setup for IDS Logs
# ==============================================================================

# --- Colors for better output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Helper Functions ---
info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# --- Check for prerequisites ---
info "Checking for Docker..."
if ! command -v docker &> /dev/null; then
    error "Docker could not be found. Please install Docker before running this script."
fi
if ! docker info &> /dev/null; then
    error "Docker daemon is not running. Please start Docker and try again."
fi
success "Docker is installed and running."

# --- User Input ---
read -p "Please enter the absolute path to your IDS log file: " IDS_LOG_FILE

if [ -z "$IDS_LOG_FILE" ]; then
    error "Log file path cannot be empty."
fi

if [ ! -f "$IDS_LOG_FILE" ]; then
    error "The file '$IDS_LOG_FILE' does not exist. Please check the path."
fi

# Convert the user-provided path to a full, absolute path to prevent issues with 'cd'.
IDS_LOG_FILE=$(readlink -f "$IDS_LOG_FILE")
success "Resolved log file path to: $IDS_LOG_FILE"


# --- Project Setup ---
PROJECT_DIR="grafana-siem"
info "Setting up project directory at ./$PROJECT_DIR"
mkdir -p "$PROJECT_DIR/loki-data"

# --- Set Permissions for Loki Data Directory ---
info "Setting permissions on Loki data directory..."
# This needs to be run before we 'cd' into the directory
sudo chown -R 10001:10001 "$PROJECT_DIR/loki-data"
success "Loki data directory permissions set."

cd "$PROJECT_DIR"

# --- Create Docker Network ---
info "Creating Docker network..."
docker network create siem-network &> /dev/null || true
success "Docker network created."

# --- Create Loki Configuration ---
# (Using the last known good configuration)
info "Creating Loki configuration file..."
cat > loki-config.yaml << EOF
auth_enabled: false
server:
  http_listen_port: 3100
ingester:
  lifecycler:
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
  chunk_idle_period: 5m
  wal:
    enabled: true
    dir: /loki/wal
schema_config:
  configs:
    - from: 2022-01-01
      store: boltdb-shipper
      object_store: filesystem
      schema: v12
      index:
        prefix: index_
        period: 24h
storage_config:
  boltdb_shipper:
    active_index_directory: /loki/index
    cache_location: /loki/boltdb-cache
    cache_ttl: 24h
  filesystem:
    directory: /loki/chunks
compactor:
  working_directory: /loki/compactor
limits_config:
  allow_structured_metadata: false
EOF
success "loki-config.yaml created."

# --- Create Promtail Configuration ---
# (Using the last known good configuration)
info "Creating Promtail configuration file with parsing fix..."
cat > promtail-config.yaml << EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /tmp/positions.yaml
clients:
  - url: http://loki:3100/loki/api/v1/push
scrape_configs:
- job_name: ids
  static_configs:
  - targets:
      - localhost
    labels:
      job: ids_logs
      __path__: $IDS_LOG_FILE
  pipeline_stages:
  # ======================================================================
  # START OF FIX: This pipeline handles mixed log formats.
  # ======================================================================
  # Stage 1: Use a specific regex to identify and capture ONLY the JSON alerts.
  # This regex will not match the plain-text info logs (like "IDS is running...").
  # If a line doesn't match, the rest of the pipeline is skipped for that line.
  - regex:
      expression: '.* - (?P<content>\{.*\})$'

  # Stage 2: Parse the captured 'content' as JSON. This stage only runs
  # on lines that successfully matched the regex above.
  - json:
      expressions:
        timestamp: timestamp
        severity: severity
        rule_name: rule_name
      source: content

  # Stage 3: Create Loki labels from the extracted fields. Again, this only
  # runs if the line was a JSON alert.
  - labels:
      severity:
      rule_name:

  # Stage 4: Use the timestamp from within the JSON alert as the official
  # log time. This makes time-based queries in Grafana accurate.
  - timestamp:
      source: timestamp
      format: RFC3339Nano
  # ======================================================================
  # END OF FIX
  # ======================================================================
EOF
success "promtail-config.yaml created."

# --- Run Docker Containers ---
info "Stopping and removing any old containers..."
docker stop grafana loki promtail &> /dev/null || true
docker rm grafana loki promtail &> /dev/null || true
success "Old containers removed."

info "Starting Loki container..."
docker run -d --name loki \
  -v "$(pwd)/loki-config.yaml":/etc/loki/local-config.yaml \
  -v "$(pwd)/loki-data":/loki \
  -p 3100:3100 \
  --network siem-network \
  grafana/loki:latest \
  -config.file=/etc/loki/local-config.yaml

info "Starting Promtail container..."
docker run -d --name promtail \
  -v "$(pwd)/promtail-config.yaml":/etc/promtail/config.yaml \
  -v "$IDS_LOG_FILE":"$IDS_LOG_FILE":ro \
  --network siem-network \
  grafana/promtail:latest \
  -config.file=/etc/promtail/config.yaml

info "Starting Grafana container..."
docker run -d --name grafana \
  -p 3000:3000 \
  --network siem-network \
  grafana/grafana-oss:latest

# --- Final Instructions ---
echo
success "All containers have been started!"
echo
info "Please follow these steps to complete the setup:"
echo -e "1. Open your web browser and go to: ${GREEN}http://localhost:3000${NC}"
echo -e "2. Log in with the default credentials:"
echo -e "   - Username: ${GREEN}admin${NC}"
echo -e "   - Password: ${GREEN}admin${NC} (you will be prompted to change this)"
echo -e "3. In Grafana, go to Configuration (gear icon) -> Data Sources -> Add data source."
echo -e "4. Select ${GREEN}Loki${NC}."
echo -e "5. For the URL, enter: ${GREEN}http://loki:3100${NC}"
echo -e "6. Click ${GREEN}'Save & test'${NC}. You should see a success message."
echo -e "7. You can now import your dashboard JSON. It will work correctly."
