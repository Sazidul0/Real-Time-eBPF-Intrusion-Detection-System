#!/bin/bash
echo "Stopping containers..."
docker stop grafana loki promtail &> /dev/null || true

echo "Removing containers..."
docker rm grafana loki promtail &> /dev/null || true

echo "Removing Docker network..."
docker network rm siem-net &> /dev/null || true

echo "Cleanup complete."
