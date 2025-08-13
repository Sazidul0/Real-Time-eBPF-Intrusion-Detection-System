#!/bin/bash

while true; do
    echo "Select an option:"
    echo "1) Start Grafana, Loki, and Promtail containers"
    echo "2) Stop Grafana, Loki, and Promtail containers"
    echo "3) Clean up containers and network"
    echo "4) Exit"
    read -p "Enter your choice (1-4): " choice

    case $choice in
        1)
            echo "Starting containers..."
            docker start grafana || echo "Failed to start Grafana"
            docker start loki || echo "Failed to start Loki"
            docker start promtail || echo "Failed to start Promtail"
            echo "Containers started."
            ;;
        2)
            echo "Stopping containers..."
            docker stop grafana || echo "Failed to stop Grafana"
            docker stop loki || echo "Failed to stop Loki"
            docker stop promtail || echo "Failed to stop Promtail"
            echo "Containers stopped."
            ;;
        3)
            echo "Stopping containers..."
            docker stop grafana loki promtail &> /dev/null || true
            echo "Removing containers..."
            docker rm grafana loki promtail &> /dev/null || true
            echo "Removing Docker network..."
            docker network rm siem-net &> /dev/null || true
            echo "Cleanup complete."
            ;;
        4)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid choice. Please select 1, 2, 3, or 4."
            ;;
    esac
done
