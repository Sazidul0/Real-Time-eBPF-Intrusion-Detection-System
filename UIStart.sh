#!/bin/bash

while true; do
    echo "Select an option:"
    echo "1) Start Grafana, Loki, and Promtail containers"
    echo "2) Stop Grafana, Loki, and Promtail containers"
    echo "3) Exit"
    read -p "Enter your choice (1-3): " choice

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
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid choice. Please select 1, 2, or 3."
            ;;
    esac
done
