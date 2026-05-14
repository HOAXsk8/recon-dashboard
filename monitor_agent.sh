#!/bin/bash

# Configuration
SERVICE_NAME="recon-agent"
CHECK_INTERVAL=60 # seconds

echo "--- Recon Agent Monitor Started ---"
echo "Monitoring $SERVICE_NAME every $CHECK_INTERVAL seconds..."

while true; do
    # Check if the container is running
    # We use grep -q to check for an exact match of the container name
    if ! sudo docker ps --format '{{.Names}}' | grep -q "^${SERVICE_NAME}$"; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ALERT: $SERVICE_NAME is not running. Attempting to start/restart..."
        
        # docker-compose up -d will start the service if it's stopped or not created
        sudo docker-compose up -d $SERVICE_NAME
        
        if [ $? -eq 0 ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: $SERVICE_NAME recovery initiated."
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to recover $SERVICE_NAME."
        fi
    fi
    
    sleep $CHECK_INTERVAL
done
