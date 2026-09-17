#!/bin/bash

# Wait for MongoDB to be ready
echo "--- Waiting for MongoDB to become ready ---"
for i in {1..30}; do
    python3 -c "
import os, sys
from app.database import sync_client
try:
    sync_client.admin.command('ping')
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null && break
    sleep 1
done

# Run admin initialization (checks if admin already exists)
echo "--- Initializing System ---"
python3 init_admin.py

# Start the dashboard application
echo "--- Starting Recon Dashboard ---"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir app --reload-dir templates

