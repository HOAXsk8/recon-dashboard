#!/bin/bash

# Run admin initialization (checks if admin already exists)
echo "--- Initializing System ---"
python3 init_admin.py

# Start the dashboard application
echo "--- Starting Recon Dashboard ---"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
