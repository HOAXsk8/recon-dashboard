import os
import urllib.parse
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient

# Re-use credentials from recon-agent setup
MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD")
if not MONGO_ROOT_PASSWORD:
    raise RuntimeError("MONGO_ROOT_PASSWORD environment variable is not set")
PASSWORD = urllib.parse.quote_plus(MONGO_ROOT_PASSWORD)
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"
DB_NAME = "recon_db"

# Async client for FastAPI
client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]

# Collections
domains_col = db["domains"]
users_col = db["users"]
audit_logs_col = db["audit_logs"]
leads_col = db["leads"]
scanners_col = db["scanners"]
settings_col = db["settings"]
tasks_col = db["tasks"]
source_maps_col = db["recovered_source_maps"]
findings_col = db["findings"]
workspaces_col = db["workspaces"]

# Sync client for setup scripts
sync_client = MongoClient(MONGO_URI)
sync_db = sync_client[DB_NAME]
sync_leads_col = sync_db["leads"]
sync_scanners_col = sync_db["scanners"]
sync_settings_col = sync_db["settings"]
sync_tasks_col = sync_db["tasks"]
sync_findings_col = sync_db["findings"]
sync_workspaces_col = sync_db["workspaces"]
