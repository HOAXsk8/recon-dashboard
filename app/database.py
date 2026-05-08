import os
import urllib.parse
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient

# Re-use credentials from recon-agent setup
PASSWORD = urllib.parse.quote_plus("5I2ZKu83YQL7+fGu")
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

# Sync client for setup scripts
sync_client = MongoClient(MONGO_URI)
sync_db = sync_client[DB_NAME]
sync_leads_col = sync_db["leads"]
sync_scanners_col = sync_db["scanners"]
