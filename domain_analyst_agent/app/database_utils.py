import os
import urllib.parse
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from dotenv import load_dotenv

load_dotenv()

MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD")
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
DB_NAME = "recon_db"

if not MONGO_ROOT_PASSWORD:
    # Try to load from sibling project if not in environment
    try:
        with open("../.env", "r") as f:
            for line in f:
                if line.startswith("MONGO_ROOT_PASSWORD="):
                    MONGO_ROOT_PASSWORD = line.split("=")[1].strip()
                    break
    except Exception:
        pass

if not MONGO_ROOT_PASSWORD:
    raise RuntimeError("MONGO_ROOT_PASSWORD environment variable is not set")

PASSWORD = urllib.parse.quote_plus(MONGO_ROOT_PASSWORD)
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"

client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]
domains_col = db["domains"]

async def fetch_pending_domains():
    """
    Fetch domains that are scanned but haven't been analyzed yet.
    We look for domains where 'scanned' is True and 'summary' is missing or empty.
    """
    query = {
        "scanned": True,
        "$or": [
            {"summary": {"$exists": False}},
            {"summary": ""},
            {"summary": None}
        ]
    }
    cursor = domains_col.find(query)
    return await cursor.to_list(length=10) # Process in batches

async def update_domain_analysis(domain_id, summary, exploit_summary):
    """
    Update the domain record with the generated analysis and exploitation suggestions.
    """
    await domains_col.update_one(
        {"_id": ObjectId(domain_id)},
        {"$set": {
            "summary": summary,
            "exploit_summary": exploit_summary
        }}
    )
