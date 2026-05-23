import asyncio
import os
import urllib.parse
from motor.motor_asyncio import AsyncIOMotorClient
import re

MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD")
if not MONGO_ROOT_PASSWORD:
    raise ValueError("MONGO_ROOT_PASSWORD environment variable is not set")
PASSWORD = urllib.parse.quote_plus(MONGO_ROOT_PASSWORD)
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"
DB_NAME = "recon_db"

async def migrate_alerts():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]
    leads_col = db["leads"]

    print("--- Migrating Old Alert Links ---")
    
    cursor = leads_col.find({"exploitation_suggestions": {"$regex": "Navigate to `http"}})
    count = 0
    async for lead in cursor:
        old_text = lead["exploitation_suggestions"]
        # Regex to find the URL inside backticks and convert to Markdown link
        # 1. **Verify Exposure**: Navigate to `URL`
        new_text = re.sub(r"Navigate to `(https?://[^`]+)`", r"Navigate to [\1](\1)", old_text)
        
        if old_text != new_text:
            await leads_col.update_one({"_id": lead["_id"]}, {"$set": {"exploitation_suggestions": new_text}})
            count += 1

    print(f"--- Migrated {count} alerts ---")

if __name__ == "__main__":
    asyncio.run(migrate_alerts())
