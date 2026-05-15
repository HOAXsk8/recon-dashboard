import asyncio
import os
import datetime
import urllib.parse
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD", "5I2ZKu83YQL7+fGu")
PASSWORD = urllib.parse.quote_plus(MONGO_ROOT_PASSWORD)
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"
DB_NAME = "recon_db"

async def force_trigger():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]
    domains_col = db["domains"]
    tasks_col = db["tasks"]

    print("--- Triggering New Scans for New Tools ---")
    
    # 1. Reset scanned flag for all domains to trigger discovery if needed
    # await domains_col.update_many({}, {"$set": {"scanned": False}})
    
    # 2. Find all systems with web ports and create tasks directly
    cursor = domains_col.find({})
    async for domain in cursor:
        root_domain = domain["domain"]
        systems = domain.get("systems", [])
        for sys in systems:
            target = sys.get("target")
            services = sys.get("services", [])
            for svc in services:
                port = svc.get("port")
                service = svc.get("service", "").lower()
                
                if port in [80, 443, 8080, 8443, 3000, 5000, 8000] or service in ['http', 'https']:
                    proto = 'https' if port in [443, 8443] or service == 'https' else 'http'
                    
                    # Create directory_hunt task
                    exists_dh = await tasks_col.find_one({"target": target, "port": port, "task_type": "directory_hunt"})
                    if not exists_dh:
                        await tasks_col.insert_one({
                            "root_domain": root_domain,
                            "target": target,
                            "protocol": proto,
                            "port": port,
                            "task_type": "directory_hunt",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        })
                        print(f"Queued directory_hunt for {target}:{port}")

                    # Create tech_fingerprint task
                    exists_tf = await tasks_col.find_one({"target": target, "port": port, "task_type": "tech_fingerprint"})
                    if not exists_tf:
                        await tasks_col.insert_one({
                            "root_domain": root_domain,
                            "target": target,
                            "protocol": proto,
                            "port": port,
                            "task_type": "tech_fingerprint",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        })
                        print(f"Queued tech_fingerprint for {target}:{port}")

    print("--- Done ---")

if __name__ == "__main__":
    asyncio.run(force_trigger())
