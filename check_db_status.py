import asyncio
import urllib.parse
from motor.motor_asyncio import AsyncIOMotorClient

async def check():
    PASSWORD = urllib.parse.quote_plus("5I2ZKu83YQL7+fGu")
    MONGO_URI = f"mongodb://admin:{PASSWORD}@localhost:27017/?authSource=admin"
    client = AsyncIOMotorClient(MONGO_URI)
    db = client["recon_db"]
    leads_col = db["leads"]
    
    statuses = await leads_col.distinct("status")
    print(f"Statuses: {statuses}")
    
    # Also check a few leads to see the schema
    sample = await leads_col.find_one()
    print(f"Sample lead: {sample}")
    
    domains_col = db["domains"]
    sample_domain = await domains_col.find_one()
    print(f"Sample domain: {sample_domain}")

if __name__ == "__main__":
    asyncio.run(check())
