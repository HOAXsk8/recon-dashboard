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

async def fetch_all_work():
    """
    Fetch all root domains and subdomains that need analysis.
    Returns a list of tasks: {'root_id': ObjectId, 'target': 'name', 'type': 'root'|'subdomain', 'data': {...}}
    """
    tasks = []
    cursor = domains_col.find({})
    docs = await cursor.to_list(length=100)
    for doc in docs:
        root_domain = doc.get("domain")
        root_id = doc["_id"]
        
        # 1. Task for the root domain itself
        root_systems = [s for s in doc.get("systems", []) if s.get("target") == root_domain]
        root_webapps = [w for w in doc.get("web_applications", []) if w.get("target") == root_domain]
        
        tasks.append({
            "root_id": root_id,
            "target": root_domain,
            "type": "root",
            "data": {
                "domain": root_domain,
                "infrastructure": doc.get("infrastructure", {}),
                "systems": root_systems,
                "web_applications": root_webapps,
                "recon_date": doc.get("added_at"),
                "whois": doc.get("whois_raw", "N/A")
            }
        })
        
        # 2. Tasks for each subdomain
        if doc.get("infrastructure") and doc["infrastructure"].get("subdomains"):
            for sub in doc["infrastructure"]["subdomains"]:
                sub_name = sub.get("name")
                if not sub_name: continue
                
                sub_systems = [s for s in doc.get("systems", []) if s.get("target") == sub_name]
                sub_webapps = [w for w in doc.get("web_applications", []) if w.get("target") == sub_name]
                
                tasks.append({
                    "root_id": root_id,
                    "target": sub_name,
                    "type": "subdomain",
                    "data": {
                        "domain": sub_name,
                        "root_domain": root_domain,
                        "systems": sub_systems,
                        "web_applications": sub_webapps,
                        "recon_date": sub.get("added_at")
                    }
                })
                
    return tasks

async def update_analysis(task, summary, exploit_summary):
    """
    Update the database with the generated analysis.
    If it's a root domain, update top-level fields.
    If it's a subdomain, update the subdomain_summaries map.
    """
    if task["type"] == "root":
        await domains_col.update_one(
            {"_id": task["root_id"]},
            {"$set": {
                "summary": summary,
                "exploit_summary": exploit_summary
            }}
        )
    else:
        # Use dot notation to update a specific key in the subdomain_summaries object
        # Escape the subdomain name if it contains dots (MongoDB handles dots in field names with care, 
        # but here we are using them as keys in a nested object)
        # Actually, field names with dots are allowed in newer MongoDB versions, but safer to use a nested path if possible.
        # But here we want a map. We'll use the target name as the key.
        field_path = f"subdomain_summaries.{task['target'].replace('.', '_DOT_')}"
        await domains_col.update_one(
            {"_id": task["root_id"]},
            {"$set": {
                field_path: {
                    "summary": summary,
                    "exploit_summary": exploit_summary,
                    "target": task["target"]
                }
            }}
        )
