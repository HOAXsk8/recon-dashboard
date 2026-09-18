import asyncio
import datetime
import re
from motor.motor_asyncio import AsyncIOMotorClient
import os

MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
PASSWORD = os.getenv("MONGO_ROOT_PASSWORD", "yrdlQJX9Kixb91wWRl5fOQ")
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"

async def sync_all_cloud_storage():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client["recon_db"]
    domains_col = db["domains"]
    leads_col = db["leads"]

    print("=== STARTING CLOUD STORAGE FOOTPRINT SYNC ===")

    # 1. Fetch all domains for root resolution
    all_domains_docs = await domains_col.find({}, {"domain": 1, "infrastructure.subdomains": 1}).to_list(5000)
    
    def find_parent_domains(target_str):
        t = target_str.strip().lower()
        parents = set()
        for doc in all_domains_docs:
            d = doc["domain"].strip().lower()
            if t == d:
                parents.add(d)
            elif t.endswith("." + d):
                parents.add(d)
            for sub in (doc.get("infrastructure") or {}).get("subdomains", []):
                if sub.get("name", "").strip().lower() == t:
                    parents.add(d)
        if not parents:
            # Fallback to suffix guessing
            parts = t.split(".")
            if len(parts) >= 2:
                parents.add(".".join(parts[-2:]))
        return parents

    def merge_into_list(existing_list, item):
        merged = {}
        for it in (existing_list or []):
            if isinstance(it, dict):
                u = (it.get("url") or it.get("raw") or it.get("name") or "").strip().lower().rstrip("/")
                src = (it.get("source_app") or "").strip().lower()
                if u:
                    merged[(u, src)] = it
        u = (item.get("url") or item.get("raw") or item.get("name") or "").strip().lower().rstrip("/")
        src = (item.get("source_app") or "").strip().lower()
        if u:
            if (u, src) in merged:
                prev = merged[(u, src)]
                rank = {"vulnerable_write": 4, "vulnerable_takeover": 3, "open": 2, "secured": 1, "unknown": 0}
                if rank.get(item.get("status"), 0) >= rank.get(prev.get("status"), 0):
                    merged[(u, src)] = {**prev, **item}
            else:
                merged[(u, src)] = item
        return list(merged.values())

    async def add_asset_to_domains(target, asset_obj):
        prov = asset_obj.get("provider") or "AWS S3"
        prov_lower = prov.lower()
        if "s3" in prov_lower or "aws" in prov_lower:
            category = "s3_buckets"
        elif "azure" in prov_lower or "blob" in prov_lower:
            category = "azure_blobs"
        elif "google" in prov_lower or "gcp" in prov_lower or "gcs" in prov_lower:
            category = "gcp_buckets"
        else:
            category = "other_buckets"

        domains_to_update = set()
        # Direct match
        target_clean = target.strip().lower()
        if await domains_col.find_one({"domain": target_clean}):
            domains_to_update.add(target_clean)

        # Parent roots
        parents = find_parent_domains(target_clean)
        domains_to_update.update(parents)

        for d_name in domains_to_update:
            doc = await domains_col.find_one({"domain": d_name}, {f"infrastructure.cloud_footprint.{category}": 1})
            if doc:
                existing = (doc.get("infrastructure") or {}).get("cloud_footprint", {}).get(category) or []
                updated_list = merge_into_list(existing, asset_obj)
                await domains_col.update_one(
                    {"domain": d_name},
                    {"$set": {f"infrastructure.cloud_footprint.{category}": updated_list}}
                )
                print(f"  [+] Synced {asset_obj['name']} ({asset_obj['status']}) to {d_name} -> {category}")

    # Process leads
    leads_cursor = leads_col.find({
        "$or": [
            {"alert_type": {"$in": ["osint_public_buckets", "cloud_storage_writable", "cloud_storage_listable", "js_cloud_storage_leaks", "js_cloud_storage_takeover"]}},
            {"title": {"$regex": "bucket|storage", "$options": "i"}}
        ]
    })
    leads = await leads_cursor.to_list(1000)
    print(f"Found {len(leads)} cloud bucket leads to sync.")

    for lead in leads:
        title = lead.get("title") or ""
        details = lead.get("details") or {}
        target = lead.get("target") or ""
        alert_type = lead.get("alert_type") or ""

        bucket_url = ""
        bucket_name = ""
        provider = "AWS S3"
        status = "open"

        if isinstance(details, dict):
            bucket_url = details.get("bucket_url") or details.get("url") or ""
            bucket_name = details.get("bucket_name") or details.get("name") or ""
        elif isinstance(details, str):
            m = re.search(r"Bucket URL:\s*([^\s\n]+)", details)
            if m: bucket_url = m.group(1)
            m2 = re.search(r"Provider:\s*([^\s\n]+)", details)
            if m2: provider = m2.group(1)

        if not bucket_name:
            m3 = re.search(r"Bucket:\s*([^\s\n]+)", title)
            if m3:
                bucket_name = m3.group(1)
            elif ":" in title:
                bucket_name = title.split(":")[-1].strip()

        if "google" in title.lower() or (bucket_url and "storage.googleapis.com" in bucket_url):
            provider = "Google Cloud Storage"
        elif "azure" in title.lower() or (bucket_url and "blob.core.windows.net" in bucket_url):
            provider = "Azure Blob"
        elif "s3" in title.lower() or (bucket_url and "s3.amazonaws.com" in bucket_url):
            provider = "AWS S3"

        if "writable" in alert_type or "writable" in title.lower():
            status = "vulnerable_write"
        elif "takeover" in alert_type or "unclaimed" in title.lower():
            status = "vulnerable_takeover"
        else:
            status = "open"

        if not bucket_url and bucket_name:
            if provider == "Google Cloud Storage":
                bucket_url = f"https://storage.googleapis.com/{bucket_name}"
            elif provider == "AWS S3":
                bucket_url = f"https://{bucket_name}.s3.amazonaws.com"

        if bucket_url or bucket_name:
            asset_obj = {
                "name": bucket_name or bucket_url,
                "raw": bucket_url.replace("https://", "").replace("http://", "").rstrip("/"),
                "url": bucket_url,
                "provider": provider,
                "status": status,
                "http_status": 200,
                "details": lead.get("description") or f"Publicly accessible {provider} bucket",
                "source_app": target,
                "discovered_by": lead.get("source") or "Alert Lead Sync",
                "discovered_at": lead.get("timestamp") or datetime.datetime.utcnow().isoformat()
            }
            await add_asset_to_domains(target, asset_obj)

    # Process existing osint.cloud_assets in domains
    domains_with_osint = await domains_col.find({"osint.cloud_assets": {"$exists": True, "$ne": []}}).to_list(1000)
    print(f"Found {len(domains_with_osint)} domains with osint.cloud_assets to sync.")

    for d in domains_with_osint:
        d_name = d["domain"]
        cloud_assets = (d.get("osint") or {}).get("cloud_assets") or []
        for c in cloud_assets:
            if isinstance(c, dict):
                p = c.get("provider") or "AWS S3"
                is_crit = c.get("risk") == "Critical" or "open" in c.get("status", "").lower()
                status = "open" if is_crit else "secured"
                asset_obj = {
                    "name": c.get("name") or c.get("url"),
                    "raw": c.get("name") or c.get("url"),
                    "url": c.get("url") or (f"https://storage.googleapis.com/{c['name']}" if "google" in p.lower() else f"https://{c['name']}.s3.amazonaws.com"),
                    "provider": p,
                    "status": status,
                    "http_status": 200 if status == "open" else 403,
                    "details": c.get("status") or (f"{p} bucket ({status})"),
                    "source_app": d_name,
                    "discovered_by": "osint_agent",
                    "discovered_at": datetime.datetime.utcnow().isoformat()
                }
                await add_asset_to_domains(d_name, asset_obj)

    print("=== CLOUD STORAGE FOOTPRINT SYNC COMPLETE ===")

if __name__ == "__main__":
    asyncio.run(sync_all_cloud_storage())
