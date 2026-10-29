import os
import re
import pymongo

MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
PASSWORD = os.getenv("MONGO_ROOT_PASSWORD", "yrdlQJX9Kixb91wWRl5fOQ")
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"

def run_purge(dry_run=True):
    client = pymongo.MongoClient(MONGO_URI)
    db = client["recon_db"]
    domains_col = db["domains"]
    leads_col = db["leads"]

    print(f"=== CLOUD STORAGE PURGE (Dry Run: {dry_run}) ===")

    # 1. Harvest all genuine code-referenced buckets from web_applications across all domains
    genuine_bucket_keys = set()
    for doc in domains_col.find({"web_applications": {"$exists": True}}):
        for app in doc.get("web_applications", []):
            for ca in app.get("cloud_assets", []):
                if isinstance(ca, dict):
                    name = (ca.get("bucket_name") or ca.get("name") or ca.get("raw") or "").strip().lower()
                    url = (ca.get("url") or ca.get("probe_url") or "").strip().lower().rstrip("/")
                    if name: genuine_bucket_keys.add(name)
                    if url: genuine_bucket_keys.add(url)
                    raw = (ca.get("raw") or "").strip().lower().rstrip("/")
                    if raw: genuine_bucket_keys.add(raw)

    print(f"[+] Total genuine code-referenced bucket keys found in web_applications: {len(genuine_bucket_keys)}")
    for k in sorted(list(genuine_bucket_keys))[:10]:
        print(f"    - Genuine: {k}")

    # 2. Inspect domains and clean infrastructure.cloud_footprint
    total_buckets_before = 0
    total_buckets_purged = 0
    total_domains_modified = 0
    purged_names_for_leads = set()

    for doc in domains_col.find({"infrastructure.cloud_footprint": {"$exists": True}}):
        d_name = doc.get("domain")
        cf = doc.get("infrastructure", {}).get("cloud_footprint", {})
        modified = False
        new_cf = {}

        for category in ["s3_buckets", "azure_blobs", "gcp_buckets", "other_buckets"]:
            b_list = cf.get(category, [])
            total_buckets_before += len(b_list)
            kept = []

            for b in b_list:
                if not isinstance(b, dict):
                    continue
                name = (b.get("name") or b.get("raw") or "").strip().lower()
                url = (b.get("url") or f"https://{name}").strip().lower().rstrip("/")
                raw = (b.get("raw") or "").strip().lower().rstrip("/")
                disc_by = (b.get("discovered_by") or "").strip().lower()

                # A bucket is genuine ONLY if:
                # 1. It is explicitly present in genuine_bucket_keys (harvested from first-party JS in web_applications), OR
                # 2. It has a verified source_script present and discovered_by is dynamic_js_collector
                is_genuine = (
                    name in genuine_bucket_keys or
                    url in genuine_bucket_keys or
                    raw in genuine_bucket_keys or
                    (disc_by == "dynamic_js_collector" and bool(b.get("source_script")))
                )

                if is_genuine:
                    kept.append(b)
                else:
                    purged_names_for_leads.add(name)
                    total_buckets_purged += 1
                    modified = True

            new_cf[category] = kept

        if modified:
            total_domains_modified += 1
            if not dry_run:
                domains_col.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"infrastructure.cloud_footprint": new_cf}}
                )

    print(f"[+] Total buckets inspected: {total_buckets_before}")
    print(f"[+] Total guessed buckets to purge: {total_buckets_purged}")
    print(f"[+] Total domains affected: {total_domains_modified}")
    print(f"[+] Sample purged bucket names: {list(purged_names_for_leads)[:20]}")

    # 3. Clean up leads/alerts generated for purged guessed buckets
    leads_purged = 0
    if purged_names_for_leads:
        lead_query = {
            "$or": [
                {"alert_type": {"$in": ["osint_public_buckets", "cloud_storage_writable", "cloud_storage_listable"]}},
                {"title": {"$regex": "Bucket|Storage", "$options": "i"}}
            ]
        }
        for lead in leads_col.find(lead_query):
            title = lead.get("title", "")
            details = lead.get("details", {})
            b_name = ""
            if isinstance(details, dict):
                b_name = (details.get("bucket_name") or details.get("name") or "").strip().lower()
            if not b_name:
                m = re.search(r"Bucket:\s*([^\s\n]+)", title, re.I)
                if m:
                    b_name = m.group(1).strip().lower()
                elif ":" in title:
                    b_name = title.split(":")[-1].strip().lower()

            if b_name in purged_names_for_leads and b_name not in genuine_bucket_keys:
                leads_purged += 1
                if not dry_run:
                    leads_col.delete_one({"_id": lead["_id"]})

    print(f"[+] False-positive leads associated with guessed buckets purged: {leads_purged}")

if __name__ == "__main__":
    import sys
    dry = "--live" not in sys.argv
    run_purge(dry_run=dry)
