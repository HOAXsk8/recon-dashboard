import os
import urllib.parse
import pymongo
from datetime import datetime

MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD")
if not MONGO_ROOT_PASSWORD:
    raise RuntimeError("MONGO_ROOT_PASSWORD is not set")

pw = urllib.parse.quote_plus(MONGO_ROOT_PASSWORD)
mongo_host = os.getenv("MONGO_HOST", "localhost")
client = pymongo.MongoClient(f"mongodb://admin:{pw}@{mongo_host}:27017/?authSource=admin")
db = client["recon_db"]

domains_col = db["domains"]
leads_col = db["leads"]

print("Starting route discovery synchronization and backfill...")

# Helper to find parent apex domain
known_roots = list(domains_col.find({"single_domain_only": {"$ne": True}}, {"domain": 1}))
known_root_domains = [d["domain"] for d in known_roots if d.get("domain")]
print(f"Known root domains ({len(known_root_domains)}): {known_root_domains}")

def get_parent_root(target):
    target = target.lower().strip()
    # 1. Exact match in known roots
    best_match = None
    for r in known_root_domains:
        if target == r or target.endswith("." + r):
            if not best_match or len(r) > len(best_match):
                best_match = r
    if best_match:
        return best_match

    # 2. Check if any parent document has this target in infrastructure.subdomains
    parent = domains_col.find_one({"infrastructure.subdomains.name": target, "single_domain_only": {"$ne": True}})
    if parent:
        return parent["domain"]

    # 3. Fallback heuristic
    parts = target.split(".")
    if len(parts) >= 2:
        if len(parts) >= 3 and parts[-2] in ["co", "com", "org", "net", "gov", "ac", "edu"]:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return target

# 1. Find all documents with routes in web_applications or dynamic_js
query = {
    "$or": [
        {"web_applications.client_routes": {"$exists": True, "$ne": []}},
        {"client_routes": {"$exists": True, "$ne": []}},
        {"dynamic_js.client_routes": {"$exists": True, "$ne": []}}
    ]
}

docs = list(domains_col.find(query))
print(f"Found {len(docs)} documents with routes.")

total_synced = 0
for doc in docs:
    domain = doc.get("domain")
    webapps = doc.get("web_applications", [])
    
    # If no webapps but top-level client_routes
    if not webapps and (doc.get("client_routes") or doc.get("dynamic_js", {}).get("client_routes")):
        routes = doc.get("client_routes") or doc.get("dynamic_js", {}).get("client_routes")
        new_app = {
            "target": domain,
            "url": f"https://{domain}",
            "client_routes": routes,
            "client_routes_count": len(routes),
            "routes": routes,
            "status": 200,
            "dynamic_js": doc.get("dynamic_js", {})
        }
        domains_col.update_one({"_id": doc["_id"]}, {"$set": {"web_applications": [new_app]}})
        webapps = [new_app]

    for app in webapps:
        target = app.get("target") or domain
        routes = app.get("client_routes") or app.get("routes") or app.get("dynamic_js", {}).get("client_routes") or []
        if not routes:
            continue
            
        endpoints = app.get("extracted_endpoints") or app.get("dynamic_js", {}).get("extracted_endpoints") or []
        priv_routes = [r for r in routes if (isinstance(r, dict) and r.get("is_privileged")) or (isinstance(r, str) and any(kw in r.lower() for kw in ["admin", "billing", "settings", "auth", "root", "security", "manage"]))]
        
        # Ensure target doc has all route fields populated
        app["client_routes"] = routes
        app["client_routes_count"] = len(routes)
        app["routes"] = routes
        app["privileged_client_routes_count"] = len(priv_routes)
        if endpoints:
            app["extracted_endpoints"] = endpoints
            app["endpoints_count"] = len(endpoints)
        if not app.get("js_scanned_at"):
            app["js_scanned_at"] = app.get("dynamic_js", {}).get("scanned_at") or datetime.utcnow().isoformat()
            
        domains_col.update_one(
            {"domain": domain, "web_applications.target": target},
            {"$set": {
                "web_applications.$.client_routes": routes,
                "web_applications.$.client_routes_count": len(routes),
                "web_applications.$.routes": routes,
                "web_applications.$.privileged_client_routes_count": len(priv_routes),
                "web_applications.$.extracted_endpoints": endpoints,
                "web_applications.$.endpoints_count": len(endpoints),
                "web_applications.$.js_scanned_at": app["js_scanned_at"]
            }}
        )

        # Now propagate to Parent Root Domain
        parent_root = get_parent_root(target)
        if parent_root and parent_root != domain:
            parent_doc = domains_col.find_one({"domain": parent_root})
            if parent_doc:
                existing_webapps = parent_doc.get("web_applications", [])
                matching_app = next((w for w in existing_webapps if w.get("target") == target), None)
                
                if matching_app:
                    # Update matching app inside parent_doc
                    domains_col.update_one(
                        {"domain": parent_root, "web_applications.target": target},
                        {"$set": {
                            "web_applications.$.client_routes": routes,
                            "web_applications.$.client_routes_count": len(routes),
                            "web_applications.$.routes": routes,
                            "web_applications.$.privileged_client_routes_count": len(priv_routes),
                            "web_applications.$.extracted_endpoints": endpoints,
                            "web_applications.$.endpoints_count": len(endpoints),
                            "web_applications.$.dynamic_js": app.get("dynamic_js", {}),
                            "web_applications.$.js_scanned_at": app["js_scanned_at"]
                        }}
                    )
                else:
                    # Push this webapp to parent_doc web_applications
                    domains_col.update_one(
                        {"domain": parent_root},
                        {"$push": {"web_applications": app}}
                    )
                total_synced += 1
                print(f"  Synced {len(routes)} routes for {target} -> parent root {parent_root}")

# 2. Update all leads for js_client_framework_routes to link root_domain and routes
leads = list(leads_col.find({"alert_type": "js_client_framework_routes"}))
print(f"\nUpdating {len(leads)} js_client_framework_routes leads with root_domain...")
for lead in leads:
    t = lead.get("target")
    if t:
        root = get_parent_root(t)
        # Find routes for this target from domains
        doc = domains_col.find_one({"web_applications.target": t}, {"web_applications.$": 1})
        routes = []
        if doc and doc.get("web_applications"):
            routes = doc["web_applications"][0].get("client_routes", [])
        
        leads_col.update_one(
            {"_id": lead["_id"]},
            {"$set": {
                "root_domain": root,
                "routes": routes,
                "routes_count": len(routes)
            }}
        )

print(f"\nBackfill complete! Synced {total_synced} webapp route entries into parent root domains.")
