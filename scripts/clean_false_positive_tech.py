#!/usr/bin/env python3
"""
Sanitizes false-positive technology stack detections in MongoDB caused by
file-enumeration catch-alls and 302 redirects.
"""

import os
import sys
import argparse
import urllib.parse
from datetime import datetime
import pymongo

PRIMARY_RUNTIMES = {
    "php": ["php", "wordpress", "laravel", "drupal", "joomla", "symfony"],
    "python": ["python", "django", "flask", "fastapi", "tornado"],
    "java": ["java", "spring boot", "spring", "apache tomcat", "tomcat", "jboss", "weblogic"],
    "asp.net": ["asp.net", "iis", "asp.net core", "asp.net mvc"],
    "ruby on rails": ["ruby on rails", "ruby", "rails"],
    "coldfusion": ["coldfusion", "adobe coldfusion"],
    "node.js": ["node.js", "node", "express", "koa", "sails"]
}

def load_env():
    env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k not in os.environ:
                        os.environ[k] = v

def connect_db():
    load_env()
    mongo_password = os.getenv("MONGO_ROOT_PASSWORD")
    if not mongo_password:
        raise RuntimeError("MONGO_ROOT_PASSWORD is not set in environment or .env")
    pw = urllib.parse.quote_plus(mongo_password)
    mongo_host = os.getenv("MONGO_HOST", "localhost")
    client = pymongo.MongoClient(f"mongodb://admin:{pw}@{mongo_host}:27017/?authSource=admin", serverSelectionTimeoutMS=5000)
    return client["recon_db"]

def get_authoritative_runtimes(app_doc):
    """
    Examines authoritative evidence (WhatWeb, Server header, Cookies, Favicon)
    to determine which primary runtime(s) have verified proof.
    """
    confirmed = set()
    
    # 1. Server banner & headers
    server = (app_doc.get("server") or "").lower()
    if any(k in server for k in ["php"]):
        confirmed.add("php")
    if any(k in server for k in ["gunicorn", "uvicorn", "werkzeug"]):
        confirmed.add("python")
    if any(k in server for k in ["tomcat", "jboss", "weblogic"]):
        confirmed.add("java")
    if any(k in server for k in ["kestrel", "microsoft-iis", "iis"]):
        confirmed.add("asp.net")
    if any(k in server for k in ["express", "node"]):
        confirmed.add("node.js")
    if any(k in server for k in ["coldfusion"]):
        confirmed.add("coldfusion")

    sec_headers = app_doc.get("security_headers") or {}
    x_powered = (sec_headers.get("x-powered-by") or "").lower()
    if "express" in x_powered or "next.js" in x_powered or "node" in x_powered:
        confirmed.add("node.js")
    if "php" in x_powered:
        confirmed.add("php")
    if "asp.net" in x_powered:
        confirmed.add("asp.net")

    # 2. WhatWeb plugins
    whatweb = app_doc.get("whatweb", {})
    plugins = whatweb.get("plugins", {})
    for p_name in plugins.keys():
        p_low = p_name.lower()
        for rt, aliases in PRIMARY_RUNTIMES.items():
            if any(a in p_low for a in aliases):
                confirmed.add(rt)

    # 3. Cookie audit
    cookie_audit = app_doc.get("cookie_audit", {}) or {}
    cookies = (cookie_audit.get("discovered_cookies") or []) + (cookie_audit.get("insecure_session_cookies") or [])
    for c in cookies:
        raw_val = c.get("name") if isinstance(c, dict) else str(c)
        c_name = str(raw_val or "").upper()
        if "PHPSESSID" in c_name:
            confirmed.add("php")
        elif "JSESSIONID" in c_name:
            confirmed.add("java")
        elif "ASPNET" in c_name or "ASP.NET" in c_name:
            confirmed.add("asp.net")
        elif "CSRFTOKEN" in c_name or "DJANGO" in c_name:
            confirmed.add("python")
        elif "CFID" in c_name or "CFTOKEN" in c_name:
            confirmed.add("coldfusion")

    # 4. Favicon framework
    fav = app_doc.get("favicon", {}) or {}
    fw = str(fav.get("framework") or "").lower()
    for rt, aliases in PRIMARY_RUNTIMES.items():
        if any(a in fw for a in aliases):
            confirmed.add(rt)

    return confirmed

def sanitize_tech_stack(tech_list, confirmed_runtimes):
    """
    Filters out unconfirmed conflicting primary runtimes from a tech_stack.
    """
    detected_runtimes = {}
    for item in tech_list:
        base = item.split(":")[0].strip()
        low = base.lower()
        for rt, aliases in PRIMARY_RUNTIMES.items():
            if any(a == low or low.startswith(a + " ") or a in low for a in aliases):
                detected_runtimes[item] = rt
                break

    # If only 0 or 1 primary runtime is detected, no conflict exists
    detected_runtime_classes = set(detected_runtimes.values())
    if len(detected_runtime_classes) <= 1:
        return tech_list, []

    # Conflict detected! If we have confirmed runtimes, preserve confirmed ones
    cleaned = []
    removed = []
    
    if confirmed_runtimes:
        for item in tech_list:
            if item in detected_runtimes:
                rt_class = detected_runtimes[item]
                if rt_class in confirmed_runtimes:
                    cleaned.append(item)
                else:
                    removed.append(item)
            else:
                cleaned.append(item)
    else:
        # None confirmed by headers/cookies/whatweb: if 3+ conflicting runtimes exist from file hunt false positives, remove them
        if len(detected_runtime_classes) >= 3:
            for item in tech_list:
                if item in detected_runtimes:
                    removed.append(item)
                else:
                    cleaned.append(item)
        else:
            return tech_list, []

    return cleaned, removed

def main():
    parser = argparse.ArgumentParser(description="Clean false-positive technology detection combinations in recon_db")
    parser.add_argument("--dry-run", action="store_true", help="Preview modifications without writing to MongoDB")
    args = parser.parse_args()

    db = connect_db()
    domains_col = db["domains"]
    alerts_col = db["alerts"]

    print(f"[*] Connected to recon_db. Mode: {'DRY RUN' if args.dry_run else 'LIVE REPAIR'}")

    total_apps_cleaned = 0
    total_domains_cleaned = 0
    total_alerts_cleaned = 0

    cursor = domains_col.find({"web_applications": {"$exists": True, "$not": {"$size": 0}}})
    for doc in cursor:
        d_id = doc["_id"]
        d_name = doc.get("domain", "")
        web_apps = doc.get("web_applications", [])
        modified_apps = False

        for app in web_apps:
            target = app.get("target") or d_name
            tech_stack = app.get("tech_stack", [])
            if not tech_stack:
                continue

            confirmed_rt = get_authoritative_runtimes(app)
            cleaned_tech, removed = sanitize_tech_stack(tech_stack, confirmed_rt)

            if removed:
                print(f"[!] Target '{target}': Conflicting tech found: {removed}")
                print(f"    Confirmed active runtimes: {confirmed_rt or 'None'}")
                print(f"    Cleaned stack: {cleaned_tech}")

                app["tech_stack"] = cleaned_tech
                modified_apps = True
                total_apps_cleaned += 1

                # Clean up alerts for the removed technologies on this target
                if not args.dry_run:
                    for rem_tech in removed:
                        rem_base = rem_tech.split(":")[0].strip()
                        res = alerts_col.delete_many({
                            "target": target,
                            "alert_type": "tech_stack_changes",
                            "$or": [
                                {"title": {"$regex": rem_base, "$options": "i"}},
                                {"description": {"$regex": rem_base, "$options": "i"}}
                            ]
                        })
                        total_alerts_cleaned += res.deleted_count

        if modified_apps and not args.dry_run:
            # Also synchronize the domain-level tech_stack
            new_domain_tech = list(dict.fromkeys([t for a in web_apps for t in a.get("tech_stack", [])]))
            domains_col.update_one(
                {"_id": d_id},
                {
                    "$set": {
                        "web_applications": web_apps,
                        "tech_stack": new_domain_tech
                    }
                }
            )
            total_domains_cleaned += 1

    print("\n" + "=" * 50)
    print(f"Sanitization Summary:")
    print(f"  Web Applications cleaned: {total_apps_cleaned}")
    print(f"  Domains updated:          {total_domains_cleaned}")
    print(f"  False positive alerts:    {total_alerts_cleaned}")
    print("=" * 50)

if __name__ == "__main__":
    main()
