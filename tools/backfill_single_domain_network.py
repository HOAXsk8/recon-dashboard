import os
import sys
import asyncio
import pymongo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dns_analytics import AsnNetworkResolver

MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
PASSWORD = os.getenv("MONGO_ROOT_PASSWORD", "yrdlQJX9Kixb91wWRl5fOQ")
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"

async def run_backfill():
    client = pymongo.MongoClient(MONGO_URI)
    db = client["recon_db"]
    domains_col = db["domains"]
    asn_resolver = AsnNetworkResolver()

    print("=== BACKFILLING SINGLE DOMAIN & ROOT NETWORK TOPOLOGY RECORDS (WITH ASN) ===")
    count_updated = 0

    cursor = domains_col.find({})
    for doc in cursor:
        d_name = doc.get("domain")
        if not d_name:
            continue

        candidate_ips = []
        if doc.get("ip") and str(doc["ip"]).strip() not in ("Unknown", "N/A", ""):
            candidate_ips.append(str(doc["ip"]).strip())
        for tip in doc.get("target_ips") or []:
            if tip and str(tip).strip() not in ("Unknown", "N/A", ""):
                candidate_ips.append(str(tip).strip())
        for dns_a in doc.get("dns_records", {}).get("a") or []:
            if dns_a and str(dns_a).strip() not in ("Unknown", "N/A", ""):
                candidate_ips.append(str(dns_a).strip())
        for dns_aaaa in doc.get("dns_records", {}).get("aaaa") or []:
            if dns_aaaa and str(dns_aaaa).strip() not in ("Unknown", "N/A", ""):
                candidate_ips.append(str(dns_aaaa).strip())
        for s in doc.get("systems") or []:
            if isinstance(s, dict) and s.get("ip") and str(s["ip"]).strip() not in ("Unknown", "N/A", ""):
                candidate_ips.append(str(s["ip"]).strip())

        lb = (doc.get("infrastructure", {}).get("load_balancer") or
              doc.get("infrastructure", {}).get("root_load_balancer") or {})
        for lb_ip in lb.get("ips") or []:
            if lb_ip and str(lb_ip).strip() not in ("Unknown", "N/A", ""):
                candidate_ips.append(str(lb_ip).strip())

        candidate_ips = list(dict.fromkeys(candidate_ips))
        if not candidate_ips:
            continue

        updates = {}
        current_target_ips = doc.get("target_ips") or []
        if set(candidate_ips) != set(current_target_ips):
            updates["target_ips"] = candidate_ips

        if not doc.get("ip") or doc.get("ip") in ("Unknown", "N/A"):
            updates["ip"] = candidate_ips[0]

        current_sys = doc.get("system")
        if not current_sys:
            updates["system"] = {"ip": candidate_ips[0], "target": d_name}
        elif not current_sys.get("ip") or current_sys.get("ip") in ("Unknown", "N/A"):
            updates["system.ip"] = candidate_ips[0]

        # Resolve ASN if missing
        if not doc.get("asn"):
            for s in doc.get("systems") or []:
                if s.get("asn"):
                    updates["asn"] = str(s["asn"])
                    if s.get("as_org") and not doc.get("as_org"):
                        updates["as_org"] = s["as_org"]
                    if s.get("cidr") and not doc.get("cidr"):
                        updates["cidr"] = s["cidr"]
                    break

            if not updates.get("asn") and candidate_ips:
                try:
                    asn_info = await asn_resolver.resolve_ip(candidate_ips[0])
                    if asn_info.get("asn"):
                        updates["asn"] = str(asn_info["asn"])
                        updates["as_org"] = asn_info.get("org")
                        updates["cidr"] = asn_info.get("cidr")
                        updates["ptr"] = asn_info.get("ptr")
                        updates["infrastructure.asn_data.primary_asn"] = str(asn_info["asn"])
                        updates["infrastructure.asn_data.primary_org"] = asn_info.get("org")
                        updates["infrastructure.asn_data.cidr"] = asn_info.get("cidr")
                except Exception:
                    pass

        if updates:
            domains_col.update_one({"_id": doc["_id"]}, {"$set": updates})
            count_updated += 1
            if count_updated % 100 == 0 or d_name == "accounts.o2.co.uk":
                print(f"[+] Updated {d_name}: {list(updates.keys())}")

    print(f"\n[✓] Backfill complete. Total domain records updated: {count_updated}")

if __name__ == "__main__":
    asyncio.run(run_backfill())
