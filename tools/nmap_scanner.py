import subprocess
import xml.etree.ElementTree as ET
import os
import urllib.parse
from pymongo import MongoClient
from datetime import datetime
import logging

# --- Configuration ---
MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD")
if not MONGO_ROOT_PASSWORD:
    raise RuntimeError("MONGO_ROOT_PASSWORD environment variable is not set")
PASSWORD = urllib.parse.quote_plus(MONGO_ROOT_PASSWORD)
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"
DB_NAME = "recon_db"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_nmap(target):
    """Runs nmap against a target and returns the XML output."""
    logger.info(f"Scanning {target}...")
    # -sS: TCP SYN scan
    # -sU: UDP scan
    # -p-: All ports
    # -T4: Aggressive timing for speed
    # --max-retries 1: Limit retries to 1
    # --max-rtt-timeout 2s: Set timeout to 2 seconds
    # -oX -: Output to XML on stdout
    cmd = ["nmap", "-sS", "-sU", "-p-", "-T4", "--max-retries", "1", "--max-rtt-timeout", "2s", "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Nmap failed for {target}: {e.stderr}")
        return None

def parse_nmap_xml(xml_data):
    """Parses Nmap XML and extracts open ports and services."""
    if not xml_data:
        return []
    
    services = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall('host'):
            ip_addr = host.find('address[@addrtype="ipv4"]')
            ip = ip_addr.get('addr') if ip_addr is not None else "Unknown"
            
            for port_elem in host.findall('.//port'):
                state = port_elem.find('state').get('state')
                if state == 'open':
                    portid = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol')
                    service_elem = port_elem.find('service')
                    service_name = service_elem.get('name') if service_elem is not None else "unknown"
                    product = service_elem.get('product') if service_elem is not None else ""
                    version = service_elem.get('version') if service_elem is not None else ""
                    
                    services.append({
                        "port": portid,
                        "protocol": protocol,
                        "service": service_name,
                        "software": product,
                        "version": version
                    })
        return services
    except Exception as e:
        logger.error(f"Failed to parse XML: {e}")
        return []

def main():
    while True:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        domains_col = db["domains"]

        # 1. Gather all unique hostnames/targets from the database
        # Filter for targets that haven't been scanned recently or ever
        targets = set()
        for doc in domains_col.find({}, {"domain": 1, "infrastructure.subdomains.name": 1, "scanned": 1}):
            if not doc.get("scanned", False):
                if doc.get("domain"):
                    targets.add(doc["domain"])
                if doc.get("infrastructure") and doc["infrastructure"].get("subdomains"):
                    for sub in doc["infrastructure"]["subdomains"]:
                        if sub.get("name"):
                            targets.add(sub["name"])

        if not targets:
            logger.info("No new targets to scan. Sleeping for 60 seconds...")
            client.close()
            import time
            time.sleep(60)
            continue

        logger.info(f"Found {len(targets)} targets to scan.")

        for target in targets:
            xml_output = run_nmap(target)
            if xml_output:
                services = parse_nmap_xml(xml_output)
                logger.info(f"Found {len(services)} open ports on {target}")
                
                # Update the database
                primary_doc = domains_col.find_one({"domain": target})
                
                if primary_doc:
                    root = ET.fromstring(xml_output)
                    ip_addr = root.find('.//address[@addrtype="ipv4"]')
                    ip = ip_addr.get('addr') if ip_addr is not None else target
                    
                    system_entry = {
                        "ip": ip,
                        "hostname": target,
                        "services": services,
                        "recon_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                    
                    domains_col.update_one(
                        {"domain": target},
                        {"$set": {"systems": [system_entry], "recon_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "scanned": True}}
                    )
                else:
                    parent_doc = domains_col.find_one({"infrastructure.subdomains.name": target})
                    if parent_doc:
                        root = ET.fromstring(xml_output)
                        ip_addr = root.find('.//address[@addrtype="ipv4"]')
                        ip = ip_addr.get('addr') if ip_addr is not None else target

                        system_entry = {
                            "ip": ip,
                            "hostname": target,
                            "services": services,
                            "recon_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                        }
                        
                        existing_system = domains_col.find_one({"domain": parent_doc["domain"], "systems.hostname": target})
                        
                        if existing_system:
                            domains_col.update_one(
                                {"domain": parent_doc["domain"], "systems.hostname": target},
                                {"$set": {"systems.$.services": services, "systems.$.recon_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}}
                            )
                        else:
                            domains_col.update_one(
                                {"domain": parent_doc["domain"]},
                                {"$push": {"systems": system_entry}}
                            )

        client.close()
        logger.info("Batch complete. Sleeping...")
        import time
        time.sleep(10)


if __name__ == "__main__":
    main()
