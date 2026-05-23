import asyncio
import datetime
import logging
import xml.etree.ElementTree as ET
from base_agent import BaseAgent, logger

class PortScannerAgent(BaseAgent):
    def __init__(self):
        super().__init__("port_scanner", "Port Scanner Tool")

    async def run_nmap(self, target):
        logger.info(f"Running optimized Nmap on {target}")
        # Optimized for speed: TCP only, top 1000 ports, service versioning
        cmd = [
            "nmap", "-sS", "--top-ports", "1000", "-sV",
            "--max-retries", "1",
            "--max-rtt-timeout", "500ms",
            "-T4", target, "-oX", "-"
        ]
        # Set a 10-minute timeout for the scan
        stdout, stderr = await self.run_command(cmd, timeout=600)
        if stderr:
            logger.warning(f"Nmap stderr: {stderr}")
        return stdout

    def parse_nmap_xml(self, xml_data):
        services = []
        ip = "N/A"
        try:
            root = ET.fromstring(xml_data)
            for host in root.findall('host'):
                addr = host.find('address')
                if addr is not None:
                    ip = addr.get('addr')
                
                for port in host.findall('.//port'):
                    p_id = port.get('portid')
                    proto = port.get('protocol')
                    state_el = port.find('state')
                    if state_el is not None:
                        state = state_el.get('state')
                        if state == 'open':
                            service = port.find('service')
                            service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                            soft = service.get('product', '') if service is not None else ''
                            version = service.get('version', '') if service is not None else ''
                            services.append({
                                "port": int(p_id),
                                "protocol": proto,
                                "service": service_name,
                                "software": soft,
                                "version": version
                            })
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
        return ip, services

    async def create_port_alert(self, root_domain, target, old_ports, new_ports):
        """Create a lead/alert for changed ports using the centralized alerting system."""
        old_set = {f"{p['port']}/{p['protocol']}" for p in old_ports}
        new_set = {f"{p['port']}/{p['protocol']}" for p in new_ports}
        
        added = new_set - old_set
        removed = old_set - new_set
        
        if not added and not removed:
            return

        title = f"Port Change Detected: {target}"
        changes = []
        if added:
            changes.append(f"OPENED: {', '.join(added)}")
        if removed:
            changes.append(f"CLOSED: {', '.join(removed)}")
        
        description = " | ".join(changes)
        risk = "high" if any(p.split('/')[0] in ['22', '3389', '21', '23', '445'] for p in added) else "medium"
        
        details = f"A change in the open ports was detected for {target}.\n\nPrevious ports: {', '.join(old_set) or 'None'}\nNew ports: {', '.join(new_set) or 'None'}"
        exploitation = f"### Port Analysis\n\n1. **Verify Services**: For new ports, identify the service running and check for vulnerabilities.\n2. **Firewall Check**: Ensure that newly opened ports are intended to be public.\n3. **Decommissioning**: If ports were closed, verify if it was a planned decommission or a service failure."

        await self.create_alert(title, description, target, risk, details, exploitation)

    async def update_scan_results_in_db(self, root_domain, target, ip, services):
        # Fetch previous results for comparison
        domain_doc = await self.domains_col.find_one({"domain": root_domain})
        old_systems = domain_doc.get("systems", [])
        
        # Find latest scan for this specific target
        latest_prev_scan = None
        for sys in reversed(old_systems):
            if sys.get("target") == target:
                latest_prev_scan = sys
                break
        
        changed_ports = set()
        if latest_prev_scan:
            old_services = latest_prev_scan.get("services", [])
            await self.create_port_alert(root_domain, target, old_services, services)
            
            # Identify which ports are new or have changed service info
            old_map = {p['port']: p for p in old_services}
            for s in services:
                if s['port'] not in old_map or old_map[s['port']] != s:
                    changed_ports.add(s['port'])
        else:
            # All ports are "new" if no previous scan exists
            changed_ports = {s['port'] for s in services}

        system_entry = {
            "ip": ip,
            "target": target,
            "services": services,
            "last_scanned": datetime.datetime.utcnow().isoformat()
        }
        await self.domains_col.update_one(
            {"domain": root_domain},
            {"$push": {"systems": system_entry}}
        )
        return changed_ports

    async def process_tasks(self):
        task = await self.tasks_col.find_one_and_update(
            {"task_type": "scan", "status": "pending"},
            {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}},
            sort=[("created_at", 1)]
        )

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]

        try:
            xml_data = await self.run_nmap(target)
            ip, services = self.parse_nmap_xml(xml_data)
            
            if services:
                changed_ports = await self.update_scan_results_in_db(root_domain, target, ip, services)
                
                # Trigger directory hunt for web services
                for svc in services:
                    if svc['port'] in [80, 443, 8080, 8443, 3000, 5000, 8000] or svc['service'] in ['http', 'https']:
                        proto = 'https' if svc['port'] in [443, 8443] or svc['service'] == 'https' else 'http'
                        
                        exists = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": target,
                            "port": svc['port'],
                            "task_type": "directory_hunt"
                        })
                        
                        # Re-run if it doesn't exist OR if the port changed
                        if not exists or svc['port'] in changed_ports:
                            if exists:
                                await self.tasks_col.delete_one({"_id": exists["_id"]})
                                
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "protocol": proto,
                                "port": svc['port'],
                                "task_type": "directory_hunt",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Queued directory hunt for {target}:{svc['port']} (Change detected: {svc['port'] in changed_ports})")

                        # Also trigger tech fingerprinting
                        exists_tech = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": target,
                            "port": svc['port'],
                            "task_type": "tech_fingerprint"
                        })
                        if not exists_tech:
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "protocol": proto,
                                "port": svc['port'],
                                "task_type": "tech_fingerprint",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Queued tech fingerprint for {target}:{svc['port']}")

                        # Also trigger nuclei scanning
                        exists_nuclei = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": target,
                            "port": svc['port'],
                            "task_type": "nuclei_scan"
                        })
                        if not exists_nuclei:
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "protocol": proto,
                                "port": svc['port'],
                                "task_type": "nuclei_scan",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Queued NUCLEI scan for {target}:{svc['port']}")
            
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            logger.info(f"Completed port scan for {target}")

            # Check if this was the last task for the root domain
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in port scan for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = PortScannerAgent()
    asyncio.run(agent.main_loop())
