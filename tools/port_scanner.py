import asyncio
import datetime
import logging
import xml.etree.ElementTree as ET
from base_agent import BaseAgent, logger

class PortScannerAgent(BaseAgent):
    def __init__(self):
        super().__init__("port_scanner", "Port Scanner Tool")

    async def run_nmap(self, target):
        logger.info(f"Running FULL Nmap (TCP/UDP) on {target}")
        cmd = [
            "nmap", "-sS", "-sU", "-p-", "-sV",
            "--max-retries", "2",
            "--max-rtt-timeout", "1s",
            "-T4", target, "-oX", "-"
        ]
        stdout, stderr = await self.run_command(cmd)
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
                            soft = service.get('product', '') if service is not None else ''
                            services.append({
                                "port": int(p_id),
                                "protocol": proto,
                                "software": soft
                            })
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
        return ip, services

    async def update_scan_results_in_db(self, root_domain, target, ip, services):
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

    async def check_completion(self, root_domain):
        """Check if all tasks for this root domain are completed."""
        pending = await self.tasks_col.count_documents({
            "root_domain": root_domain,
            "status": {"$in": ["pending", "processing"]}
        })
        if pending == 0:
            await self.domains_col.update_one(
                {"domain": root_domain},
                {"$set": {"scanned": True, "last_scanned": datetime.datetime.utcnow().isoformat()}}
            )
            logger.info(f"Root domain {root_domain} fully scanned.")

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
                await self.update_scan_results_in_db(root_domain, target, ip, services)
            
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
