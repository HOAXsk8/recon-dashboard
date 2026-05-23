import asyncio
import datetime
import logging
from base_agent import BaseAgent, logger

WORDLIST_PATH = "/app/wordlists/subdomains-top5000.txt"

class SubdomainDiscoveryAgent(BaseAgent):
    def __init__(self):
        super().__init__("subdomain_discovery", "Subdomain Discovery Tool")

    async def run_subfinder(self, domain):
        logger.info(f"Running Subfinder on {domain}")
        stdout, stderr = await self.run_command(["subfinder", "-d", domain, "-silent"])
        if stderr:
            logger.warning(f"Subfinder stderr: {stderr}")
        return [line.strip() for line in stdout.splitlines() if line.strip()]

    async def has_wildcard_dns(self, domain):
        """Check if a domain has wildcard DNS configured."""
        random_sub = f"detect-wildcard-{datetime.datetime.utcnow().timestamp()}.{domain}"
        try:
            import socket
            # Use a thread-safe way to resolve in async
            loop = asyncio.get_event_loop()
            await loop.getaddrinfo(random_sub, None)
            logger.warning(f"Wildcard DNS detected for {domain}. Skipping active brute-force.")
            return True
        except socket.gaierror:
            return False
        except Exception as e:
            logger.error(f"Error checking wildcard for {domain}: {e}")
            return False

    async def run_ffuf(self, domain):
        logger.info(f"Running ffuf on {domain}")
        # Added -ac for auto-calibration and -t 50 to keep it somewhat controlled
        cmd = [
            "ffuf", "-w", WORDLIST_PATH, "-u", f"http://FUZZ.{domain}",
            "-mc", "200,204,301,302,307,401,403", "-s", "-ac", "-t", "50"
        ]
        stdout, stderr = await self.run_command(cmd)
        found = []
        for line in stdout.splitlines():
            sub = line.strip()
            if sub:
                found.append(f"{sub}.{domain}")
        return found

    async def process_tasks(self):
        # ... (same as before)
        # 1. Check for new domains that need discovery
        new_domains = await self.domains_col.find({"scanned": False, "blacklisted": {"$ne": True}}).to_list(length=10)
        for d in new_domains:
            root_domain = d["domain"]
            exists = await self.tasks_col.find_one({"root_domain": root_domain, "target": root_domain, "task_type": "discovery"})
            if not exists:
                await self.tasks_col.insert_one({
                    "root_domain": root_domain,
                    "target": root_domain,
                    "task_type": "discovery",
                    "status": "pending",
                    "created_at": datetime.datetime.utcnow()
                })

        # 2. Process pending discovery tasks
        task = await self.tasks_col.find_one_and_update(
            {"task_type": "discovery", "status": "pending"},
            {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}},
            sort=[("created_at", 1)]
        )

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        
        try:
            # Passive is usually safe from wildcards
            passive = await self.run_subfinder(target)
            
            # Active: Only run ffuf if no wildcard is detected
            active = []
            if not await self.has_wildcard_dns(target):
                active = await self.run_ffuf(target)
            
            all_found = set(passive + active)

            for sub in all_found:
                # Add to verification queue
                exists = await self.tasks_col.find_one({
                    "root_domain": root_domain,
                    "target": sub,
                    "task_type": "verification"
                })
                if not exists:
                    await self.tasks_col.insert_one({
                        "root_domain": root_domain,
                        "target": sub,
                        "task_type": "verification",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    })

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

            logger.info(f"Completed discovery for {target}")

        except Exception as e:
            logger.error(f"Error in discovery for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = SubdomainDiscoveryAgent()
    asyncio.run(agent.main_loop())
