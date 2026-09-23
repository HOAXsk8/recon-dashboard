import os
import sys
import asyncio
import datetime
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from base_agent import BaseAgent, logger
except ImportError:
    from tools.base_agent import BaseAgent, logger

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
        # Bounded execution: -timeout 2, -maxtime 60 prevents hanging on slow network/DNS
        cmd = [
            "ffuf", "-w", WORDLIST_PATH, "-u", f"http://FUZZ.{domain}",
            "-mc", "200,204,301,302,307,401,403", "-s", "-ac", "-t", "50",
            "-timeout", "2", "-maxtime", "60"
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=75)
            found = []
            for line in stdout.splitlines():
                sub = line.strip()
                if sub and not sub.startswith("Encountered an error") and " " not in sub:
                    found.append(f"{sub}.{domain}")
            return found
        except Exception as e:
            logger.warning(f"ffuf active discovery skipped or timed out for {domain}: {e}")
            return []

    async def process_tasks(self):
        # 1. Check for new domains that need discovery
        new_domains = await self.domains_col.find({"scanned": False, "blacklisted": {"$ne": True}, "single_domain_only": {"$ne": True}}).to_list(length=10)
        for d in new_domains:
            if d.get("on_hold", False):
                continue
            root_domain = d["domain"]
            active_count = await self.tasks_col.count_documents({
                "root_domain": root_domain,
                "status": {"$in": ["pending", "processing"]}
            })
            if active_count == 0:
                total_tasks = await self.tasks_col.count_documents({"root_domain": root_domain})
                if total_tasks == 0:
                    await self.tasks_col.insert_one({
                        "root_domain": root_domain,
                        "target": root_domain,
                        "task_type": "discovery",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    })
                    logger.info(f"Queued initial discovery scan for new domain: {root_domain}")

        # 2. Process pending discovery tasks
        task = await self.get_next_task("discovery")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        
        # Double check if domain is single_domain_only
        d_doc = await self.domains_col.find_one({"domain": root_domain})
        if d_doc and d_doc.get("single_domain_only"):
            logger.info(f"Subdomain Discovery: Cancelling discovery task for single-target domain {root_domain}.")
            await self.tasks_col.update_one({"_id": task["_id"]}, {"$set": {"status": "cancelled", "error": "Single target only"}})
            return
        
        try:
            # Passive is fast and reliable
            passive = await self.run_subfinder(target)
            
            # Active: Run bounded ffuf only if no wildcard is detected
            active = []
            if not await self.has_wildcard_dns(target):
                active = await self.run_ffuf(target)
            
            raw_found = set(passive + active)
            raw_found.add(target)
            raw_found.add(root_domain)

            # Strict scope enforcement: only include targets that strictly belong to root_domain
            all_found = set()
            for sub in raw_found:
                cleaned_sub = sub.strip().lower().rstrip(".")
                if self.is_in_scope(cleaned_sub, root_domain):
                    all_found.add(cleaned_sub)
                else:
                    logger.warning(f"Discarding out-of-scope subdomain discovery result: {sub} for {root_domain}")


            # Fetch already scanned subdomains so each subdomain is strictly scanned once
            d_curr = await self.domains_col.find_one({"domain": root_domain}, {"infrastructure.subdomains": 1})
            already_scanned_set = set()
            if d_curr and d_curr.get("infrastructure", {}).get("subdomains"):
                for s in d_curr["infrastructure"]["subdomains"]:
                    if isinstance(s, dict):
                        if s.get("scanned", False) or bool(s.get("last_scanned")):
                            already_scanned_set.add(s.get("name", "").strip().lower())

            for sub in all_found:
                clean_target = sub.strip().lower()
                if clean_target in already_scanned_set:
                    continue

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

            logger.info(f"Completed discovery for {target} (Found {len(all_found)} in-scope targets)")

        except Exception as e:
            logger.error(f"Error in discovery for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = SubdomainDiscoveryAgent()
    asyncio.run(agent.main_loop())
