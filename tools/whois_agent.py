import asyncio
import datetime
import logging
import re
from base_agent import BaseAgent, logger

class WhoisAgent(BaseAgent):
    def __init__(self):
        super().__init__("whois_lookup", "WHOIS Lookup Tool")

    async def run_whois(self, domain):
        logger.info(f"Running WHOIS on {domain}")
        stdout, stderr = await self.run_command(["whois", domain])
        if stderr and "no match" not in stderr.lower():
            logger.warning(f"WHOIS stderr for {domain}: {stderr}")
        return stdout

    def parse_whois(self, raw_data):
        """Basic parsing of WHOIS data."""
        data = {}
        patterns = {
            "registrar": r"Registrar:\s*(.*)",
            "registrant": r"Registrant Organization:\s*(.*)",
            "admin_email": r"Admin Email:\s*(.*)",
            "creation_date": r"Creation Date:\s*(.*)",
            "expiration_date": r"Registry Expiry Date:\s*(.*)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, raw_data, re.IGNORECASE)
            if match:
                data[key] = match.group(1).strip()
        
        # Handle nameservers
        ns_matches = re.findall(r"Name Server:\s*(.*)", raw_data, re.IGNORECASE)
        if ns_matches:
            data["nameservers"] = [ns.strip() for ns in ns_matches if ns.strip()]
            
        return data

    async def process_tasks(self):
        # 1. Process Root Domains
        root_domains = await self.domains_col.find({
            "whois_complete": {"$ne": True},
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        }).to_list(length=5)
        for doc in root_domains:
            domain = doc["domain"]
            raw_whois = await self.run_whois(domain)
            if raw_whois:
                parsed = self.parse_whois(raw_whois)
                await self.domains_col.update_one(
                    {"_id": doc["_id"]},
                    {
                        "$set": {
                            "ownership": parsed,
                            "whois_raw": raw_whois,
                            "whois_complete": True,
                            "whois_updated_at": datetime.datetime.utcnow().isoformat()
                        }
                    }
                )
                logger.info(f"Root WHOIS completed for {domain}")
            # Add a small delay to avoid WHOIS rate limiting
            await asyncio.sleep(2)

        # 2. Process Subdomains
        # This is more resource intensive, we'll do one root domain's subdomains at a time
        # We look for documents that have subdomains where at least one has whois_complete != True
        doc_with_pending_subs = await self.domains_col.find_one({
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True},
            "infrastructure.subdomains": {
                "$elemMatch": {"whois_complete": {"$ne": True}}
            }
        })

        if doc_with_pending_subs:
            root_domain = doc_with_pending_subs["domain"]
            subs = doc_with_pending_subs.get("infrastructure", {}).get("subdomains", [])
            
            for i, sub in enumerate(subs):
                if not sub.get("whois_complete"):
                    sub_name = sub["name"]
                    raw_whois = await self.run_whois(sub_name)
                    
                    update_fields = {
                        f"infrastructure.subdomains.{i}.whois_complete": True,
                        f"infrastructure.subdomains.{i}.whois_raw": raw_whois,
                        f"infrastructure.subdomains.{i}.whois_updated_at": datetime.datetime.utcnow().isoformat()
                    }
                    
                    await self.domains_col.update_one(
                        {"_id": doc_with_pending_subs["_id"]},
                        {"$set": update_fields}
                    )
                    logger.info(f"Subdomain WHOIS completed for {sub_name}")
                    
                    # WHOIS servers are very sensitive to rate limits
                    await asyncio.sleep(5)
                    # Only do 5 subdomains per cycle to keep it moving but safe
                    if i >= 5: 
                        break

if __name__ == "__main__":
    agent = WhoisAgent()
    asyncio.run(agent.main_loop())
