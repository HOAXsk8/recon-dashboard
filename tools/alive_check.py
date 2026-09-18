import asyncio
import datetime
import logging
from base_agent import BaseAgent, logger

class AliveCheckAgent(BaseAgent):
    def __init__(self):
        super().__init__("alive_check", "Subdomain Alive Checking Tool")

    async def get_ip(self, target):
        """Resolve target to IP address."""
        try:
            import socket
            loop = asyncio.get_event_loop()
            res = await loop.getaddrinfo(target, None)
            if res:
                return res[0][4][0]
        except:
            pass
        return None

    async def is_wildcard(self, domain):
        """Check if a domain has wildcard DNS."""
        random_sub = f"check-{datetime.datetime.utcnow().timestamp()}.{domain}"
        ip = await self.get_ip(random_sub)
        return ip

    async def is_alive(self, target):
        """Verify if a target is alive. STRICT: Only returns True if a port is actually OPEN."""
        ports = [80, 443, 22, 8080, 8443]
        for port in ports:
            try:
                conn = asyncio.open_connection(target, port)
                _, writer = await asyncio.wait_for(conn, timeout=1.5)
                writer.close()
                await writer.wait_closed()
                return True
            except:
                continue
        return False

    async def process_tasks(self):
        task = await self.get_next_task("verification")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]

        try:
            # 1. Check for wildcard on the parent domain
            parent_domain = ".".join(target.split(".")[1:])
            wildcard_ip = await self.is_wildcard(parent_domain)
            target_ip = await self.get_ip(target)

            is_potential_fp = False
            if wildcard_ip and target_ip == wildcard_ip:
                is_potential_fp = True
                logger.info(f"Target {target} matches wildcard IP {wildcard_ip}. Requiring open port.")

            # 2. Strict alive check
            alive = await self.is_alive(target)
            
            # If it's a potential FP and no ports are open, mark as DEAD
            if is_potential_fp and not alive:
                logger.info(f"Target {target} is a Wildcard FP (No ports open).")
                alive = False

            if alive:
                # 3. Add to domains collection if it's a subdomain
                if target != root_domain:
                    # Atomically add only if not already present by name
                    await self.domains_col.update_one(
                        {
                            "domain": root_domain,
                            "infrastructure.subdomains.name": {"$ne": target}
                        },
                        {
                            "$push": {
                                "infrastructure.subdomains": {
                                    "name": target,
                                    "added_at": datetime.datetime.utcnow().isoformat()
                                }
                            }
                        }
                    )
                
                # 4. Add discovery task for recursion (ONLY if it's not a wildcard child or we really trust it)
                # For now, let's limit recursion to 2 levels to prevent explosion
                depth = target.count(".") - root_domain.count(".")
                if depth < 2:
                    exists_disc = await self.tasks_col.find_one({
                        "root_domain": root_domain,
                        "target": target,
                        "task_type": "discovery"
                    })
                    if not exists_disc:
                        await self.tasks_col.insert_one({
                            "root_domain": root_domain,
                            "target": target,
                            "task_type": "discovery",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        })

                # 5. Add scan task
                exists_scan = await self.tasks_col.find_one({
                    "root_domain": root_domain,
                    "target": target,
                    "task_type": "scan"
                })
                if not exists_scan:
                    await self.tasks_col.insert_one({
                        "root_domain": root_domain,
                        "target": target,
                        "task_type": "scan",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    })

                # Record alive status in infrastructure.subdomains
                if target != root_domain:
                    await self.domains_col.update_one(
                        {"domain": root_domain, "infrastructure.subdomains.name": target},
                        {"$set": {
                            "infrastructure.subdomains.$.alive": True,
                            "infrastructure.subdomains.$.last_scanned": datetime.datetime.utcnow().isoformat()
                        }}
                    )

                logger.info(f"Target {target} is ALIVE and added to pipeline.")
            else:
                logger.info(f"Target {target} is DEAD or Wildcard FP.")
                # Mark dead subdomains as scanned and alive=False so they do not stay stuck in Pending
                if target != root_domain:
                    await self.domains_col.update_one(
                        {"domain": root_domain, "infrastructure.subdomains.name": target},
                        {"$set": {
                            "infrastructure.subdomains.$.alive": False,
                            "infrastructure.subdomains.$.scanned": True,
                            "infrastructure.subdomains.$.last_scanned": datetime.datetime.utcnow().isoformat()
                        }}
                    )

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "alive": alive, "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in verification for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = AliveCheckAgent()
    asyncio.run(agent.main_loop())
