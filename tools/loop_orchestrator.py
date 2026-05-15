import asyncio
import datetime
import logging
import os
from base_agent import BaseAgent, logger

class ContinuousLoopAgent(BaseAgent):
    def __init__(self):
        super().__init__("loop_orchestrator", "Continuous Loop Orchestrator")
        # How often to check for completed cycles (in seconds)
        self.check_interval = 60
        # How long to wait before re-scanning a domain (in hours)
        self.rescan_interval = 24

    async def check_and_reset_cycles(self):
        """Check for root domains that have finished their scan cycle and reset them based on their specific intervals."""
        # We'll use a cursor to iterate through domains that are 'scanned=True'
        # and compare their 'last_scanned' time against their specific 'scan_interval'.
        
        cursor = self.domains_col.find({
            "scanned": True,
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        })
        
        now = datetime.datetime.utcnow()
        
        async for domain in cursor:
            root_domain = domain["domain"]
            last_scanned_str = domain.get("last_scanned")
            
            # Default to global interval if not set on domain
            interval_hours = domain.get("scan_interval", self.rescan_interval)
            
            should_reset = False
            if not last_scanned_str:
                should_reset = True
            else:
                try:
                    last_scanned = datetime.datetime.fromisoformat(last_scanned_str.replace("Z", "+00:00")).replace(tzinfo=None)
                    if now - last_scanned > datetime.timedelta(hours=interval_hours):
                        should_reset = True
                except Exception as e:
                    logger.error(f"Error parsing last_scanned for {root_domain}: {e}")
                    should_reset = True
            
            if should_reset:
                logger.info(f"Cycle complete for {root_domain} (Interval: {interval_hours}h). Resetting for continuous monitoring.")
                
                # 1. Reset scanned flag on domain
                await self.domains_col.update_one(
                    {"_id": domain["_id"]},
                    {"$set": {"scanned": False, "last_cycle_completed": last_scanned_str}}
                )
                
                # 2. Clear old tasks for this domain to allow re-entry
                # We preserve directory_hunt, js_mine, and bypass_403 tasks so they only run once
                # unless a change is detected (handled by other agents).
                await self.tasks_col.delete_many({
                    "root_domain": root_domain,
                    "task_type": {"$in": ["discovery", "verify", "scan", "tech_fingerprint"]},
                    "status": {"$in": ["completed", "failed"]}
                })
                
                # 3. Create a fresh discovery task for the root domain
                exists = await self.tasks_col.find_one({
                    "root_domain": root_domain,
                    "target": root_domain,
                    "task_type": "discovery"
                })
                if not exists:
                    await self.tasks_col.insert_one({
                        "root_domain": root_domain,
                        "target": root_domain,
                        "task_type": "discovery",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    })
                    logger.info(f"Re-queued discovery for {root_domain}")

    async def process_tasks(self):
        """Orchestrator doesn't process specific 'tasks' from the collection, 
        it manages the overall workflow state."""
        await self.check_and_reset_cycles()
        # Custom sleep since this is a global manager
        await asyncio.sleep(self.check_interval)

if __name__ == "__main__":
    agent = ContinuousLoopAgent()
    # ContinuousLoopAgent overrides process_tasks to handle its own timing
    asyncio.run(agent.main_loop())
