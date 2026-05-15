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
        """Check for root domains that have finished their scan cycle and reset them."""
        # A domain is "finished" if scanned=True
        # We also check if it hasn't been scanned in the last X hours
        threshold = datetime.datetime.utcnow() - datetime.timedelta(hours=self.rescan_interval)
        
        cursor = self.domains_col.find({
            "scanned": True,
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True},
            "$or": [
                {"last_scanned": {"$lt": threshold.isoformat()}},
                {"last_scanned": {"$exists": False}},
                {"last_scanned": None}
            ]
        })
        
        async for domain in cursor:
            root_domain = domain["domain"]
            logger.info(f"Cycle complete for {root_domain}. Resetting for continuous monitoring.")
            
            # 1. Reset scanned flag on domain
            await self.domains_col.update_one(
                {"_id": domain["_id"]},
                {"$set": {"scanned": False, "last_cycle_completed": domain.get("last_scanned")}}
            )
            
            # 2. Clear old tasks for this domain to allow re-entry
            # We delete completed/failed tasks so they can be re-added
            await self.tasks_col.delete_many({
                "root_domain": root_domain,
                "status": {"$in": ["completed", "failed"]}
            })
            
            # 3. Create a fresh discovery task for the root domain
            # This will re-trigger the entire chain: Discovery -> Verification -> Scan -> Tech/Dir Hunt
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
