import asyncio
import datetime
import logging
import os
from base_agent import BaseAgent, logger

class ContinuousLoopAgent(BaseAgent):
    def __init__(self):
        super().__init__("loop_orchestrator", "Continuous Loop Orchestrator")
        # Check every 15 seconds for new unscanned domains and stuck tasks
        self.check_interval = 15
        # Default rescan interval for completed domains (hours)
        self.rescan_interval = 24

    async def check_unscanned_domains(self):
        """Regularly check for any domains in domains_col that are not yet scanned or have no active tasks."""
        cursor = self.domains_col.find({
            "scanned": {"$ne": True},
            "blacklisted": {"$ne": True}
        })
        async for domain in cursor:
            if domain.get("on_hold", False):
                continue
                
            root_domain = domain["domain"]
            
            # Check if this domain already has any active (pending or processing) tasks
            active_count = await self.tasks_col.count_documents({
                "root_domain": root_domain,
                "status": {"$in": ["pending", "processing"]}
            })
            
            if active_count == 0:
                # Check if tasks exist at all
                total_tasks = await self.tasks_col.count_documents({"root_domain": root_domain})
                if total_tasks == 0:
                    # Brand new domain or never queued: queue discovery, osint, and archive_urls tasks
                    await self.tasks_col.insert_many([
                        {
                            "root_domain": root_domain,
                            "target": root_domain,
                            "task_type": "discovery",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        },
                        {
                            "root_domain": root_domain,
                            "target": root_domain,
                            "task_type": "osint",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        },
                        {
                            "root_domain": root_domain,
                            "target": root_domain,
                            "task_type": "archive_urls",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        }
                    ])
                    logger.info(f"Loop Orchestrator: Detected unscanned domain {root_domain}. Queued discovery, OSINT, and archive URL scans.")
                else:
                    # Has tasks and none are active: check if all are completed and mark completion
                    await self.check_completion(root_domain)

    async def recover_stale_tasks(self):
        """Recover tasks that got stuck in 'processing' due to agent restarts or crashes."""
        stale_cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        stale_tasks = await self.tasks_col.find({
            "status": "processing",
            "$or": [
                {"started_at": {"$lt": stale_cutoff}},
                {"started_at": {"$exists": False}}
            ]
        }).to_list(length=100)

        for task in stale_tasks:
            task_id = task["_id"]
            task_type = task.get("task_type", "unknown")
            target = task.get("target", "unknown")
            logger.warning(f"Loop Orchestrator: Resetting stale {task_type} task for {target} (ID: {task_id}) back to pending.")
            await self.tasks_col.update_one(
                {"_id": task_id},
                {"$set": {"status": "pending", "recovered_at": datetime.datetime.utcnow()}}
            )

    async def check_and_reset_cycles(self):
        """Check for completed root domains that are due for their next scheduled scan cycle."""
        cursor = self.domains_col.find({
            "scanned": True,
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        })
        
        now = datetime.datetime.utcnow()
        
        async for domain in cursor:
            root_domain = domain["domain"]
            last_scanned_str = domain.get("last_scanned")
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
                logger.info(f"Scan cycle due for {root_domain} (Interval: {interval_hours}h). Resetting for re-scan.")
                await self.domains_col.update_one(
                    {"_id": domain["_id"]},
                    {"$set": {"scanned": False, "osint_complete": False, "archive_hunter_complete": False, "last_cycle_completed": last_scanned_str}}
                )
                await self.tasks_col.delete_many({"root_domain": root_domain})
                await self.tasks_col.insert_many([
                    {
                        "root_domain": root_domain,
                        "target": root_domain,
                        "task_type": "discovery",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    },
                    {
                        "root_domain": root_domain,
                        "target": root_domain,
                        "task_type": "osint",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    },
                    {
                        "root_domain": root_domain,
                        "target": root_domain,
                        "task_type": "archive_urls",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    }
                ])
                logger.info(f"Loop Orchestrator: Re-queued discovery, OSINT & archive cycle for {root_domain}")

    async def process_tasks(self):
        """Orchestrator manages the overall scanning lifecycle."""
        try:
            # 1. Check for newly added or unscanned domains and begin scanning them
            await self.check_unscanned_domains()
            
            # 2. Recover any tasks stuck in processing
            await self.recover_stale_tasks()
            
            # 3. Check for completed scan cycles needing reset
            await self.check_and_reset_cycles()
        except Exception as e:
            logger.error(f"Loop Orchestrator error: {e}")
            
        await asyncio.sleep(self.check_interval)

if __name__ == "__main__":
    agent = ContinuousLoopAgent()
    asyncio.run(agent.main_loop())
