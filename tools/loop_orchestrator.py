import asyncio
import datetime
import logging
import os
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)
from base_agent import BaseAgent, logger

TASK_AGENT_MAP = {
    "discovery": "subdomain_discovery",
    "alive_check": "alive_check",
    "verification": "alive_check",
    "port_scan": "port_scanner",
    "scan": "port_scanner",
    "tech_detect": "tech_fingerprinter",
    "whatweb_detect": "whatweb_fingerprinter",
    "waf_detect": "waf_detector",
    "lb_detect": "lb_detector",
    "osint": "osint_collector",
    "archive_urls": "archive_hunter",
    "directory_hunt": "directory_hunter",
    "bypass_403": "bypass_403",
    "dns_scan": "dns_scanner",
    "screenshot": "screenshot_agent",
    "dynamic_js_extract": "dynamic_js_collector",
    "cloud_storage_audit": "cloud_storage_auditor",
}

class ContinuousLoopAgent(BaseAgent):
    def __init__(self):
        super().__init__("loop_orchestrator", "Continuous Loop Orchestrator")
        # Check loop interval in seconds
        self.check_interval = int(os.getenv("CHECK_INTERVAL", "15"))
        # Default rescan interval for completed domains (hours) - 1 week (168 hours)
        self.rescan_interval = float(os.getenv("RESCAN_INTERVAL_HOURS", "168.0"))
        # Idle cooldown before restarting a completed domain in continuous mode (minutes)
        self.completion_cooldown_minutes = float(os.getenv("RESCAN_COOLDOWN_MINUTES", "2.0"))

    async def start_domain_scan(self, domain, reason="scheduled"):
        """Queue initial scan tasks for a root domain."""
        root_domain = domain["domain"]
        is_single = domain.get("single_domain_only", False)

        logger.info(f"Loop Orchestrator: Starting scan cycle for {root_domain} (single={is_single}, reason={reason}).")

        await self.domains_col.update_one(
            {"_id": domain["_id"]},
            {"$set": {
                "scanned": False,
                "osint_complete": False,
                "archive_hunter_complete": False,
                "last_cycle_completed": domain.get("last_scanned")
            }}
        )
        # Clear any stale or orphan tasks for this domain before re-queuing
        await self.tasks_col.delete_many({"root_domain": root_domain})

        cycle_tasks = [
            {"root_domain": root_domain, "target": root_domain, "task_type": "osint", "status": "pending", "created_at": datetime.datetime.utcnow()},
            {"root_domain": root_domain, "target": root_domain, "task_type": "archive_urls", "status": "pending", "created_at": datetime.datetime.utcnow()},
            {"root_domain": root_domain, "target": root_domain, "task_type": "waf_detect", "status": "pending", "created_at": datetime.datetime.utcnow()},
            {"root_domain": root_domain, "target": root_domain, "task_type": "lb_detect", "status": "pending", "created_at": datetime.datetime.utcnow()},
            {"root_domain": root_domain, "target": root_domain, "task_type": "cloud_storage_audit", "status": "pending", "created_at": datetime.datetime.utcnow()}
        ]
        if is_single:
            cycle_tasks.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "scan", "status": "pending", "created_at": datetime.datetime.utcnow()})
        else:
            cycle_tasks.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "discovery", "status": "pending", "created_at": datetime.datetime.utcnow()})

        # Only queue verification for new/unscanned subdomains so each subdomain is scanned once
        subs = (domain.get("infrastructure") or {}).get("subdomains", [])
        unscanned_subs_queued = 0
        for sub in subs:
            if isinstance(sub, dict):
                sub_name = sub.get("name")
                is_scanned = sub.get("scanned", False) or bool(sub.get("last_scanned"))
            else:
                sub_name = sub
                is_scanned = False
            if sub_name and sub_name != root_domain and not is_scanned:
                cycle_tasks.append({
                    "root_domain": root_domain,
                    "target": sub_name,
                    "task_type": "verification",
                    "status": "pending",
                    "created_at": datetime.datetime.utcnow()
                })
                unscanned_subs_queued += 1

        await self.tasks_col.insert_many(cycle_tasks)
        logger.info(f"Loop Orchestrator: Successfully queued initial {len(cycle_tasks)} tasks for {root_domain} (including {unscanned_subs_queued} unscanned subdomains).")

    async def recover_stale_tasks(self):
        """
        Intelligently recover tasks stuck in 'processing'.
        Unlike naive timeouts that prematurely cancel active scans (like ffuf or nmap),
        this checks if the worker agent is actively heartbeating.
        Tasks are only recovered if:
          1. The scanner agent is dead/unresponsive (> 180s without heartbeat) and task has been processing > 3m.
          2. The task has had zero activity for > 45 minutes (hard stall).
        """
        now = datetime.datetime.utcnow()
        agent_heartbeat_cutoff = now - datetime.timedelta(seconds=180)
        hard_stall_cutoff = now - datetime.timedelta(minutes=45)
        agent_dead_cutoff = now - datetime.timedelta(minutes=3)

        processing_tasks = await self.tasks_col.find({"status": "processing"}).to_list(length=200)

        # Cache scanner heartbeat statuses
        active_scanners = {}
        async for s in self.scanners_col.find():
            active_scanners[s.get("key")] = s.get("last_heartbeat")

        for task in processing_tasks:
            task_id = task["_id"]
            task_type = task.get("task_type", "unknown")
            target = task.get("target", "unknown")
            last_activity = task.get("last_activity") or task.get("started_at") or task.get("created_at")

            agent_key = TASK_AGENT_MAP.get(task_type)
            last_heartbeat = active_scanners.get(agent_key)
            agent_alive = last_heartbeat and last_heartbeat > agent_heartbeat_cutoff

            should_recover = False
            recovery_reason = ""

            if not last_activity:
                should_recover = True
                recovery_reason = "missing timestamp"
            elif agent_alive:
                # Agent is alive and heartbeating. Only recover if hard-stalled with zero activity for 45+ mins
                if last_activity < hard_stall_cutoff:
                    should_recover = True
                    recovery_reason = f"hard stall (no activity for 45+ minutes since {last_activity})"
            else:
                # Agent appears dead or offline
                if last_activity < agent_dead_cutoff:
                    should_recover = True
                    recovery_reason = f"agent '{agent_key}' is unresponsive (last heartbeat: {last_heartbeat})"

            if should_recover:
                logger.warning(
                    f"Loop Orchestrator: Resetting stale {task_type} task for {target} (ID: {task_id}) "
                    f"back to pending. Reason: {recovery_reason}"
                )
                await self.tasks_col.update_one(
                    {"_id": task_id},
                    {"$set": {"status": "pending", "recovered_at": now}}
                )

    async def watchdog_ensure_running(self):
        """
        Periodic Watchdog:
        Inspects all active domains to ensure scanning is running.
        If nothing is processing for an active domain:
          - If the domain is unscanned or stopped prematurely: restarts the scan pipeline immediately.
          - If the domain is completed (scanned: True): checks if the cooldown / rescan interval has passed,
            and restarts the scan cycle to maintain continuous reconnaissance.
        RESPECTS:
          - Global scanning pause (`scan_pause: True`).
          - Domain-level `on_hold: True` or `blacklisted: True`.
        """
        # 1. Respect Global Pause
        if await self.check_global_pause():
            logger.debug("Loop Orchestrator Watchdog: Global pause is active. Skipping auto-restart.")
            return

        now = datetime.datetime.utcnow()
        cursor = self.domains_col.find({
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        })

        async for domain in cursor:
            root_domain = domain["domain"]

            # Count active tasks (pending or processing)
            active_count = await self.tasks_col.count_documents({
                "root_domain": root_domain,
                "status": {"$in": ["pending", "processing"]}
            })

            if active_count > 0:
                # Scanning is actively in progress
                continue

            # Nothing is processing for this domain!
            is_scanned = domain.get("scanned", False)
            last_scanned_str = domain.get("last_scanned")
            interval_hours = domain.get("scan_interval", self.rescan_interval)

            if not is_scanned:
                # Unscanned or interrupted domain with 0 active tasks
                total_tasks = await self.tasks_col.count_documents({"root_domain": root_domain})
                if total_tasks == 0:
                    logger.info(f"Loop Orchestrator Watchdog: Domain {root_domain} has no tasks. Starting initial scan.")
                    await self.start_domain_scan(domain, reason="unscanned_new_domain")
                else:
                    # Tasks exist but none are active: check completion
                    completed_count = await self.tasks_col.count_documents({"root_domain": root_domain, "status": "completed"})
                    failed_count = await self.tasks_col.count_documents({"root_domain": root_domain, "status": "failed"})
                    if completed_count + failed_count == total_tasks:
                        logger.info(f"Loop Orchestrator Watchdog: All {total_tasks} tasks completed for {root_domain}. Marking completion.")
                        await self.check_completion(root_domain)
                    else:
                        logger.warning(f"Loop Orchestrator Watchdog: Domain {root_domain} stalled with 0 active tasks. Restarting pipeline.")
                        await self.start_domain_scan(domain, reason="stalled_restart")
            else:
                # Domain is marked completed (scanned: True). Check if it is time to restart.
                should_restart = False
                custom_interval = domain.get("scan_interval")
                if custom_interval is not None and float(custom_interval) > 0:
                    # User specified an explicit schedule interval (hours)
                    restart_threshold_seconds = float(custom_interval) * 3600
                else:
                    # Default rescan interval: 1 week (168 hours)
                    restart_threshold_seconds = self.rescan_interval * 3600

                if not last_scanned_str:
                    should_restart = True
                else:
                    try:
                        last_scanned = datetime.datetime.fromisoformat(last_scanned_str.replace("Z", "+00:00")).replace(tzinfo=None)
                        elapsed_seconds = (now - last_scanned).total_seconds()
                        if elapsed_seconds >= restart_threshold_seconds:
                            logger.info(
                                f"Loop Orchestrator Watchdog: Domain {root_domain} idle for {int(elapsed_seconds)}s "
                                f"(threshold: {int(restart_threshold_seconds)}s). Restarting cycle."
                            )
                            should_restart = True
                    except Exception as e:
                        logger.error(f"Error parsing last_scanned for {root_domain}: {e}")
                        should_restart = True

                if should_restart:
                    await self.start_domain_scan(domain, reason="periodic_rescan_cycle")

    async def purge_orphaned_tasks(self):
        """Purge tasks belonging to domains that are no longer active in domains_col."""
        active_domains = await self.domains_col.distinct("domain", {
            "blacklisted": {"$ne": True}
        })
        active_set = set(active_domains)
        task_root_domains = await self.tasks_col.distinct("root_domain")
        for rd in task_root_domains:
            if rd and rd not in active_set:
                logger.warning(f"Loop Orchestrator: Purging orphaned/out-of-scope tasks for domain: {rd}")
                del_result = await self.tasks_col.delete_many({"root_domain": rd})
                logger.info(f"Loop Orchestrator: Deleted {del_result.deleted_count} tasks for {rd}")

    async def process_tasks(self):
        """Orchestrator manages the overall scanning lifecycle and watchdog."""
        try:
            now = datetime.datetime.utcnow()
            # Standby / Sleep detection: if time elapsed since last loop iteration is much larger than check_interval
            if hasattr(self, "_last_loop_time") and self._last_loop_time:
                loop_gap = (now - self._last_loop_time).total_seconds()
                if loop_gap > (self.check_interval * 3):
                    logger.warning(
                        f"Loop Orchestrator: System sleep/standby wake detected (gap of {int(loop_gap)}s). "
                        f"Resetting any interrupted processing tasks."
                    )
                    await self.tasks_col.update_many(
                        {"status": "processing"},
                        {"$set": {"status": "pending", "recovered_at": now}}
                    )
            self._last_loop_time = now

            # 1. Purge any orphaned or out-of-scope tasks
            await self.purge_orphaned_tasks()

            # 2. Recover any truly dead/hung tasks
            await self.recover_stale_tasks()

            # 3. Watchdog: check whether domains are running; restart if idle/stopped (unless paused)
            await self.watchdog_ensure_running()

        except Exception as e:
            logger.error(f"Loop Orchestrator error: {e}", exc_info=True)

        await asyncio.sleep(self.check_interval)

if __name__ == "__main__":
    agent = ContinuousLoopAgent()
    asyncio.run(agent.main_loop())
