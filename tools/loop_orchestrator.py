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
        # Default rescan interval for completed domains (hours) - 1 month (720 hours / 30 days)
        self.rescan_interval = float(os.getenv("RESCAN_INTERVAL_HOURS", "720.0"))
        # Idle cooldown before restarting a completed domain in continuous mode (minutes)
        self.completion_cooldown_minutes = float(os.getenv("RESCAN_COOLDOWN_MINUTES", "2.0"))

    async def start_domain_scan(self, domain, reason="scheduled"):
        """Queue initial scan tasks for a root domain."""
        root_domain = domain["domain"]
        is_single = domain.get("single_domain_only", False)

        logger.info(f"Loop Orchestrator: Starting scan cycle for {root_domain} (single={is_single}, reason={reason}).")

        last_completed = domain.get("last_scanned")
        if not last_completed or last_completed == "Never":
            last_completed = domain.get("last_cycle_completed")

        await self.domains_col.update_one(
            {"_id": domain["_id"]},
            {"$set": {
                "scanned": False,
                "osint_complete": False,
                "archive_hunter_complete": False,
                "last_cycle_completed": last_completed
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
            cycle_tasks.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "verification", "status": "pending", "created_at": datetime.datetime.utcnow()})
            cycle_tasks.insert(1, {"root_domain": root_domain, "target": root_domain, "task_type": "scan", "status": "pending", "created_at": datetime.datetime.utcnow()})
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

        ws_id = str(domain["workspace_id"]) if domain.get("workspace_id") else None
        if ws_id:
            for t in cycle_tasks:
                t["workspace_id"] = ws_id

        await self.tasks_col.insert_many(cycle_tasks)
        logger.info(f"Loop Orchestrator: Successfully queued initial {len(cycle_tasks)} tasks for {root_domain} (workspace: {ws_id}, including {unscanned_subs_queued} unscanned subdomains).")

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
                # Fast tasks (discovery, verification, waf, lb, osint) shouldn't hang for more than 5 minutes
                fast_tasks = {"discovery", "verification", "waf_detect", "lb_detect", "osint", "archive_urls"}
                stall_limit_mins = 5 if task_type in fast_tasks else 25
                stall_cutoff = now - datetime.timedelta(minutes=stall_limit_mins)
                if last_activity < stall_cutoff:
                    should_recover = True
                    recovery_reason = f"task stall (no activity for {stall_limit_mins}+ minutes since {last_activity})"
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

            # Check if domain's workspace is paused
            ws_id = domain.get("workspace_id")
            if ws_id:
                try:
                    from bson import ObjectId
                    ws_query = {"_id": ObjectId(ws_id)} if isinstance(ws_id, str) and len(ws_id) == 24 else {"_id": ws_id}
                    ws_doc = await self.workspaces_col.find_one(ws_query)
                    if ws_doc and ws_doc.get("scan_paused"):
                        # Workspace is paused - skip watchdog auto-restart
                        continue
                except Exception:
                    pass

            effective_interval_hours = await self.get_effective_scan_interval(domain)
            is_scanned = domain.get("scanned", False)
            last_scanned_str = domain.get("last_scanned")

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
                # Domain is marked completed (scanned: True). Check if it is time to restart based on effective interval.
                should_restart = False
                restart_threshold_seconds = effective_interval_hours * 3600.0

                if not last_scanned_str:
                    should_restart = True
                else:
                    try:
                        last_scanned = datetime.datetime.fromisoformat(last_scanned_str.replace("Z", "+00:00")).replace(tzinfo=None)
                        elapsed_seconds = (now - last_scanned).total_seconds()
                        if elapsed_seconds >= restart_threshold_seconds:
                            logger.info(
                                f"Loop Orchestrator Watchdog: Domain {root_domain} idle for {int(elapsed_seconds)}s "
                                f"(threshold: {int(restart_threshold_seconds)}s / {effective_interval_hours}h). Restarting cycle."
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

            # 3. Automated Circuit Breaker: check system load and halt offending workspace if limit reached
            await self.check_resource_circuit_breaker()

            # 4. Watchdog: check whether domains are running; restart if idle/stopped (unless paused)
            await self.watchdog_ensure_running()

        except Exception as e:
            logger.error(f"Loop Orchestrator error: {e}", exc_info=True)

        await asyncio.sleep(self.check_interval)

    async def get_effective_scan_interval(self, domain: dict) -> float:
        """
        Hierarchy:
        1. Domain-level override (if set and > 0)
        2. Workspace-level default_scan_interval (if set and > 0)
        3. Global default (self.rescan_interval = 720.0 hours / 1 month)
        """
        custom_interval = domain.get("scan_interval")
        if custom_interval is not None and float(custom_interval) > 0:
            return float(custom_interval)

        ws_id = domain.get("workspace_id")
        if ws_id:
            try:
                from bson import ObjectId
                ws_query = {"_id": ObjectId(ws_id)} if isinstance(ws_id, str) and len(ws_id) == 24 else {"_id": ws_id}
                ws_doc = await self.workspaces_col.find_one(ws_query)
                if ws_doc and ws_doc.get("default_scan_interval") is not None and float(ws_doc.get("default_scan_interval")) > 0:
                    return float(ws_doc["default_scan_interval"])
            except Exception as e:
                logger.debug(f"Error fetching workspace scan interval: {e}")

        return self.rescan_interval

    async def check_resource_circuit_breaker(self):
        """
        Circuit Breaker: monitors system CPU and RAM.
        If system load is >= 92% CPU or RAM, auto-pauses the most recently active
        workspace to prevent host crashes/dropped packets and sends an alert.
        """
        try:
            # Check RAM from /proc/meminfo
            ram_percent = 0.0
            with open("/proc/meminfo", "r") as f:
                raw_mem = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        raw_mem[parts[0].strip()] = int(parts[1].split()[0])
                total = raw_mem.get("MemTotal", 1)
                avail = raw_mem.get("MemAvailable", raw_mem.get("MemFree", 0))
                ram_percent = round(((total - avail) / total) * 100.0, 1)

            # Check CPU from /proc/stat
            cpu_percent = 0.0
            if hasattr(self, "_last_cb_cpu") and self._last_cb_cpu:
                with open("/proc/stat", "r") as f:
                    fields = [float(x) for x in f.readline().split()[1:8]]
                idle = fields[3] + fields[4]
                total_cpu = sum(fields)
                d_idle = idle - self._last_cb_cpu["idle"]
                d_total = total_cpu - self._last_cb_cpu["total"]
                if d_total > 0:
                    cpu_percent = round((1.0 - (d_idle / d_total)) * 100.0, 1)
                self._last_cb_cpu = {"idle": idle, "total": total_cpu}
            else:
                with open("/proc/stat", "r") as f:
                    fields = [float(x) for x in f.readline().split()[1:8]]
                self._last_cb_cpu = {"idle": fields[3] + fields[4], "total": sum(fields)}

            if cpu_percent >= 92.0 or ram_percent >= 92.0:
                logger.critical(
                    f"CIRCUIT BREAKER TRIGGERED: System resources critical (CPU: {cpu_percent}%, RAM: {ram_percent}%). "
                    f"Identifying offending workspace to halt."
                )
                active_ws_ids = await self.tasks_col.distinct("workspace_id", {"status": "processing"})
                active_unpaused = []
                for wid in active_ws_ids:
                    if wid:
                        from bson import ObjectId
                        ws_doc = await self.workspaces_col.find_one({"_id": ObjectId(wid)} if len(wid) == 24 else {"_id": wid})
                        if ws_doc and not ws_doc.get("scan_paused"):
                            active_unpaused.append(ws_doc)

                if active_unpaused:
                    ws_to_halt = sorted(active_unpaused, key=lambda w: str(w.get("_id")), reverse=True)[0]
                    ws_id_str = str(ws_to_halt["_id"])
                    ws_name = ws_to_halt.get("name", "Unknown")

                    logger.warning(f"Circuit Breaker: Auto-halting scanning for workspace '{ws_name}' ({ws_id_str}).")
                    await self.workspaces_col.update_one(
                        {"_id": ws_to_halt["_id"]},
                        {"$set": {
                            "scan_paused": True,
                            "paused_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "pause_reason": f"Automated circuit breaker: resource exhaustion limit reached (CPU: {cpu_percent}%, RAM: {ram_percent}%)"
                        }}
                    )
                    reset_res = await self.tasks_col.update_many(
                        {"workspace_id": ws_id_str, "status": "processing"},
                        {"$set": {"status": "pending", "paused": True}}
                    )
                    logger.info(f"Circuit Breaker: Reset {reset_res.modified_count} processing tasks for {ws_name} back to pending.")

                    await self.leads_col.insert_one({
                        "domain": ws_name,
                        "workspace_id": ws_id_str,
                        "title": f"Resource Exhaustion: Scanning Halted on {ws_name}",
                        "severity": "high",
                        "status": "new",
                        "category": "system",
                        "details": {
                            "workspace": ws_name,
                            "cpu_percent": cpu_percent,
                            "ram_percent": ram_percent,
                            "message": f"Scanning was automatically paused on workspace '{ws_name}' to protect host system stability."
                        },
                        "created_at": datetime.datetime.utcnow()
                    })
        except Exception as e:
            logger.debug(f"Circuit breaker monitor error: {e}")

if __name__ == "__main__":
    agent = ContinuousLoopAgent()
    asyncio.run(agent.main_loop())
