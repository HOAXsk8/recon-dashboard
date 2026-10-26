#!/usr/bin/env python3
"""
Recon Autoscaler (tools/autoscaler.py)
=====================================
Unified, intelligent, multi-tool autoscaler for the continuous reconnaissance pipeline.
Monitors system vitals (CPU & RAM) from /proc alongside task backlogs in MongoDB.
Dynamically scales worker containers for all reconnaissance tools to maximize throughput
while strictly maintaining total system resource utilization below 80%.
"""

import os
import sys
import time
import json
import socket
import logging
import asyncio
import http.client
import datetime
from typing import Dict, Any, List, Optional, Tuple
from motor.motor_asyncio import AsyncIOMotorClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("autoscaler")

MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD")
if not MONGO_ROOT_PASSWORD:
    try:
        env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.startswith("MONGO_ROOT_PASSWORD="):
                        MONGO_ROOT_PASSWORD = line.split("=", 1)[1].strip().strip('"').strip("'")
                        break
    except Exception:
        pass

MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_URI = f"mongodb://admin:{MONGO_ROOT_PASSWORD}@{MONGO_HOST}:27017/?authSource=admin" if MONGO_ROOT_PASSWORD else f"mongodb://{MONGO_HOST}:27017"
DB_NAME = "recon_db"

def discover_docker_socket() -> str:
    """Find the valid Docker UNIX socket path."""
    candidates = [
        os.getenv("DOCKER_SOCKET"),
        "/var/run/docker.sock",
        os.path.expanduser("~/.colima/default/docker.sock"),
        "/Users/john/.colima/default/docker.sock",
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return "/var/run/docker.sock"


class DockerUnixClient:
    """Pure standard-library Docker Engine API client via UNIX Domain Socket."""
    def __init__(self, sock_path: Optional[str] = None):
        self.sock_path = sock_path or discover_docker_socket()

    def request(self, method: str, path: str, body: Any = None) -> Tuple[int, Any]:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self.sock_path)
            conn = http.client.HTTPConnection("localhost")
            conn.sock = sock
            headers = {"Content-Type": "application/json"} if body is not None else {}
            payload = json.dumps(body) if body is not None else None
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", errors="ignore")
            status = resp.status
            conn.close()
            try:
                data = json.loads(raw) if raw and raw.startswith(("{", "[")) else raw
            except Exception:
                data = raw
            return status, data
        except Exception as e:
            logger.debug(f"Docker API call {method} {path} error: {e}")
            return 500, str(e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def list_all_containers(self) -> List[Dict[str, Any]]:
        status, containers = self.request("GET", "/v1.41/containers/json?all=1")
        if status == 200 and isinstance(containers, list):
            return containers
        return []

    def start_container(self, name_or_id: str) -> bool:
        status, _ = self.request("POST", f"/v1.41/containers/{name_or_id}/start")
        return status in [204, 304]

    def stop_container(self, name_or_id: str, timeout: int = 5) -> bool:
        status, _ = self.request("POST", f"/v1.41/containers/{name_or_id}/stop?t={timeout}")
        return status in [204, 304]

    def remove_container(self, name_or_id: str, force: bool = True) -> bool:
        status, _ = self.request("DELETE", f"/v1.41/containers/{name_or_id}?v=1&force={'true' if force else 'false'}")
        return status in [204, 404]

    def inspect_container(self, name_or_id: str) -> Optional[dict]:
        status, data = self.request("GET", f"/v1.41/containers/{name_or_id}/json")
        return data if status == 200 and isinstance(data, dict) else None

    def create_cloned_worker(self, name: str, template_name: str, instance_id: int, mem_limit: int, nano_cpus: int) -> bool:
        """Create a new container cloning the config of an existing template container."""
        tpl = self.inspect_container(template_name)
        if not tpl:
            logger.error(f"[Autoscaler] Template container '{template_name}' not found for creating '{name}'.")
            return False

        cfg = tpl.get("Config", {})
        host_cfg = tpl.get("HostConfig", {})

        existing_env = cfg.get("Env", [])
        new_env = [e for e in existing_env if not e.startswith("INSTANCE_ID=")]
        new_env.append(f"INSTANCE_ID={instance_id}")

        create_payload = {
            "Image": cfg.get("Image", "recon-dashboard:latest"),
            "Cmd": cfg.get("Cmd"),
            "Env": new_env,
            "HostConfig": {
                "Binds": host_cfg.get("Binds", [
                    "/app/app",
                    "/app/templates",
                    "/app/tools"
                ]),
                "NetworkMode": host_cfg.get("NetworkMode", "host"),
                "Memory": mem_limit or host_cfg.get("Memory", 1073741824),
                "NanoCpus": nano_cpus or host_cfg.get("NanoCpus", 1000000000),
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3}
            }
        }

        status, resp = self.request("POST", f"/v1.41/containers/create?name={name}", create_payload)
        if status in [200, 201]:
            logger.info(f"[Autoscaler] Created worker container {name} successfully.")
            return True
        else:
            logger.error(f"[Autoscaler] Failed to create container {name}: status {status}, response: {resp}")
            return False


class SystemResourceMonitor:
    """Monitors real-time CPU % and RAM % directly from /proc."""
    def __init__(self):
        self._last_cpu = None
        self._last_time = 0.0

    def sample_vitals(self) -> Dict[str, float]:
        ram_percent = 0.0
        cpu_percent = 0.0
        now = time.time()

        # 1. RAM Usage from /proc/meminfo
        try:
            mem_info = {}
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        k = parts[0].strip()
                        v = parts[1].strip().split()[0]
                        if v.isdigit():
                            mem_info[k] = int(v)
            total = mem_info.get("MemTotal", 0)
            available = mem_info.get("MemAvailable", mem_info.get("MemFree", 0))
            if total > 0:
                used = total - available
                ram_percent = round((used / total) * 100.0, 1)
        except Exception:
            pass

        # 2. CPU Usage from /proc/stat
        try:
            with open("/proc/stat", "r") as f:
                first_line = f.readline()
            fields = [float(x) for x in first_line.split()[1:]]
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
            total = sum(fields)

            if self._last_cpu is not None and (now - self._last_time) > 0.1:
                last_idle, last_total = self._last_cpu
                idle_delta = idle - last_idle
                total_delta = total - last_total
                if total_delta > 0:
                    cpu_percent = round(100.0 * (1.0 - (idle_delta / total_delta)), 1)

            self._last_cpu = (idle, total)
            self._last_time = now
            cpu_percent = max(0.0, min(100.0, cpu_percent))
        except Exception:
            pass

        return {
            "ram_percent": ram_percent,
            "cpu_percent": cpu_percent,
            "peak_percent": max(ram_percent, cpu_percent)
        }


# Multi-Tool Scaling Profiles Matrix
TOOL_SCALING_PROFILES: Dict[str, Dict[str, Any]] = {
    "directory_hunter": {
        "name": "Directory & File Hunter",
        "task_type": ["directory_hunt"],
        "container_slug": "directory-hunter",
        "template_container": "directory-hunter-1",
        "baseline_is_numbered": True,
        "min_workers": 2,
        "max_workers": 12,
        "mem_limit": 1258291200,   # 1200MB
        "nano_cpus": 1000000000,   # 1.0 core
        "priority": 10,
    },
    "dynamic_js_collector": {
        "name": "Dynamic JS Collector",
        "task_type": ["dynamic_js_extract"],
        "container_slug": "dynamic-js-collector",
        "template_container": "dynamic-js-collector",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 4,
        "mem_limit": 2147483648,   # 2048MB
        "nano_cpus": 1500000000,   # 1.5 cores
        "priority": 9,
    },
    "alive_check": {
        "name": "Alive Check Agent",
        "task_type": ["verification", "alive_check"],
        "container_slug": "alive-check",
        "template_container": "alive-check",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 6,
        "mem_limit": 536870912,    # 512MB
        "nano_cpus": 800000000,    # 0.8 core
        "priority": 9,
    },
    "port_scanner": {
        "name": "Port Scanner",
        "task_type": ["scan", "port_scan"],
        "container_slug": "port-scanner",
        "template_container": "port-scanner",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 6,
        "mem_limit": 536870912,    # 512MB
        "nano_cpus": 800000000,    # 0.8 core
        "priority": 8,
    },
    "tech_fingerprinter": {
        "name": "Tech Fingerprinter",
        "task_type": ["tech_detect"],
        "container_slug": "tech-fingerprinter",
        "template_container": "tech-fingerprinter",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 6,
        "mem_limit": 805306368,    # 768MB
        "nano_cpus": 800000000,    # 0.8 core
        "priority": 8,
    },
    "archive_hunter": {
        "name": "Archive Hunter",
        "task_type": ["archive_urls"],
        "container_slug": "archive-hunter",
        "template_container": "archive-hunter",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 4,
        "mem_limit": 536870912,    # 512MB
        "nano_cpus": 600000000,    # 0.6 core
        "priority": 7,
    },
    "subdomain_discovery": {
        "name": "Subdomain Discovery",
        "task_type": ["discovery"],
        "container_slug": "subdomain-discovery",
        "template_container": "subdomain-discovery",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 3,
        "mem_limit": 805306368,    # 768MB
        "nano_cpus": 1000000000,   # 1.0 core
        "priority": 7,
    },
    "bypass_403": {
        "name": "403 Bypass Engine",
        "task_type": ["bypass_403"],
        "container_slug": "bypass-403",
        "template_container": "bypass-403",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 4,
        "mem_limit": 536870912,    # 512MB
        "nano_cpus": 600000000,    # 0.6 core
        "priority": 6,
    },
    "screenshot_agent": {
        "name": "Screenshot Agent",
        "task_type": ["screenshot"],
        "container_slug": "screenshot-agent",
        "template_container": "screenshot-agent",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 3,
        "mem_limit": 1610612736,   # 1536MB
        "nano_cpus": 1000000000,   # 1.0 core
        "priority": 5,
    },
    "waf_detector": {
        "name": "WAF Detector",
        "task_type": ["waf_detect"],
        "container_slug": "waf-detector",
        "template_container": "waf-detector",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 3,
        "mem_limit": 402653184,    # 384MB
        "nano_cpus": 500000000,    # 0.5 core
        "priority": 5,
    },
    "cloud_storage_auditor": {
        "name": "Cloud Storage Auditor",
        "task_type": ["cloud_storage_audit"],
        "container_slug": "cloud-storage-auditor",
        "template_container": "cloud-storage-auditor",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 3,
        "mem_limit": 402653184,    # 384MB
        "nano_cpus": 500000000,    # 0.5 core
        "priority": 5,
    },
    "lb_detector": {
        "name": "Load Balancer Detector",
        "task_type": ["lb_detect"],
        "container_slug": "lb-detector",
        "template_container": "lb-detector",
        "baseline_is_numbered": False,
        "min_workers": 1,
        "max_workers": 3,
        "mem_limit": 402653184,    # 384MB
        "nano_cpus": 500000000,    # 0.5 core
        "priority": 5,
    }
}


class ReconAutoscaler:
    """
    Unified, intelligent autoscaler for all continuous reconnaissance tools.
    - Monitors pending queues per tool.
    - Scales up worker containers dynamically when backlog exists and headroom is < 75%.
    - Enforces strict 80% ceiling: halts and scales down excess workers if usage >= 80%.
    - Scales down idle workers to baseline and removes stale scanner records.
    """
    def __init__(self, db_client: Optional[AsyncIOMotorClient] = None):
        self.client = db_client or AsyncIOMotorClient(MONGO_URI)
        self.db = self.client[DB_NAME]
        self.tasks_col = self.db["tasks"]
        self.settings_col = self.db["settings"]
        self.scanners_col = self.db["scanners"]
        self.docker = DockerUnixClient()
        self.monitor = SystemResourceMonitor()

        # Hard constraints
        self.target_ceiling = 80.0       # Hard ceiling: strictly below 80%
        self.scale_up_threshold = 75.0   # Scale up threshold: only add workers when headroom is safely < 75%
        self.emergency_scale_down = 80.0 # Scale down immediately if >= 80%
        self.loop_interval = 6           # Seconds between autoscaling checks
        self.last_scale_action = 0.0
        self.cooldown_sec = 6.0          # Settling time after starting or stopping a worker

    def parse_tool_containers(self, all_containers: List[Dict[str, Any]]) -> Dict[str, Dict[int, Dict[str, Any]]]:
        """
        Maps tool_key -> { instance_id -> {id, name, state, status} }
        """
        tool_instances: Dict[str, Dict[int, Dict[str, Any]]] = {k: {} for k in TOOL_SCALING_PROFILES}

        for c in all_containers:
            for raw_name in c.get("Names", []):
                clean_name = raw_name.lstrip("/")
                for tool_key, profile in TOOL_SCALING_PROFILES.items():
                    slug = profile["container_slug"]
                    # Case 1: unnumbered baseline (e.g. "dynamic-js-collector")
                    if clean_name == slug:
                        tool_instances[tool_key][1] = {
                            "id": c.get("Id"),
                            "name": clean_name,
                            "state": c.get("State", ""),
                            "status": c.get("Status", "")
                        }
                    # Case 2: numbered instance (e.g. "dynamic-js-collector-2" or "directory-hunter-1")
                    elif clean_name.startswith(f"{slug}-"):
                        suffix = clean_name[len(slug) + 1:]
                        if suffix.isdigit():
                            iid = int(suffix)
                            tool_instances[tool_key][iid] = {
                                "id": c.get("Id"),
                                "name": clean_name,
                                "state": c.get("State", ""),
                                "status": c.get("Status", "")
                            }

        return tool_instances

    async def get_queue_depths(self) -> Dict[str, Dict[str, int]]:
        """Fetch pending and processing task counts for each tool."""
        all_task_types = []
        for p in TOOL_SCALING_PROFILES.values():
            all_task_types.extend(p["task_type"])

        pipeline = [
            {"$match": {"task_type": {"$in": all_task_types}, "status": {"$in": ["pending", "processing"]}}},
            {"$group": {"_id": {"task_type": "$task_type", "status": "$status"}, "count": {"$sum": 1}}}
        ]

        cursor = self.tasks_col.aggregate(pipeline)
        raw_counts = {}
        async for doc in cursor:
            tt = doc["_id"]["task_type"]
            st = doc["_id"]["status"]
            raw_counts[(tt, st)] = doc["count"]

        queue_depths = {}
        for tool_key, profile in TOOL_SCALING_PROFILES.items():
            pending = sum(raw_counts.get((tt, "pending"), 0) for tt in profile["task_type"])
            processing = sum(raw_counts.get((tt, "processing"), 0) for tt in profile["task_type"])
            queue_depths[tool_key] = {"pending": pending, "processing": processing}

        return queue_depths

    async def prune_stale_scanners(self, active_worker_keys: set):
        """Clean up any dynamic scanner records from DB for non-running instances."""
        try:
            # Match any dynamic worker like directory_hunter_3, tech_fingerprinter_2, etc.
            dynamic_scanners = await self.scanners_col.find({
                "key": {"$regex": r"^[a-zA-Z0-9_]+_\d+$"}
            }).to_list(length=200)

            stale_ids = []
            for sc in dynamic_scanners:
                k = sc.get("key", "")
                if k not in active_worker_keys:
                    stale_ids.append(sc["_id"])

            if stale_ids:
                await self.scanners_col.delete_many({"_id": {"$in": stale_ids}})
                logger.info(f"[Autoscaler] Pruned {len(stale_ids)} stale dynamic scanner records from database.")
        except Exception as e:
            logger.debug(f"[Autoscaler] Prune scanners error: {e}")

    async def evaluate_and_scale(self):
        """Unified evaluation loop: samples vitals and decides scaling actions."""
        now = time.time()
        vitals = self.monitor.sample_vitals()
        cpu_pct = vitals["cpu_percent"]
        ram_pct = vitals["ram_percent"]
        peak_pct = vitals["peak_percent"]

        # 1. Fetch task backlogs and container map
        all_containers = self.docker.list_all_containers()
        tool_instances = self.parse_tool_containers(all_containers)
        queue_depths = await self.get_queue_depths()

        # Build active running worker set
        active_worker_keys = set()
        running_counts: Dict[str, int] = {}
        excess_workers_map: Dict[str, List[int]] = {}

        for tool_key, profile in TOOL_SCALING_PROFILES.items():
            instances = tool_instances.get(tool_key, {})
            running_iids = [iid for iid, info in instances.items() if info["state"] == "running"]
            running_counts[tool_key] = len(running_iids)
            min_w = profile["min_workers"]
            excess = [iid for iid in running_iids if iid > min_w]
            excess_workers_map[tool_key] = sorted(excess)

            for iid in running_iids:
                if iid == 1 and not profile["baseline_is_numbered"]:
                    active_worker_keys.add(tool_key)
                else:
                    active_worker_keys.add(f"{tool_key}_{iid}")

        # Periodic cleanup of stale scanner records
        await self.prune_stale_scanners(active_worker_keys)

        # Total workers running
        total_workers = sum(running_counts.values())

        # Save autoscaler telemetry to Mongo for dashboard
        telemetry = {
            "key": "autoscaler",
            "last_evaluated": datetime.datetime.utcnow().isoformat() + "Z",
            "cpu_percent": cpu_pct,
            "ram_percent": ram_pct,
            "peak_percent": peak_pct,
            "target_ceiling": self.target_ceiling,
            "total_workers": total_workers,
            "status": "active",
            "tools": {}
        }
        for tool_key, profile in TOOL_SCALING_PROFILES.items():
            telemetry["tools"][tool_key] = {
                "name": profile["name"],
                "running": running_counts.get(tool_key, 0),
                "min": profile["min_workers"],
                "max": profile["max_workers"],
                "pending": queue_depths[tool_key]["pending"],
                "processing": queue_depths[tool_key]["processing"],
            }
        await self.settings_col.update_one({"key": "autoscaler"}, {"$set": telemetry}, upsert=True)

        logger.info(
            f"[Autoscaler] Vitals: CPU={cpu_pct}%, RAM={ram_pct}% (Peak={peak_pct}%). "
            f"Total active workers: {total_workers}."
        )

        # -------------------------------------------------------------------
        # 1. EMERGENCY RELIEF: Peak resource >= 80.0%
        # -------------------------------------------------------------------
        if peak_pct >= self.emergency_scale_down:
            logger.warning(
                f"[Autoscaler] System resource ceiling exceeded (CPU: {cpu_pct}%, RAM: {ram_pct}% >= {self.emergency_scale_down}%). "
                f"Halting spawn and relieving load."
            )
            if (now - self.last_scale_action) >= self.cooldown_sec:
                # Find tool with excess workers to stop
                tool_to_relieve = None
                max_excess = 0
                for tool_key, excess in excess_workers_map.items():
                    if len(excess) > max_excess:
                        max_excess = len(excess)
                        tool_to_relieve = tool_key

                if tool_to_relieve and excess_workers_map[tool_to_relieve]:
                    target_iid = max(excess_workers_map[tool_to_relieve])
                    profile = TOOL_SCALING_PROFILES[tool_to_relieve]
                    slug = profile["container_slug"]
                    target_container = f"{slug}-{target_iid}"
                    logger.warning(f"[Autoscaler] Emergency scale-down: stopping {target_container} to reduce usage below 80%.")
                    stopped = self.docker.stop_container(target_container, timeout=5)
                    if stopped:
                        self.docker.remove_container(target_container, force=True)
                        await self.scanners_col.delete_one({"key": f"{tool_to_relieve}_{target_iid}"})
                        self.last_scale_action = now
                        logger.info(f"[Autoscaler] Emergency stopped and removed {target_container}.")
            return

        # -------------------------------------------------------------------
        # 2. SCALE-UP: When headroom is safely available (< 75%)
        # -------------------------------------------------------------------
        if peak_pct < self.scale_up_threshold:
            if (now - self.last_scale_action) >= self.cooldown_sec:
                # Identify candidates needing more workers
                candidates = []
                for tool_key, profile in TOOL_SCALING_PROFILES.items():
                    pending = queue_depths[tool_key]["pending"]
                    processing = queue_depths[tool_key]["processing"]
                    running = running_counts[tool_key]
                    max_w = profile["max_workers"]

                    if pending > 0 and running < max_w:
                        total_work = pending + processing
                        if running < total_work:
                            candidates.append({
                                "tool_key": tool_key,
                                "priority": profile["priority"],
                                "pending": pending,
                                "running": running,
                                "max": max_w
                            })

                if candidates:
                    # Sort candidates by: priority descending, then pending backlog descending
                    candidates.sort(key=lambda x: (x["priority"], x["pending"]), reverse=True)
                    top_candidate = candidates[0]
                    chosen_key = top_candidate["tool_key"]
                    profile = TOOL_SCALING_PROFILES[chosen_key]
                    slug = profile["container_slug"]
                    template = profile["template_container"]
                    current_instances = tool_instances.get(chosen_key, {})

                    # Check if there is an existing stopped container we can restart
                    stopped_iids = [iid for iid, info in current_instances.items() if info["state"] != "running"]
                    if stopped_iids:
                        next_iid = min(stopped_iids)
                        target_name = current_instances[next_iid]["name"]
                        logger.info(
                            f"[Autoscaler] Headroom available ({peak_pct}% < {self.scale_up_threshold}%). "
                            f"Starting existing stopped {target_name} for {profile['name']} ({top_candidate['pending']} pending tasks)."
                        )
                        started = self.docker.start_container(target_name)
                        if started:
                            self.last_scale_action = now
                            logger.info(f"[Autoscaler] Started {target_name}. Now running: {top_candidate['running'] + 1} workers.")
                            return
                    else:
                        # Find next available instance_id
                        existing_iids = set(current_instances.keys())
                        next_iid = 1
                        while next_iid in existing_iids:
                            next_iid += 1

                        target_name = f"{slug}-{next_iid}"
                        logger.info(
                            f"[Autoscaler] Headroom available ({peak_pct}% < {self.scale_up_threshold}%). "
                            f"Spawning new {target_name} for {profile['name']} ({top_candidate['pending']} pending tasks)."
                        )
                        created = self.docker.create_cloned_worker(
                            name=target_name,
                            template_name=template,
                            instance_id=next_iid,
                            mem_limit=profile["mem_limit"],
                            nano_cpus=profile["nano_cpus"]
                        )
                        if created:
                            started = self.docker.start_container(target_name)
                            if started:
                                self.last_scale_action = now
                                logger.info(f"[Autoscaler] Successfully launched {target_name}.")
                                return

        # -------------------------------------------------------------------
        # 3. IDLE SCALE-DOWN: Queue empty, scale back to baseline
        # -------------------------------------------------------------------
        if (now - self.last_scale_action) >= self.cooldown_sec:
            for tool_key, profile in TOOL_SCALING_PROFILES.items():
                pending = queue_depths[tool_key]["pending"]
                processing = queue_depths[tool_key]["processing"]
                running = running_counts[tool_key]
                min_w = profile["min_workers"]

                # If queue is empty and running workers exceed needed baseline
                needed = max(min_w, processing)
                if pending == 0 and running > needed:
                    excess = excess_workers_map[tool_key]
                    if excess:
                        highest_iid = max(excess)
                        slug = profile["container_slug"]
                        target_name = f"{slug}-{highest_iid}"
                        logger.info(
                            f"[Autoscaler] Idle scale-down: {profile['name']} pending queue is empty ({processing} active). "
                            f"Stopping excess {target_name} back toward baseline ({needed} workers)."
                        )
                        stopped = self.docker.stop_container(target_name, timeout=10)
                        if stopped:
                            self.docker.remove_container(target_name, force=True)
                            await self.scanners_col.delete_one({"key": f"{tool_key}_{highest_iid}"})
                            self.last_scale_action = now
                            logger.info(f"[Autoscaler] Stopped, removed and pruned {target_name}.")
                            return

    async def run(self):
        """Continuous execution daemon."""
        logger.info("[Autoscaler] Starting continuous automated multi-tool autoscaling daemon...")
        while True:
            try:
                await self.evaluate_and_scale()
            except Exception as e:
                logger.error(f"[Autoscaler] Unexpected error: {e}", exc_info=True)
            await asyncio.sleep(self.loop_interval)


if __name__ == "__main__":
    autoscaler = ReconAutoscaler()
    asyncio.run(autoscaler.run())
