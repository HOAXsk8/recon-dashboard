import os
import sys
import time
import json
import socket
import logging
import asyncio
import http.client
from typing import Dict, Any, List, Optional
from motor.motor_asyncio import AsyncIOMotorClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("directory_hunter_autoscaler")

MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD")
if not MONGO_ROOT_PASSWORD:
    # Attempt to read from .env if available
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

def discover_docker_socket() -> Optional[str]:
    """Find the valid Docker UNIX socket path across container and macOS environments."""
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

    def request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
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

    def list_directory_hunters(self) -> Dict[int, Dict[str, Any]]:
        """Returns map of instance_id -> {name, state, id}."""
        status, containers = self.request("GET", "/v1.41/containers/json?all=1")
        if status != 200 or not isinstance(containers, list):
            return {}

        results = {}
        for c in containers:
            for name in c.get("Names", []):
                clean_name = name.lstrip("/")
                if clean_name.startswith("directory-hunter-"):
                    suffix = clean_name.replace("directory-hunter-", "")
                    if suffix.isdigit():
                        iid = int(suffix)
                        results[iid] = {
                            "id": c.get("Id"),
                            "name": clean_name,
                            "state": c.get("State", ""),
                            "status": c.get("Status", "")
                        }
        return results

    def start_container(self, name_or_id: str) -> bool:
        status, _ = self.request("POST", f"/v1.41/containers/{name_or_id}/start")
        return status in [204, 304]

    def stop_container(self, name_or_id: str, timeout: int = 5) -> bool:
        status, _ = self.request("POST", f"/v1.41/containers/{name_or_id}/stop?t={timeout}")
        return status in [204, 304]

    def inspect_container(self, name_or_id: str) -> Optional[dict]:
        status, data = self.request("GET", f"/v1.41/containers/{name_or_id}/json")
        return data if status == 200 and isinstance(data, dict) else None

    def create_directory_hunter(self, instance_id: int, template_id: int = 1) -> bool:
        """Create a new directory-hunter container cloning the config of an existing one."""
        tpl_name = f"directory-hunter-{template_id}"
        tpl = self.inspect_container(tpl_name)
        
        cfg = tpl.get("Config", {}) if tpl else {}
        host_cfg = tpl.get("HostConfig", {}) if tpl else {}

        # Update environment with INSTANCE_ID
        existing_env = cfg.get("Env", [])
        new_env = [e for e in existing_env if not e.startswith("INSTANCE_ID=")]
        new_env.append(f"INSTANCE_ID={instance_id}")

        create_payload = {
            "Image": cfg.get("Image", "recon-dashboard:latest"),
            "Cmd": cfg.get("Cmd", ["python", "tools/directory_hunter.py"]),
            "Env": new_env,
            "HostConfig": {
                "Binds": host_cfg.get("Binds", [
                    "/app/app",
                    "/app/templates",
                    "/app/tools",
                    "/app/wordlists"
                ]),
                "NetworkMode": host_cfg.get("NetworkMode", "host"),
                "Memory": host_cfg.get("Memory", 1258291200), # 1200MB limit
                "NanoCpus": host_cfg.get("NanoCpus", 1000000000), # 1.0 CPU core
                "RestartPolicy": {"Name": "always"}
            }
        }

        name = f"directory-hunter-{instance_id}"
        status, resp = self.request("POST", f"/v1.41/containers/create?name={name}", create_payload)
        if status in [200, 201]:
            logger.info(f"[Autoscaler] Created container {name} successfully.")
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
        now = time.time()
        ram_percent = 0.0
        try:
            with open("/proc/meminfo", "r") as f:
                raw_mem = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        raw_mem[parts[0].strip()] = int(parts[1].split()[0])
            total = raw_mem.get("MemTotal", 1)
            avail = raw_mem.get("MemAvailable", raw_mem.get("MemFree", 0))
            ram_percent = round(((total - avail) / total) * 100.0, 1)
        except Exception:
            pass

        cpu_percent = 0.0
        try:
            with open("/proc/stat", "r") as f:
                fields = [float(x) for x in f.readline().split()[1:8]]
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0.0)
            total = sum(fields)

            if self._last_cpu and (now - self._last_time) < 15.0:
                d_idle = idle - self._last_cpu["idle"]
                d_total = total - self._last_cpu["total"]
                if d_total > 0:
                    cpu_percent = round((1.0 - (d_idle / d_total)) * 100.0, 1)
            else:
                time.sleep(0.08)
                with open("/proc/stat", "r") as f2:
                    fields2 = [float(x) for x in f2.readline().split()[1:8]]
                idle2 = fields2[3] + (fields2[4] if len(fields2) > 4 else 0.0)
                total2 = sum(fields2)
                d_idle = idle2 - idle
                d_total = total2 - total
                if d_total > 0:
                    cpu_percent = round((1.0 - (d_idle / d_total)) * 100.0, 1)

            self._last_cpu = {"idle": idle, "total": total}
            self._last_time = now
            cpu_percent = max(0.0, min(100.0, cpu_percent))
        except Exception:
            pass

        return {
            "ram_percent": ram_percent,
            "cpu_percent": cpu_percent,
            "peak_percent": max(ram_percent, cpu_percent)
        }


class DirectoryHunterAutoscaler:
    """
    Automated autoscaler for Directory & File Hunter instances.
    Maintains maximum parallelism by scaling up workers to consume pending tasks
    while strictly keeping total system resource utilization (CPU & RAM) below 80%.
    """
    def __init__(self, db_client: Optional[AsyncIOMotorClient] = None):
        self.client = db_client or AsyncIOMotorClient(MONGO_URI)
        self.db = self.client[DB_NAME]
        self.tasks_col = self.db["tasks"]
        self.settings_col = self.db["settings"]
        self.docker = DockerUnixClient()
        self.monitor = SystemResourceMonitor()

        # Constraints
        self.target_ceiling = 80.0       # Hard ceiling requested by user: strictly below 80%
        self.scale_up_threshold = 75.0   # Scale up threshold: only add workers when headroom is safely < 75%
        self.emergency_scale_down = 80.0 # Scale down immediately if >= 80%
        self.min_workers = 2             # Keep at least 2 baseline workers ready
        self.max_workers = 24            # Upper bound cap
        self.loop_interval = 7           # Seconds between autoscaling checks
        self.last_scale_action = 0.0
        self.cooldown_sec = 6.0          # Settling time after starting or stopping a worker

    async def evaluate_and_scale(self):
        """Evaluate task queue and system vitals, scaling directory-hunter workers dynamically."""
        now = time.time()
        vitals = self.monitor.sample_vitals()
        cpu_pct = vitals["cpu_percent"]
        ram_pct = vitals["ram_percent"]
        peak_pct = vitals["peak_percent"]

        # Check pending & processing directory_hunt tasks
        pending_dh = await self.tasks_col.count_documents({"task_type": "directory_hunt", "status": "pending"})
        processing_dh = await self.tasks_col.count_documents({"task_type": "directory_hunt", "status": "processing"})

        # Get existing directory-hunter containers
        containers = self.docker.list_directory_hunters()
        running_workers = [iid for iid, info in containers.items() if info["state"] == "running"]
        stopped_workers = [iid for iid, info in containers.items() if info["state"] != "running"]

        running_count = len(running_workers)

        logger.info(
            f"[DirectoryHunter Autoscaler] Vitals: CPU={cpu_pct}%, RAM={ram_pct}% (Peak={peak_pct}%, Limit={self.target_ceiling}%). "
            f"Workers running: {running_count}. Queue: {pending_dh} pending, {processing_dh} processing."
        )

        # Update Mongo status for Dashboard visibility
        await self.settings_col.update_one(
            {"key": "directory_hunter_autoscaler"},
            {"$set": {
                "running_workers": running_count,
                "pending_tasks": pending_dh,
                "processing_tasks": processing_dh,
                "cpu_percent": cpu_pct,
                "ram_percent": ram_pct,
                "target_ceiling": self.target_ceiling,
                "status": "active",
                "last_evaluated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }},
            upsert=True
        )

        # 1. EMERGENCY / OVER-CEILING PROTECTION: >= 80.0%
        if peak_pct >= self.emergency_scale_down:
            logger.warning(
                f"[DirectoryHunter Autoscaler] System resource ceiling exceeded (CPU: {cpu_pct}%, RAM: {ram_pct}% >= {self.emergency_scale_down}%). "
                f"Halting spawn."
            )
            if running_count > self.min_workers and (now - self.last_scale_action) >= self.cooldown_sec:
                # Stop highest-numbered running instance to relieve load back below 80%
                highest_id = max(running_workers)
                target_container = f"directory-hunter-{highest_id}"
                logger.warning(f"[DirectoryHunter Autoscaler] Relieving load: stopping {target_container} to bring usage below 80%.")
                stopped = self.docker.stop_container(target_container, timeout=5)
                if stopped:
                    self.last_scale_action = now
                    logger.info(f"[DirectoryHunter Autoscaler] Successfully stopped {target_container}.")
            return

        # 2. SCALE-UP: Pending tasks exist and system is safely below threshold (< 75%)
        if pending_dh > 0:
            if (now - self.last_scale_action) < self.cooldown_sec:
                logger.debug("[DirectoryHunter Autoscaler] In cooldown, waiting for previous scale action to settle.")
                return

            if peak_pct < self.scale_up_threshold and running_count < self.max_workers:
                # We don't need more workers than total tasks remaining
                total_work = pending_dh + processing_dh
                if running_count < total_work:
                    # Pick next worker to start
                    # First check if there are existing stopped workers
                    if stopped_workers:
                        next_id = min(stopped_workers)
                        target_name = f"directory-hunter-{next_id}"
                        logger.info(
                            f"[DirectoryHunter Autoscaler] Headroom available (CPU: {cpu_pct}%, RAM: {ram_pct}% < {self.scale_up_threshold}%). "
                            f"Starting existing {target_name}."
                        )
                        started = self.docker.start_container(target_name)
                        if started:
                            self.last_scale_action = now
                            logger.info(f"[DirectoryHunter Autoscaler] Started {target_name}. Now running: {running_count + 1} workers.")
                            return
                    else:
                        # No stopped worker available: spawn the next instance!
                        next_id = (max(containers.keys()) + 1) if containers else 1
                        target_name = f"directory-hunter-{next_id}"
                        logger.info(
                            f"[DirectoryHunter Autoscaler] Headroom available (CPU: {cpu_pct}%, RAM: {ram_pct}% < {self.scale_up_threshold}%). "
                            f"Creating and starting new {target_name}."
                        )
                        created = self.docker.create_directory_hunter(next_id)
                        if created:
                            started = self.docker.start_container(target_name)
                            if started:
                                self.last_scale_action = now
                                logger.info(f"[DirectoryHunter Autoscaler] Spawned and started {target_name}. Now running: {running_count + 1} workers.")
                                return

        # 3. IDLE SCALE-DOWN: Pending queue is empty, scale down excess workers back toward baseline
        needed_workers = max(self.min_workers, processing_dh)
        if pending_dh == 0 and running_count > needed_workers:
            if (now - self.last_scale_action) >= self.cooldown_sec:
                highest_id = max(running_workers)
                target_container = f"directory-hunter-{highest_id}"
                logger.info(
                    f"[DirectoryHunter Autoscaler] Scale-down: pending queue empty ({processing_dh} active). "
                    f"Stopping excess {target_container} back toward baseline ({needed_workers} workers)."
                )
                stopped = self.docker.stop_container(target_container, timeout=10)
                if stopped:
                    self.last_scale_action = now
                    logger.info(f"[DirectoryHunter Autoscaler] Stopped excess {target_container}.")

    async def run(self):
        """Continuous execution loop."""
        logger.info("[DirectoryHunter Autoscaler] Starting continuous automated autoscaling daemon...")
        while True:
            try:
                await self.evaluate_and_scale()
            except Exception as e:
                logger.error(f"[DirectoryHunter Autoscaler] Unexpected error: {e}", exc_info=True)
            await asyncio.sleep(self.loop_interval)

if __name__ == "__main__":
    autoscaler = DirectoryHunterAutoscaler()
    asyncio.run(autoscaler.run())
