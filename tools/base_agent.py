import asyncio
import os
import datetime
import logging
import urllib.parse
import hashlib
from motor.motor_asyncio import AsyncIOMotorClient

# --- Configuration ---
MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD")
if not MONGO_ROOT_PASSWORD:
    raise RuntimeError("MONGO_ROOT_PASSWORD environment variable is not set")
PASSWORD = urllib.parse.quote_plus(MONGO_ROOT_PASSWORD)
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"
DB_NAME = "recon_db"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BaseAgent:
    def __init__(self, agent_key, agent_name, type="script"):
        self.agent_key = agent_key
        self.agent_name = agent_name
        self.type = type
        self.client = AsyncIOMotorClient(MONGO_URI)
        self.db = self.client[DB_NAME]
        self.domains_col = self.db["domains"]
        self.scanners_col = self.db["scanners"]
        self.tasks_col = self.db["tasks"]
        self.leads_col = self.db["leads"]
        self.fingerprints_col = self.db["alert_fingerprints"]
        self.settings_col = self.db["settings"]
        self.pause_event = asyncio.Event()
        self.pause_event.set() # Default to running

    @staticmethod
    def is_in_scope(target: str, root_domain: str, single_domain_only: bool = False) -> bool:
        """
        Validate that target is strictly within the scope of root_domain.
        If single_domain_only is True, target must strictly equal root_domain.
        Otherwise, target must be root_domain itself or a subdomain (*.root_domain).
        Strips protocols, credentials, ports, and paths if present.
        """
        if not target or not root_domain:
            return False
        
        target = str(target).strip().lower()
        root_domain = str(root_domain).strip().lower().rstrip(".")
        
        # Handle URLs
        if "://" in target:
            try:
                parsed = urllib.parse.urlparse(target)
                target = parsed.hostname or target
            except Exception:
                pass
        
        # Strip path or query if remaining
        if "/" in target:
            target = target.split("/")[0]
        if "?" in target:
            target = target.split("?")[0]
        
        # Strip port if present (e.g. host:8080)
        if ":" in target:
            target = target.split(":")[0]
            
        target = target.strip().rstrip(".")
        
        if single_domain_only:
            return target == root_domain

        # Exact match or subdomain
        return target == root_domain or target.endswith(f".{root_domain}")

    async def is_domain_active(self, root_domain: str) -> bool:
        """Check if root_domain exists in domains_col and is not blacklisted or on hold."""
        if not root_domain:
            return False
        root_domain = str(root_domain).strip().lower()
        doc = await self.domains_col.find_one({
            "domain": root_domain,
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        })
        return doc is not None

    async def get_next_task(self, task_type: str):
        """
        Fetch the next valid, in-scope pending task for task_type.
        Automatically discards and cancels tasks for deleted/inactive domains
        or out-of-scope targets.
        """
        while True:
            task = await self.tasks_col.find_one_and_update(
                {"task_type": task_type, "status": "pending"},
                {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}},
                sort=[("priority", -1), ("created_at", 1)]
            )
            if not task:
                return None

            root_domain = task.get("root_domain")
            target = task.get("target")

            # 1. Check if the root domain is currently active in the workspace
            domain_doc = await self.domains_col.find_one({
                "domain": root_domain,
                "blacklisted": {"$ne": True},
                "on_hold": {"$ne": True}
            })
            if not domain_doc:
                logger.warning(f"[{self.agent_name}] Discarding task {task.get('_id')} for inactive/deleted domain: {root_domain}")
                await self.tasks_col.delete_many({
                    "root_domain": root_domain,
                    "status": "pending"
                })
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "cancelled", "error": "Root domain not active or out of scope", "completed_at": datetime.datetime.utcnow()}}
                )
                continue

            is_single = domain_doc.get("single_domain_only", False)

            # 2. If domain is single_domain_only, discard any discovery tasks
            if is_single and task_type == "discovery":
                logger.info(f"[{self.agent_name}] Cancelling discovery task {task.get('_id')} because {root_domain} is a single target.")
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "cancelled", "error": "Single target domain", "completed_at": datetime.datetime.utcnow()}}
                )
                continue

            # 3. Check if the target is within the scope of root_domain
            if target and not self.is_in_scope(target, root_domain, single_domain_only=is_single):
                logger.warning(f"[{self.agent_name}] Discarding task {task.get('_id')} with out-of-scope target: {target} (Root: {root_domain}, Single: {is_single})")
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "cancelled", "error": f"Target {target} out of scope for {root_domain}", "completed_at": datetime.datetime.utcnow()}}
                )
                continue

            return task

    async def check_global_pause(self):
        """Check if scanning is globally paused."""
        try:
            settings = await self.settings_col.find_one({"key": "global_settings"})
            if settings and settings.get("scan_pause", False):
                return True
        except Exception as e:
            logger.error(f"Error checking global pause: {e}")
        return False

    async def create_alert(self, title, description, target, risk_level, details, exploitation_suggestions, response_size=None, extra_key=None):
        """
        Create a new alert (lead) with fingerprint-based deduplication.
        Prevents repeats even if the user deletes the lead.
        """
        # Create a unique fingerprint based on target, title, and optional extra_key (e.g. source map URL or secret)
        fingerprint_input = f"{target}|{title}|{extra_key}" if extra_key else f"{target}|{title}"
        fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()

        # 1. Check if this fingerprint is explicitly suppressed
        suppressed = await self.fingerprints_col.find_one({"fingerprint": fingerprint, "status": "suppressed"})
        if suppressed:
            logger.info(f"Skipping suppressed alert: {title} on {target}")
            return False

        # 2. Check if a lead with this fingerprint already exists
        existing_lead = await self.leads_col.find_one({"fingerprint": fingerprint})
        if existing_lead:
            # If it exists, we don't create a new one. 
            # We could update the timestamp, but let's stick to "tuning out repeats".
            return False

        # 3. Create the new lead
        lead_doc = {
            "title": title,
            "description": description,
            "target": target,
            "risk_level": risk_level,
            "status": "new",
            "source": self.agent_name,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "details": details,
            "exploitation_suggestions": exploitation_suggestions,
            "fingerprint": fingerprint,
            "acknowledged": False,
            "response_size": int(response_size) if response_size is not None else 0
        }
        
        await self.leads_col.insert_one(lead_doc)
        
        # 4. Save/Update the fingerprint record
        await self.fingerprints_col.update_one(
            {"fingerprint": fingerprint},
            {
                "$set": {
                    "target": target,
                    "title": title,
                    "last_seen": datetime.datetime.utcnow(),
                    "status": "active"
                }
            },
            upsert=True
        )
        
        logger.info(f"Created NEW ALERT: {title} on {target}")
        return True

    async def update_heartbeat(self):
        """Update agent status and check for pause/resume commands."""
        await self.scanners_col.update_one(
            {"key": self.agent_key},
            {
                "$set": {
                    "name": self.agent_name,
                    "type": self.type,
                    "status": "Running",
                    "last_heartbeat": datetime.datetime.utcnow(),
                    "pid": os.getpid()
                }
            },
            upsert=True
        )

        while True:
            try:
                await self.scanners_col.update_one(
                    {"key": self.agent_key},
                    {
                        "$set": {
                            "name": self.agent_name,
                            "type": self.type,
                            "status": "Running",
                            "last_heartbeat": datetime.datetime.utcnow(),
                            "pid": os.getpid()
                        }
                    },
                    upsert=True
                )

                scanner = await self.scanners_col.find_one({"key": self.agent_key})
                global_paused = await self.check_global_pause()
                
                if global_paused:
                    if self.pause_event.is_set():
                        logger.info(f"{self.agent_name} PAUSED (Global Pause Active).")
                        self.pause_event.clear()
                    # Optionally update status in scanners_col to reflect global pause
                    await self.scanners_col.update_one(
                        {"key": self.agent_key},
                        {"$set": {"status": "Paused (Global)"}}
                    )
                elif scanner and scanner.get("status") == "Stopped":
                    if self.pause_event.is_set():
                        logger.info(f"{self.agent_name} PAUSED via UI.")
                        self.pause_event.clear()
                else:
                    if not self.pause_event.is_set():
                        logger.info(f"{self.agent_name} RESUMED.")
                        self.pause_event.set()
                    # Ensure status is Running if it was previously Paused (Global)
                    if scanner and scanner.get("status") == "Paused (Global)":
                        await self.scanners_col.update_one(
                            {"key": self.agent_key},
                            {"$set": {"status": "Running"}}
                        )

            except Exception as e:
                logger.error(f"Heartbeat update failed: {e}")
            await asyncio.sleep(10)

    async def check_completion(self, root_domain):
        """Check if all tasks for this root domain are completed."""
        pending = await self.tasks_col.count_documents({
            "root_domain": root_domain,
            "status": {"$in": ["pending", "processing"]}
        })
        if pending == 0:
            await self.domains_col.update_one(
                {"domain": root_domain},
                {"$set": {"scanned": True, "last_scanned": datetime.datetime.utcnow().isoformat()}}
            )
            logger.info(f"Root domain {root_domain} fully scanned.")

    async def run_command(self, cmd, timeout=300):
        """Helper to run shell commands asynchronously with a timeout."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return stdout.decode().strip(), stderr.decode().strip()
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError(f"Command '{' '.join(cmd)}' timed out after {timeout} seconds")
        except Exception as e:
            raise RuntimeError(f"Error running command '{' '.join(cmd)}': {e}")

    async def reverse_dns_lookup(self, ip: str, timeout: int = 5) -> list:
        """
        Perform a reverse DNS lookup using `dig -x <ip> +short`.
        Falls back to public DNS (@8.8.8.8) and dnspython if needed.
        Returns a list of FQDNs.
        """
        if not ip:
            return []
        ip = str(ip).strip()
        fqdns = []

        # 1. Try dig -x <ip> +short (system resolver)
        try:
            stdout, _ = await self.run_command(["dig", "-x", ip, "+short"], timeout=timeout)
            for line in stdout.splitlines():
                clean = line.strip().rstrip(".")
                if clean and not clean.startswith(";;") and clean not in fqdns:
                    fqdns.append(clean)
        except Exception:
            pass

        # 2. If empty, try dig -x <ip> @8.8.8.8 +short (public resolver)
        if not fqdns:
            try:
                stdout, _ = await self.run_command(["dig", "-x", ip, "@8.8.8.8", "+short"], timeout=timeout)
                for line in stdout.splitlines():
                    clean = line.strip().rstrip(".")
                    if clean and not clean.startswith(";;") and clean not in fqdns:
                        fqdns.append(clean)
            except Exception:
                pass

        # 3. If still empty and dnspython is installed, try dnspython
        if not fqdns:
            try:
                import dns.reversename
                import dns.asyncresolver
                rev_name = dns.reversename.from_address(ip)
                resolver = dns.asyncresolver.Resolver()
                resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
                resolver.timeout = timeout
                resolver.lifetime = timeout
                ans = await resolver.resolve(rev_name, "PTR")
                for rdata in ans:
                    clean = str(rdata).strip().rstrip(".")
                    if clean and clean not in fqdns:
                        fqdns.append(clean)
            except Exception:
                pass

        return fqdns

    async def main_loop(self):
        asyncio.create_task(self.update_heartbeat())
        while True:
            await self.pause_event.wait()
            try:
                await self.process_tasks()
            except Exception as e:
                logger.error(f"Main loop error: {e}")
            await asyncio.sleep(5)

    async def process_tasks(self):
        raise NotImplementedError("Subclasses must implement process_tasks")
