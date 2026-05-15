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
    def __init__(self, agent_key, agent_name):
        self.agent_key = agent_key
        self.agent_name = agent_name
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

    async def check_global_pause(self):
        """Check if scanning is globally paused."""
        try:
            settings = await self.settings_col.find_one({"key": "global_settings"})
            if settings and settings.get("scan_pause", False):
                return True
        except Exception as e:
            logger.error(f"Error checking global pause: {e}")
        return False

    async def create_alert(self, title, description, target, risk_level, details, exploitation_suggestions):
        """
        Create a new alert (lead) with fingerprint-based deduplication.
        Prevents repeats even if the user deletes the lead.
        """
        # Create a unique fingerprint based on target and title
        # Description might change slightly (e.g. timestamp or count), so we use title + target
        fingerprint_input = f"{target}|{title}"
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
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "details": details,
            "exploitation_suggestions": exploitation_suggestions,
            "fingerprint": fingerprint,
            "acknowledged": False
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
                    "type": "script",
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
                            "last_heartbeat": datetime.datetime.utcnow(),
                            "pid": os.getpid()
                        }
                    }
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
