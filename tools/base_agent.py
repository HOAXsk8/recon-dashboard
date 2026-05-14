import asyncio
import os
import datetime
import logging
import urllib.parse
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
        self.pause_event = asyncio.Event()
        self.pause_event.set() # Default to running

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
                if scanner and scanner.get("status") == "Stopped":
                    if self.pause_event.is_set():
                        logger.info(f"{self.agent_name} PAUSED via UI.")
                        self.pause_event.clear()
                else:
                    if not self.pause_event.is_set():
                        logger.info(f"{self.agent_name} RESUMED via UI.")
                        self.pause_event.set()

            except Exception as e:
                logger.error(f"Heartbeat update failed: {e}")
            await asyncio.sleep(10)

    async def run_command(self, cmd):
        """Helper to run shell commands asynchronously."""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return stdout.decode().strip(), stderr.decode().strip()

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
