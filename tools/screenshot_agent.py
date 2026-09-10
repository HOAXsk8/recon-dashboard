import asyncio
import datetime
import hashlib
import logging
import os
import re
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger

class ScreenshotAgent(BaseAgent):
    def __init__(self):
        super().__init__("screenshot_agent", "Visual Web Screenshotting Agent")
        self.screenshots_dir = "/app/screenshots"
        os.makedirs(self.screenshots_dir, exist_ok=True)

    async def capture_screenshot(self, target, url):
        """Capture full-viewport screenshot of a web application using headless Chromium."""
        # Sanitize target for filename
        clean_target = re.sub(r'[^a-zA-Z0-9_.-]', '_', target)
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        filename = f"{clean_target}_{url_hash}.png"
        output_path = os.path.join(self.screenshots_dir, filename)

        cmd = [
            "chromium",
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--disable-software-rasterizer",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-default-apps",
            "--hide-scrollbars",
            "--window-size=1280,800",
            "--virtual-time-budget=3000",
            f"--screenshot={output_path}",
            url
        ]

        logger.info(f"Capturing visual screenshot for {url} -> {filename}")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
            
            # Check if screenshot was successfully created
            if os.path.exists(output_path) and os.path.getsize(output_path) > 1000:
                logger.info(f"Screenshot successfully captured for {target} ({os.path.getsize(output_path)} bytes)")
                return f"/screenshots/{filename}"
            else:
                logger.warning(f"Screenshot file not created or too small for {url}")
                return None
        except asyncio.TimeoutError:
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
            logger.warning(f"Screenshot timeout (20s) for {url}")
            return None
        except Exception as e:
            logger.error(f"Error capturing screenshot for {url}: {e}")
            return None

    async def process_domain_webapps(self, doc):
        domain = doc.get("domain")
        webapps = doc.get("web_applications", [])
        if not webapps:
            return

        for i, app in enumerate(webapps):
            # Skip if already captured
            if app.get("screenshot"):
                continue

            target = app.get("target") or domain
            url = app.get("url")
            if not url:
                continue

            screenshot_rel_path = await self.capture_screenshot(target, url)
            if screenshot_rel_path:
                await self.domains_col.update_one(
                    {"_id": doc["_id"], "web_applications.target": target},
                    {
                        "$set": {
                            "web_applications.$.screenshot": screenshot_rel_path,
                            "web_applications.$.screenshot_at": datetime.datetime.utcnow().isoformat()
                        }
                    }
                )
            else:
                # Mark attempted so we don't continuously hammer unreachable sites
                await self.domains_col.update_one(
                    {"_id": doc["_id"], "web_applications.target": target},
                    {
                        "$set": {
                            "web_applications.$.screenshot_failed": True,
                            "web_applications.$.screenshot_at": datetime.datetime.utcnow().isoformat()
                        }
                    }
                )

            # Polite gap between heavy headless browser launches
            await asyncio.sleep(2)

    async def process_tasks(self):
        # 1. Process tasks explicitly queued in tasks_col
        task = await self.get_next_task("screenshot")

        if task:
            root_domain = task["root_domain"]
            target = task.get("target", root_domain)
            doc = await self.domains_col.find_one({
                "domain": root_domain,
                "blacklisted": {"$ne": True},
                "on_hold": {"$ne": True}
            })
            if doc:
                await self.process_domain_webapps(doc)
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            return

        # 2. Automatically find any domain with pending screenshots
        doc = await self.domains_col.find_one({
            "web_applications": {
                "$elemMatch": {
                    "screenshot": {"$exists": False},
                    "screenshot_failed": {"$ne": True}
                }
            },
            "blacklisted": {"$ne": True}
        })

        if doc:
            await self.process_domain_webapps(doc)
        else:
            await asyncio.sleep(6)

if __name__ == "__main__":
    agent = ScreenshotAgent()
    asyncio.run(agent.main_loop())
