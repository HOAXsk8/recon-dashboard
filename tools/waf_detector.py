import asyncio
import datetime
import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger


class WafDetectorAgent(BaseAgent):
    def __init__(self):
        super().__init__("waf_detector", "WAF Detector")

    async def run_wafw00f(self, url):
        """Run wafw00f against a URL and return parsed JSON results."""
        logger.info(f"Running wafw00f on {url}")
        safe_name = url.replace("://", "_").replace("/", "_").replace(".", "_")
        tmp_output = f"/tmp/wafw00f_{safe_name}.json"
        cmd = ["wafw00f", "-a", "-o", tmp_output, "-f", "json", url]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=120)
            if stderr:
                logger.debug(f"[wafw00f stderr] {stderr}")
            if os.path.exists(tmp_output):
                with open(tmp_output, "r") as f:
                    data = json.load(f)
                os.remove(tmp_output)
                return data
        except Exception as e:
            logger.error(f"wafw00f error for {url}: {e}")
        return None

    def parse_wafw00f_result(self, data):
        """
        Parse wafw00f JSON output into a normalised result dict.

        wafw00f JSON output:
        [{"url": "...", "detected": [{"firewall": "Cloudflare", "manufacturer": "..."}], "generic": false}]
        """
        result = {
            "detected": False,
            "firewall": None,
            "manufacturer": None,
            "mode": None,
            "confidence": None,
            "generic": False,
            "scanned_at": datetime.datetime.utcnow().isoformat()
        }
        if not data or not isinstance(data, list):
            return result

        entry = data[0] if data else {}
        detections = entry.get("detected", [])
        result["generic"] = entry.get("generic", False)

        if detections:
            result["detected"] = True
            first = detections[0]
            result["firewall"] = first.get("firewall")
            result["manufacturer"] = first.get("manufacturer")
            result["confidence"] = "high" if len(detections) == 1 else "medium"
            if result["generic"] and not result["firewall"]:
                result["firewall"] = "Generic WAF"
                result["confidence"] = "low"

        return result

    async def process_tasks(self):
        task = await self.get_next_task("waf_detect")
        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]

        try:
            raw = None
            for scheme in ["https", "http"]:
                url = f"{scheme}://{target}"
                raw = await self.run_wafw00f(url)
                if raw is not None:
                    break

            waf_result = self.parse_wafw00f_result(raw)

            # Change detection
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            old_waf = domain_doc.get("infrastructure", {}).get("waf", {}) if domain_doc else {}
            old_firewall = old_waf.get("firewall")
            new_firewall = waf_result.get("firewall")

            if old_waf and old_firewall != new_firewall:
                if new_firewall and not old_firewall:
                    title = f"WAF Newly Detected: {target}"
                    description = f"A Web Application Firewall ({new_firewall}) was detected on {target} where none existed before."
                    risk = "medium"
                elif not new_firewall and old_firewall:
                    title = f"WAF Removed: {target}"
                    description = f"The WAF ({old_firewall}) previously detected on {target} is no longer present."
                    risk = "high"
                else:
                    title = f"WAF Changed: {target}"
                    description = f"WAF changed from {old_firewall} to {new_firewall} on {target}."
                    risk = "medium"

                details = (
                    f"WAF detection result for {target}:\n"
                    f"- Previous: {old_firewall or 'None'}\n"
                    f"- Current: {new_firewall or 'None'}\n"
                    f"- Manufacturer: {waf_result.get('manufacturer') or 'Unknown'}\n"
                    f"- Confidence: {waf_result.get('confidence') or 'N/A'}"
                )
                exploitation = (
                    "### WAF Change Analysis\n\n"
                    "1. **Verify Legitimacy**: Confirm this WAF change was intentional and authorised.\n"
                    "2. **Coverage Gap**: If a WAF was removed, assess the increased exposure of web applications.\n"
                    "3. **Bypass Research**: A WAF change may introduce new bypass opportunities or close existing ones."
                )
                await self.create_alert(title, description, target, risk, details, exploitation)

            await self.domains_col.update_one(
                {"domain": root_domain},
                {"$set": {"infrastructure.waf": waf_result}}
            )
            logger.info(f"WAF scan complete for {target}: detected={waf_result['detected']}, firewall={waf_result['firewall']}")

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"WAF detection error for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )


if __name__ == "__main__":
    agent = WafDetectorAgent()
    asyncio.run(agent.main_loop())
