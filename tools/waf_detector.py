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
        [
          {"url": "https://...", "detected": true, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."},
          {"url": "https://...", "detected": true, "firewall": "Generic", "manufacturer": "Unknown"}
        ]
        """
        result = {
            "detected": False,
            "firewall": None,
            "manufacturer": None,
            "mode": None,
            "confidence": None,
            "generic": False,
            "all_detections": [],
            "scanned_at": datetime.datetime.utcnow().isoformat()
        }
        if not data or not isinstance(data, list):
            return result

        detected_entries = []
        has_generic = False

        for entry in data:
            if not isinstance(entry, dict):
                continue

            # Handle case where entry["detected"] is a list of dicts (legacy or wrapper format)
            raw_detected = entry.get("detected")
            if isinstance(raw_detected, list):
                for sub in raw_detected:
                    if isinstance(sub, dict) and sub.get("firewall") and str(sub.get("firewall")).lower() != "none":
                        if str(sub.get("firewall")).lower() == "generic":
                            has_generic = True
                        else:
                            detected_entries.append(sub)
                if entry.get("generic"):
                    has_generic = True
                continue

            # Standard wafw00f format: entry has "detected": bool, "firewall": str, "manufacturer": str
            if raw_detected is True:
                fw = entry.get("firewall")
                if fw and str(fw).lower() != "none":
                    if str(fw).lower() == "generic":
                        has_generic = True
                    else:
                        detected_entries.append(entry)

        result["generic"] = has_generic

        if detected_entries:
            result["detected"] = True
            first = detected_entries[0]
            result["firewall"] = first.get("firewall")
            result["manufacturer"] = first.get("manufacturer")
            result["confidence"] = "high" if len(detected_entries) == 1 else "medium"
            result["all_detections"] = [
                {"firewall": d.get("firewall"), "manufacturer": d.get("manufacturer")}
                for d in detected_entries
            ]
        elif has_generic:
            result["detected"] = True
            result["firewall"] = "Generic WAF"
            result["manufacturer"] = "Unknown"
            result["confidence"] = "low"
            result["all_detections"] = [{"firewall": "Generic WAF", "manufacturer": "Unknown"}]

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

            # If WAF is detected, perform reverse DNS lookup using `dig -x` to obtain device FQDNs
            waf_result["ips"] = []
            waf_result["reverse_dns"] = {}
            waf_result["fqdns"] = []

            if waf_result.get("detected"):
                try:
                    import socket
                    loop = asyncio.get_event_loop()
                    addr_info = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
                    resolved_ips = []
                    for item in addr_info:
                        ip = item[4][0]
                        if ip and not ip.startswith("127.") and ip not in resolved_ips:
                            resolved_ips.append(ip)
                    waf_result["ips"] = resolved_ips

                    for ip in resolved_ips:
                        try:
                            fqdns = await self.reverse_dns_lookup(ip)
                            if fqdns:
                                waf_result["reverse_dns"][ip] = fqdns
                                for f in fqdns:
                                    if f not in waf_result["fqdns"]:
                                        waf_result["fqdns"].append(f)
                        except Exception as rdns_err:
                            logger.debug(f"Reverse DNS error for WAF IP {ip}: {rdns_err}")
                except Exception as dns_err:
                    logger.debug(f"Error resolving IPs for WAF target {target}: {dns_err}")

            if target.strip().lower() == root_domain.strip().lower():
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {"infrastructure.waf": waf_result}}
                )
            else:
                await self.domains_col.update_one(
                    {"domain": root_domain, "infrastructure.subdomains.name": target},
                    {"$set": {"infrastructure.subdomains.$.waf": waf_result}}
                )
                await self.domains_col.update_one(
                    {"domain": root_domain, "web_applications.target": target},
                    {"$set": {"web_applications.$.waf": waf_result}}
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
