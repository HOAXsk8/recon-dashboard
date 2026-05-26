import asyncio
import datetime
import json
import logging
from base_agent import BaseAgent, logger

class NucleiScannerAgent(BaseAgent):
    def __init__(self):
        super().__init__("nuclei_scanner", "Nuclei Vulnerability Scanner")
        self.template_update_interval_days = 7

    async def check_for_template_updates(self):
        """Periodically check and update nuclei templates."""
        while True:
            try:
                settings = await self.settings_col.find_one({"key": "nuclei_settings"})
                last_update_str = settings.get("last_template_update") if settings else None
                
                should_update = False
                now = datetime.datetime.utcnow()
                
                if not last_update_str:
                    should_update = True
                else:
                    last_update = datetime.datetime.fromisoformat(last_update_str.replace("Z", "+00:00")).replace(tzinfo=None)
                    if (now - last_update).days >= self.template_update_interval_days:
                        should_update = True
                
                if should_update:
                    logger.info("Updating Nuclei templates (Weekly Automation)...")
                    # -up: update nuclei binary, -ut: update templates
                    stdout, stderr = await self.run_command(["nuclei", "-up", "-ut"], timeout=300)
                    logger.info(f"Nuclei update result: {stdout}")
                    
                    await self.settings_col.update_one(
                        {"key": "nuclei_settings"},
                        {"$set": {"last_template_update": now.isoformat()}},
                        upsert=True
                    )
            except Exception as e:
                logger.error(f"Error updating Nuclei templates: {e}")
            
            # Check every hour if it's time to update
            await asyncio.sleep(3600)

    async def run_nuclei(self, url, task_type="nuclei_scan"):
        logger.info(f"Running {task_type} on {url}")
        
        if task_type == "nuclei_oidc_scan":
            # Targeted deep scan for OIDC/OAuth misconfigurations and fuzzing
            # -tags oauth,oidc,auth,misconfiguration: focused on auth
            # -t http/fuzzing: enables parameter fuzzing for open redirects etc
            cmd = [
                "nuclei", "-u", url, "-j", "-silent", 
                "-tags", "oauth,oidc,auth,misconfiguration",
                "-t", "http/fuzzing"
            ]
        else:
            # Standard high-signal scan
            cmd = [
                "nuclei", "-u", url, "-j", "-silent", "-t", "http/cves,http/exposures,http/vulnerabilities"
            ]

        try:
            stdout, stderr = await self.run_command(cmd, timeout=1200) # Increased to 20 min for deep scans
            findings = []
            if stdout:
                for line in stdout.splitlines():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return findings
        except Exception as e:
            logger.error(f"Nuclei error ({task_type}) for {url}: {e}")
        return []

    def map_severity(self, nuclei_severity):
        """Map nuclei severity levels to dashboard risk levels."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "low"
        }
        return mapping.get(nuclei_severity.lower(), "low")

    async def process_tasks(self):
        task = await self.tasks_col.find_one_and_update(
            {"task_type": {"$in": ["nuclei_scan", "nuclei_oidc_scan"]}, "status": "pending"},
            {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}},
            sort=[("created_at", 1)]
        )

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        protocol = task.get("protocol", "http")
        port = task.get("port", 80)
        task_type = task["task_type"]
        
        # Build URL
        if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
            url = f"{protocol}://{target}"
        else:
            url = f"{protocol}://{target}:{port}"

        try:
            findings = await self.run_nuclei(url, task_type=task_type)
            
            for finding in findings:
                template_id = finding.get("template-id")
                info = finding.get("info", {})
                title = f"Nuclei: {info.get('name', template_id)}"
                severity = info.get("severity", "info")
                description = info.get("description", "No description provided.")
                remediation = info.get("remediation", "No remediation provided.")
                matched_at = finding.get("matched-at", "")
                
                # Risk mapping
                risk_level = self.map_severity(severity)
                
                # Format details
                details = f"**Nuclei Finding Details**\n\n"
                details += f"- **Template ID:** {template_id}\n"
                details += f"- **Severity:** {severity.upper()}\n"
                details += f"- **Description:** {description}\n"
                if finding.get("matcher-name"):
                    details += f"- **Matcher:** {finding.get('matcher-name')}\n"
                if matched_at:
                    details += f"- **Matched At:** {matched_at}\n"
                if finding.get("curl-command"):
                    details += f"\n**Reproduction:**\n```bash\n{finding.get('curl-command')}\n```"

                exploitation = f"### Remediation Guidance\n\n{remediation}\n\n"
                exploitation += "### Security Analysis\n\n1. **Verify Impact**: Confirm if the finding is a true positive by manually replicating the request.\n2. **Patch Management**: Apply necessary security updates for the affected software.\n3. **Configuration**: Review server configurations to mitigate further exposures."

                await self.create_alert(
                    title=title,
                    description=description[:200] + "..." if len(description) > 200 else description,
                    target=target,
                    risk_level=risk_level,
                    details=details,
                    exploitation_suggestions=exploitation
                )

                # TRIGGER SECONDARY OIDC SCAN IF DISCOVERY IS FOUND
                if task_type == "nuclei_scan":
                    if "openid-configuration" in template_id.lower() or "openid-configuration" in matched_at.lower():
                        # Check if we already have an OIDC scan pending/completed for this target
                        exists = await self.tasks_col.find_one({
                            "target": target,
                            "task_type": "nuclei_oidc_scan"
                        })
                        if not exists:
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "protocol": protocol,
                                "port": port,
                                "task_type": "nuclei_oidc_scan",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Auto-triggered DEEP OIDC scan for {target} after detection.")

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            logger.info(f"Completed {task_type} for {url}")

            # Check completion for root domain
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in Nuclei scan for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

    async def main_loop(self):
        # Start the background heartbeat and template update task
        asyncio.create_task(self.update_heartbeat())
        asyncio.create_task(self.check_for_template_updates())
        
        while True:
            await self.pause_event.wait()
            try:
                await self.process_tasks()
            except Exception as e:
                logger.error(f"Main loop error: {e}")
            await asyncio.sleep(5)

if __name__ == "__main__":
    agent = NucleiScannerAgent()
    asyncio.run(agent.main_loop())
