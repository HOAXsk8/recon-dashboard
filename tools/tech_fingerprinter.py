import asyncio
import datetime
import logging
import json
import os
from base_agent import BaseAgent, logger

class TechFingerprinterAgent(BaseAgent):
    def __init__(self):
        super().__init__("tech_fingerprinter", "Technology Fingerprinter")

    async def run_httpx(self, url):
        logger.info(f"Running httpx fingerprinting on {url}")
        
        # Use httpx with tech detection and JSON output
        # -td: tech detect, -title: get page title, -server: get server header
        # -sc: status code, -sh: show headers (we'll parse them for security headers)
        cmd = [
            "httpx", "-u", url, "-td", "-title", "-server", "-sc", "-json", "-silent"
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=60)
            if stdout:
                return json.loads(stdout)
        except Exception as e:
            logger.error(f"httpx error for {url}: {e}")
        return None

    def extract_security_headers(self, raw_headers):
        """Parse raw headers from httpx output to find security headers."""
        headers = {}
        # httpx JSON output usually has a 'header' field which is a dict or string
        # If it's a string, we might need to parse it. Let's assume it's a dict for now based on standard httpx output.
        if not raw_headers:
            return headers

        # Common security headers to look for
        security_list = {
            "Strict-Transport-Security": "hsts",
            "Content-Security-Policy": "csp",
            "X-Frame-Options": "x_frame_options",
            "X-Content-Type-Options": "x_content_type_options",
            "X-XSS-Protection": "x_xss_protection",
            "Referrer-Policy": "referrer_policy"
        }

        # Normalize keys to lowercase for matching
        normalized_headers = {k.lower(): v for k, v in raw_headers.items()}
        
        for h_name, key in security_list.items():
            val = normalized_headers.get(h_name.lower())
            if val:
                headers[key] = val
            else:
                headers[key] = None # Explicitly mark as missing
        
        return headers

    async def create_tech_alert(self, root_domain, target, old_tech, new_tech, url):
        """Create a lead/alert for a changed technology stack using the centralized alerting system."""
        added = set(new_tech) - set(old_tech)
        removed = set(old_tech) - set(new_tech)
        
        if not added and not removed:
            return

        title = f"Tech Stack Change: {target}"
        
        changes = []
        if added:
            changes.append(f"Added: {', '.join(added)}")
        if removed:
            changes.append(f"Removed: {', '.join(removed)}")
        
        description = " | ".join(changes)
        details = f"A change in the technology stack was detected for {url}.\n\nPrevious stack: {', '.join(old_tech) or 'None'}\nNew stack: {', '.join(new_tech) or 'None'}"
        exploitation = f"### Tech Stack Analysis\n\n1. **Review Changes**: Analyze why these technologies were added or removed. New technologies might introduce new attack surfaces.\n2. **Version Check**: Check if the newly added technologies have known vulnerabilities (CVEs).\n3. **Consistency**: Ensure these changes align with known infrastructure updates."

        await self.create_alert(title, description, target, "medium", details, exploitation)

    async def create_header_alert(self, target, old_headers, new_headers, url):
        """Create a lead/alert for degraded security headers using the centralized alerting system."""
        regressions = []
        for key, name in [
            ("hsts", "Strict-Transport-Security"),
            ("csp", "Content-Security-Policy"),
            ("x_frame_options", "X-Frame-Options")
        ]:
            if old_headers.get(key) and not new_headers.get(key):
                regressions.append(name)
        
        if not regressions:
            return

        title = f"Security Header Regression: {target}"
        description = f"Removed: {', '.join(regressions)}"
        details = f"One or more security headers were removed from {url}.\n\nRegressions: {', '.join(regressions)}"
        exploitation = f"### Header Analysis\n\n1. **Check Config**: Verify if a recent server configuration change accidentally removed these headers.\n2. **Security Impact**: Removing {regressions} increases susceptibility to attacks like Clickjacking or XSS."

        await self.create_alert(title, description, target, "high", details, exploitation)

    async def process_tasks(self):
        task = await self.tasks_col.find_one_and_update(
            {"task_type": "tech_fingerprint", "status": "pending"},
            {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}},
            sort=[("created_at", 1)]
        )

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        protocol = task.get("protocol", "http")
        port = task.get("port", 80)
        
        # Build URL
        if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
            url = f"{protocol}://{target}"
        else:
            url = f"{protocol}://{target}:{port}"

        try:
            data = await self.run_httpx(url)
            
            if data:
                tech_stack = data.get("tech", [])
                if data.get("server"):
                    tech_stack.append(data["server"])
                
                # Deduplicate and clean
                tech_stack = list(set([t.strip() for t in tech_stack if t.strip()]))
                
                # Extract security headers
                raw_headers = data.get("headers", {})
                security_headers = self.extract_security_headers(raw_headers)
                
                # Update web_applications in the domains collection
                domain_doc = await self.domains_col.find_one({"domain": root_domain})
                if domain_doc:
                    web_apps = domain_doc.get("web_applications", [])
                    app_found = False
                    for app in web_apps:
                        if app.get("target") == target:
                            # Check for tech stack changes
                            old_tech = app.get("tech_stack", [])
                            tech_changed = set(old_tech) != set(tech_stack)
                            
                            if tech_changed:
                                await self.create_tech_alert(root_domain, target, old_tech, tech_stack, url)
                                
                                # Force a re-run of directory hunt because the web app changed
                                await self.tasks_col.delete_many({
                                    "root_domain": root_domain,
                                    "target": target,
                                    "port": port,
                                    "task_type": "directory_hunt"
                                })
                                await self.tasks_col.insert_one({
                                    "root_domain": root_domain,
                                    "target": target,
                                    "protocol": protocol,
                                    "port": port,
                                    "task_type": "directory_hunt",
                                    "status": "pending",
                                    "created_at": datetime.datetime.utcnow()
                                })
                                logger.info(f"Forced NEW directory hunt for {target}:{port} due to tech stack change.")
                            
                            # Check for header regressions
                            old_headers = app.get("security_headers", {})
                            await self.create_header_alert(target, old_headers, security_headers, url)

                            app["tech_stack"] = tech_stack
                            app["security_headers"] = security_headers
                            app["title"] = data.get("title", "")
                            app_found = True
                            break
                    
                    if not app_found:
                        # New application discovery - also generate an alert if tech is found
                        if tech_stack:
                            await self.create_tech_alert(root_domain, target, [], tech_stack, url)
                            
                        web_apps.append({
                            "target": target,
                            "url": url,
                            "tech_stack": tech_stack,
                            "security_headers": security_headers,
                            "title": data.get("title", ""),
                            "sensitive_files": []
                        })
                    
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$set": {"web_applications": web_apps}}
                    )
                    logger.info(f"Updated tech stack for {url}: {tech_stack}")
            
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )

        except Exception as e:
            logger.error(f"Error in tech fingerprint for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = TechFingerprinterAgent()
    asyncio.run(agent.main_loop())
