import asyncio
import datetime
import logging
import json
import os
import re
import httpx
from base_agent import BaseAgent, logger

class JavascriptMinerAgent(BaseAgent):
    def __init__(self):
        super().__init__("js_miner", "Javascript Source Miner")
        # Regex for secrets: matches common keywords followed by an assignment and a string
        self.secret_regex = re.compile(
            r'(?:user|pass|key|secret|token|api|auth|creds|aws|google|github|private|access)[^=]{0,20}=\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )
        # Regex for URLs
        self.url_regex = re.compile(r'https?://[^\s\'"]+')

    async def fetch_js_content(self, url):
        """Fetch JS content using httpx."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    return response.text
        except Exception as e:
            logger.error(f"Error fetching JS content from {url}: {e}")
        return None

    def mine_content(self, content):
        """Extract secrets and URLs from content."""
        secrets = self.secret_regex.findall(content)
        urls = self.url_regex.findall(content)
        
        # Deduplicate and clean
        unique_secrets = list(set([s.strip() for s in secrets if len(s.strip()) > 5]))
        unique_urls = list(set([u.strip() for u in urls]))
        
        return unique_secrets, unique_urls

    async def create_js_alert(self, root_domain, target, finding_type, finding_value, source_url):
        """Create a lead/alert for a JS finding using the centralized alerting system."""
        if finding_type == "url":
            title = f"JS Discovery: Hidden URL"
            risk = "low"
            description = f"Discovered hidden URL: {finding_value}"
        else:
            title = f"JS Discovery: Potential Secret"
            risk = "high"
            description = f"Discovered potential secret/key: {finding_value[:10]}..."

        details = f"A finding was discovered in a Javascript file at {source_url}.\n\nType: {finding_type}\nValue: {finding_value}"
        exploitation = f"### JS Mining Analysis\n\n1. **Verify Finding**: Check the source file at {source_url} to confirm the context of the finding.\n2. **Impact Assessment**: Determine if the secret is valid or if the hidden URL points to internal/unprotected endpoints.\n3. **Remediation**: Remove hardcoded secrets and ensure hidden URLs are properly protected."

        await self.create_alert(title, description, target, risk, details, exploitation)

    async def process_tasks(self):
        task = await self.tasks_col.find_one_and_update(
            {"task_type": "js_mine", "status": "pending"},
            {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}},
            sort=[("created_at", 1)]
        )

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        js_path = task["path"] # Path relative to the target's base URL
        base_url = task["base_url"]
        
        full_url = f"{base_url}/{js_path}".replace("//", "/").replace(":/", "://")

        try:
            content = await self.fetch_js_content(full_url)
            if content:
                secrets, urls = self.mine_content(content)
                
                # Create alerts
                for s in secrets:
                    await self.create_js_alert(root_domain, target, "secret", s, full_url)
                for u in urls:
                    await self.create_js_alert(root_domain, target, "url", u, full_url)
                
                # Update web_applications in the domains collection
                domain_doc = await self.domains_col.find_one({"domain": root_domain})
                if domain_doc:
                    web_apps = domain_doc.get("web_applications", [])
                    for app in web_apps:
                        if app.get("target") == target:
                            # Add findings to the app entry
                            js_findings = app.get("js_findings", [])
                            
                            # Deduplicate and add
                            existing_findings = {f["value"]: f["type"] for f in js_findings}
                            for s in secrets:
                                if s not in existing_findings:
                                    js_findings.append({"type": "secret", "value": s, "source": full_url})
                            for u in urls:
                                if u not in existing_findings:
                                    js_findings.append({"type": "url", "value": u, "source": full_url})
                            
                            app["js_findings"] = js_findings
                            break
                    
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$set": {"web_applications": web_apps}}
                    )
                    logger.info(f"Mined JS {full_url}: {len(secrets)} secrets, {len(urls)} URLs.")
            
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )

        except Exception as e:
            logger.error(f"Error in JS mining for {full_url}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    print("--- JS Miner Agent Starting ---")
    agent = JavascriptMinerAgent()
    asyncio.run(agent.main_loop())
