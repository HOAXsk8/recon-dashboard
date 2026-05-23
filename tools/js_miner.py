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
        super().__init__("js_miner", "Javascript Source Miner", type="script")
        # High-confidence regex for common API keys/secrets/tokens
        self.secret_patterns = {
            "Google API Key": re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b'),
            "AWS Access Key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
            "AWS Secret Key": re.compile(r'[^A-Za-z0-9/+=]([A-Za-z0-9/+=]{40})[^A-Za-z0-9/+=]'),
            "JWT Token": re.compile(r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b'),
            "Bearer Token": re.compile(r'\bBearer\s+[A-Za-z0-9-._~+/]+=*\b'),
            "Stripe Key": re.compile(r'\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b'),
            "Firebase Key": re.compile(r'\b[a-zA-Z0-9]{40}:APA91b[a-zA-Z0-9-_]{134}\b'),
            "Slack Token": re.compile(r'\bxox[baprs]-[0-9a-zA-Z]{10,48}\b'),
            "GitHub Token": re.compile(r'\bgh[opsu]_[0-9a-zA-Z]{36}\b'),
            "SSH Private Key": re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
            "Slack Webhook": re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'),
            "Generic High-Entropy": re.compile(r'(?i)(?:key|secret|token|auth|password|passwd)[\s:="\' ]+([a-zA-Z0-9_-]{40,})'),
        }
        # Noise filter for common library/framework strings
        self.noise_blacklist = {
            "__vlist", "callback", "undefined", "function", "true", "false", "Object", "Array", "String",
            "prototype", "webpack", "module", "exports", "default", "window", "document", "script",
            "single", "values", "pushState", "onCompositionStart", "Bearer", "Unknown", "Unknown WAF",
            "callback for watcher", "sub_component_", "KeyObject"
        }
        # Robust regex for absolute URLs
        self.abs_url_regex = re.compile(r'https?://[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)')
        # Robust regex for relative paths (looking for paths starting with /, ./, or ../)
        self.rel_path_regex = re.compile(r'(?:"|\')((?:/|\.\./|\./)[a-zA-Z0-9_\-\./]+(?:\?[^\s"\'<>]+)?)(?:"|\')')
        
        self.garbage_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.ttf', '.ico', '.pdf', '.zip', '.gz', '.tar']

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

    def mine_content(self, content, source_url):
        """Extract secrets and URLs from content."""
        findings_secrets = []
        findings_urls = []
        
        # Extract Secrets
        for type_name, pattern in self.secret_patterns.items():
            matches = pattern.findall(content)
            for m in set(matches):
                if isinstance(m, tuple): m = m[0]
                
                # Apply noise filter
                if m in self.noise_blacklist or len(m) < 8:
                    continue
                
                # Check for common non-secret artifacts
                if any(noise in m for noise in ["{", "}", "[", "]", "(", ")", ";"]):
                    continue

                findings_secrets.append({"type": type_name, "value": m})
        
        # Extract URLs
        all_found_urls = set(self.abs_url_regex.findall(content))
        for rel_match in self.rel_path_regex.finditer(content):
            all_found_urls.add(rel_match.group(1))
            
        for u in all_found_urls:
            # Resolve relative URLs
            if not u.startswith(('http://', 'https://', '//')):
                import urllib.parse
                full_url = urllib.parse.urljoin(source_url, u)
            else:
                full_url = u if not u.startswith('//') else f"https:{u}"
            
            # Skip garbage
            if any(full_url.lower().endswith(ext) or f"{ext}?" in full_url.lower() for ext in self.garbage_extensions):
                continue
            
            findings_urls.append(full_url)
            
        return list({s["value"]: s for s in findings_secrets}.values()), list(set(findings_urls))

    async def create_js_alert(self, root_domain, target, finding_type, finding_value, source_url):
        """Create a lead/alert for a JS finding using the centralized alerting system."""
        if finding_type == "url":
            title = f"JS Discovery: Hidden URL"
            risk = "low"
            # Truncate long URLs in description
            desc_val = finding_value if len(finding_value) < 100 else finding_value[:97] + "..."
            description = f"Discovered hidden URL: {desc_val}"
        else:
            title = f"JS Discovery: Potential Secret"
            risk = "high"
            description = f"Discovered potential secret/key: {finding_value[:15]}..."

        details = f"A finding was discovered in a Javascript file at {source_url}.\n\nType: {finding_type}\nValue: {finding_value}"
        exploitation = f"### JS Mining Analysis\n\n1. **Verify Finding**: Check the source file at {source_url} to confirm the context of the finding.\n2. **Impact Assessment**: Determine if the secret is valid or if the hidden URL points to internal/unprotected endpoints.\n3. **Remediation**: Remove hardcoded secrets and ensure hidden URLs are properly protected."

        await self.create_alert(title, description, target, risk, details, exploitation)

    async def scrape_js_links(self, html_content, base_url):
        """Extract JS links from HTML content."""
        # Match <script src="...">
        src_regex = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        links = src_regex.findall(html_content)
        
        js_links = []
        for link in links:
            # Handle relative vs absolute URLs
            if link.startswith("http://") or link.startswith("https://"):
                js_links.append(link)
            elif link.startswith("//"):
                js_links.append(f"https:{link}")
            elif link.startswith("/"):
                js_links.append(f"{base_url.rstrip('/')}/{link.lstrip('/')}")
            else:
                js_links.append(f"{base_url.rstrip('/')}/{link}")
        
        return list(set(js_links))

    async def validate_url(self, client, url):
        """Check if a URL is alive (not 404)."""
        try:
            # We use GET with a short timeout. 
            # We consider it "valid" if it doesn't return a 404.
            # (e.g., 200, 403, 500 are all potentially interesting endpoints)
            resp = await client.get(url, timeout=5.0, follow_redirects=True)
            return resp.status_code != 404
        except Exception:
            # If it's a connection error or timeout, we might still want it if it was in JS?
            # But the user specifically asked to check if it exists. 
            # Let's assume connection errors = invalid for now to keep the dashboard clean.
            return False

    async def process_tasks(self):
        # 1. Handle JS Scraping (finding links in HTML)
        scrape_task = await self.tasks_col.find_one_and_update(
            {"task_type": "js_scrape", "status": "pending"},
            {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}},
            sort=[("created_at", 1)]
        )

        if scrape_task:
            target = scrape_task["target"]
            root_domain = scrape_task["root_domain"]
            url = scrape_task["url"]
            
            try:
                async with httpx.AsyncClient(verify=False, timeout=30.0, follow_redirects=True) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        js_links = await self.scrape_js_links(resp.text, url)
                        for link in js_links:
                            # Create js_mine task for each found JS file
                            # Extract path and base_url from the link
                            if "://" in link:
                                parts = link.split("://", 1)
                                proto = parts[0]
                                rest = parts[1].split("/", 1)
                                link_host = rest[0]
                                link_path = rest[1] if len(rest) > 1 else ""
                                link_base = f"{proto}://{link_host}"
                            else:
                                # Fallback (shouldn't happen with scrape_js_links logic)
                                link_base = url
                                link_path = link

                            # Only process if it's on the same domain or a subdomain
                            # (Avoid scraping external JS like Google Analytics etc. unless specifically wanted)
                            if root_domain in link:
                                exists = await self.tasks_col.find_one({
                                    "root_domain": root_domain,
                                    "target": target,
                                    "path": link_path,
                                    "task_type": "js_mine"
                                })
                                if not exists:
                                    await self.tasks_col.insert_one({
                                        "root_domain": root_domain,
                                        "target": target,
                                        "path": link_path,
                                        "base_url": link_base,
                                        "task_type": "js_mine",
                                        "status": "pending",
                                        "created_at": datetime.datetime.utcnow()
                                    })
                                    logger.info(f"Queued JS MINE for {link}")

                await self.tasks_col.update_one(
                    {"_id": scrape_task["_id"]},
                    {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
                )
                await self.check_completion(root_domain)
            except Exception as e:
                logger.error(f"Error scraping JS links from {url}: {e}")
                await self.tasks_col.update_one(
                    {"_id": scrape_task["_id"]},
                    {"$set": {"status": "failed", "error": str(e)}}
                )
            return # Process one task per loop

        # 2. Handle JS Mining (analyzing file content) - Original logic
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
                secrets, raw_urls = self.mine_content(content, full_url)
                
                # Validate URLs found in JS
                urls = []
                async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
                    # To avoid overwhelming, we could use a semaphore, but for small sets gather is fine.
                    # Limit concurrency to 5
                    sem = asyncio.Semaphore(5)
                    async def sem_validate(u):
                        async with sem:
                            return await self.validate_url(client, u)
                    
                    validation_tasks = [sem_validate(u) for u in raw_urls]
                    results = await asyncio.gather(*validation_tasks)
                    for u, is_valid in zip(raw_urls, results):
                        if is_valid:
                            urls.append(u)
                
                # Create alerts
                for s in secrets:
                    await self.create_js_alert(root_domain, target, "secret", s["value"], full_url)
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
                                if s["value"] not in existing_findings:
                                    js_findings.append({
                                        "type": "secret", 
                                        "value": s["value"], 
                                        "secret_type": s["type"], 
                                        "source": full_url,
                                        "discovered_at": datetime.datetime.utcnow().isoformat()
                                    })
                            for u in urls:
                                if u not in existing_findings:
                                    js_findings.append({
                                        "type": "url", 
                                        "value": u, 
                                        "source": full_url,
                                        "discovered_at": datetime.datetime.utcnow().isoformat()
                                    })
                            
                            app["js_findings"] = js_findings
                            break
                    
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$set": {"web_applications": web_apps}}
                    )
                    logger.info(f"Mined JS {full_url}: {len(secrets)} secrets, {len(urls)} validated URLs (from {len(raw_urls)} raw).")
            
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

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
