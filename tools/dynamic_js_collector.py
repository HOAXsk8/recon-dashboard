import asyncio
import datetime
import json
import os
import re
import sys
import urllib.parse
import httpx
from typing import Dict, List, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger
from playwright.async_api import async_playwright


class DynamicJsCollectorAgent(BaseAgent):
    """
    Dynamic JavaScript Collector & Extractor Agent.
    
    Navigates to live target web applications using headless Chromium, intercepts
    all runtime network requests for JavaScript files (including Webpack chunks and
    dynamically loaded modules), retrieves full script contents, and extracts:
      1. In-scope subdomains & cloud storage assets
      2. Hidden API routes & endpoints
      3. Sensitive secrets, tokens, and credentials
      4. Exposed Source Map files (.js.map)
    """

    def __init__(self):
        super().__init__("dynamic_js_collector", "Dynamic JS Recon & Extractor")
        
        # High-confidence regex for common credentials / tokens in JS
        self.secret_patterns = {
            "Google API Key": re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b'),
            "AWS Access Key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
            "AWS Secret Key": re.compile(r'[^A-Za-z0-9/+=]([A-Za-z0-9/+=]{40})[^A-Za-z0-9/+=]'),
            "JWT Token": re.compile(r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b'),
            "Bearer Token": re.compile(r'\bBearer\s+[A-Za-z0-9-._~+/]+=*\b'),
            "Stripe Key": re.compile(r'\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b'),
            "Firebase Key": re.compile(r'\b[a-zA-Z0-9]{40}:APA91b[a-zA-Z0-9-_]{134}\b'),
            "Slack Webhook": re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'),
            "GitHub Token": re.compile(r'\bgh[opsu]_[0-9a-zA-Z]{36}\b'),
            "SSH Private Key": re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
        }

        # Regex for Cloud and Storage Providers frequently found in JS
        self.cloud_regex = re.compile(
            r'[a-zA-Z0-9_\-\.]+\.(?:s3(?:[-.][a-z0-9-]+)?\.amazonaws\.com|blob\.core\.windows\.net|azureedge\.net|cloudfront\.net|storage\.googleapis\.com|firebaseio\.com)'
        )

        # Regex for API endpoints
        self.api_endpoint_regex = re.compile(
            r'(?:["\'`])((?:/api/|/v[0-9]+/|/graphql|/rest/|/auth/|/oauth/|/v[0-9]+\.[0-9]+/)[a-zA-Z0-9_\-\./?=&%#]+)(?:["\'`])'
        )

        # Source Map directive regex
        self.sourcemap_regex = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)')

    async def capture_via_crawler(self, url: str) -> Dict[str, str]:
        """
        Direct high-speed network crawler: fetches HTML with modern browser headers,
        extracts all external script sources, preloaded module scripts, and inline
        scripts, and recursively discovers dynamic JavaScript chunks.
        """
        captured: Dict[str, str] = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0, headers=headers) as client:
                res = await client.get(url)
                if res.status_code != 200 and res.status_code != 304:
                    return captured
                
                base_url = str(res.url)
                html = res.text
                
                # 1. Extract inline scripts
                inline_matches = re.findall(r'<script(?:\s+[^>]*)?>([\s\S]*?)</script>', html, re.IGNORECASE)
                for idx, code in enumerate(inline_matches):
                    code_clean = code.strip()
                    if len(code_clean) >= 25:
                        captured[f"{base_url}#inline-script-{idx+1}"] = code_clean

                # 2. Extract external script tags & modulepreloads
                script_urls = set()
                for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                    src = match.group(1).strip()
                    if src and not src.startswith("data:"):
                        script_urls.add(urllib.parse.urljoin(base_url, src))
                
                for match in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\'][^>]+(?:rel=["\'](?:modulepreload|preload)["\']|as=["\']script["\'])', html, re.IGNORECASE):
                    href = match.group(1).strip()
                    if href and not href.startswith("data:"):
                        script_urls.add(urllib.parse.urljoin(base_url, href))
                
                for match in re.finditer(r'<link[^>]+(?:rel=["\'](?:modulepreload|preload)["\']|as=["\']script["\'])[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
                    href = match.group(1).strip()
                    if href and not href.startswith("data:"):
                        script_urls.add(urllib.parse.urljoin(base_url, href))

                # 3. Fetch external scripts concurrently
                async def fetch_one(s_url):
                    try:
                        r = await client.get(s_url, timeout=12.0)
                        if r.status_code == 200 and r.text:
                            return s_url, r.text
                    except Exception:
                        pass
                    return s_url, None

                if script_urls:
                    tasks = [fetch_one(u) for u in script_urls]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for res_tuple in results:
                        if isinstance(res_tuple, tuple) and res_tuple[1]:
                            s_url, text = res_tuple
                            captured[s_url] = text

                # 4. Secondary dynamic chunk discovery from downloaded scripts
                chunk_urls = set()
                chunk_pattern = re.compile(r'["\']((?:/(?:static|assets|chunks|js)/|[a-zA-Z0-9_\-\.]+/)[a-zA-Z0-9_\-\.]+\.(?:chunk\.)?js(?:\?[^"\']*)?)["\']')
                for s_url, text in list(captured.items()):
                    for m in chunk_pattern.finditer(text):
                        rel = m.group(1)
                        if not rel.startswith("http") and not rel.startswith("//"):
                            full = urllib.parse.urljoin(s_url, rel)
                            if full not in captured:
                                chunk_urls.add(full)

                if chunk_urls:
                    chunk_tasks = [fetch_one(u) for u in list(chunk_urls)[:30]]
                    chunk_results = await asyncio.gather(*chunk_tasks, return_exceptions=True)
                    for res_tuple in chunk_results:
                        if isinstance(res_tuple, tuple) and res_tuple[1]:
                            s_url, text = res_tuple
                            captured[s_url] = text

        except Exception as e:
            logger.debug(f"Crawler script extraction exception for {url}: {e}")

        return captured

    async def capture_dynamic_scripts(self, url: str, timeout_ms: int = 15000) -> Dict[str, str]:
        """
        Capture all JavaScript files requested by target URL.
        Executes hybrid interception: runs Playwright headless browser for runtime scripts,
        augmented with direct high-speed HTTP chunk & script crawling.
        """
        captured_scripts: Dict[str, str] = {}
        
        # 1. Direct Network & Chunk Crawler (Fast & Resilient)
        crawler_scripts = await self.capture_via_crawler(url)
        captured_scripts.update(crawler_scripts)
        logger.info(f"Direct crawler captured {len(crawler_scripts)} JavaScript sources from {url}")

        # 2. Attempt Headless Browser Interception (to catch deferred Webpack/Vite runtime requests)
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    executable_path="/usr/bin/chromium",
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--single-process",
                        "--disable-blink-features=AutomationControlled",
                        "--ignore-certificate-errors",
                    ]
                )
                
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                    viewport={"width": 1280, "height": 800},
                    ignore_https_errors=True
                )
                
                page = await context.new_page()

                async def on_response(response):
                    try:
                        ct = response.headers.get("content-type", "").lower()
                        req_type = response.request.resource_type
                        clean_url = response.url.split("?")[0].lower()
                        
                        is_js = (
                            "javascript" in ct
                            or req_type == "script"
                            or clean_url.endswith(".js")
                            or clean_url.endswith(".mjs")
                        )
                        
                        if is_js and response.status == 200:
                            body_text = await response.text()
                            if body_text and len(body_text.strip()) > 0:
                                captured_scripts[response.url] = body_text
                    except Exception:
                        pass

                page.on("response", on_response)

                try:
                    logger.info(f"Navigating to {url} to capture dynamic scripts...")
                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                    try:
                        await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
                    except Exception:
                        pass
                    await asyncio.sleep(2)
                except Exception as e:
                    logger.debug(f"Browser navigation notice for {url}: {e}")
                finally:
                    await browser.close()
        except Exception as e:
            logger.debug(f"Headless browser notice for {url}: {e}")

        logger.info(f"Total JavaScript files collected from {url}: {len(captured_scripts)}")
        return captured_scripts

    def extract_from_script(self, script_url: str, content: str, root_domain: str) -> dict:
        """
        Analyze the full text of a JavaScript file for subdomains, endpoints,
        secrets, and source map references.
        """
        subdomains: Set[str] = set()
        cloud_assets: Set[str] = set()
        endpoints: Set[str] = set()
        secrets: List[dict] = []
        sourcemaps: List[str] = []

        # 1. In-Scope Subdomains: *.root_domain
        escaped_root = re.escape(root_domain)
        subdomain_pattern = re.compile(
            rf'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?)*\.{escaped_root})\b',
            re.IGNORECASE
        )
        for match in subdomain_pattern.finditer(content):
            sub = match.group(1).lower().strip(".")
            if sub and sub != root_domain:
                subdomains.add(sub)

        # 2. Third-Party Cloud Assets (S3, CloudFront, Azure, GCP, Firebase)
        for match in self.cloud_regex.finditer(content):
            cloud_assets.add(match.group(0).lower())

        # 3. API Endpoints
        # 3a. From relative quoted paths
        for match in self.api_endpoint_regex.finditer(content):
            ep = match.group(1)
            if len(ep) < 150 and not ep.endswith(('.png', '.jpg', '.css', '.svg', '.woff', '.ttf')):
                endpoints.add(ep)

        # 3b. From absolute URLs
        abs_urls = re.findall(r'https?://[^\s"\'`<>]+', content)
        for u in abs_urls:
            try:
                parsed = urllib.parse.urlparse(u)
                path = parsed.path
                if any(path.startswith(prefix) for prefix in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/auth/', '/oauth/']):
                    full_ep = path + (f"?{parsed.query}" if parsed.query else "")
                    if len(full_ep) < 150:
                        endpoints.add(full_ep)
            except Exception:
                pass

        # 4. Secrets
        for sec_name, pattern in self.secret_patterns.items():
            for m in pattern.findall(content):
                if isinstance(m, tuple):
                    m = m[0]
                m_str = str(m).strip()
                if len(m_str) >= 8 and not any(ch in m_str for ch in ["{", "}", "[", "]", ";"]):
                    secrets.append({"type": sec_name, "value": m_str})

        # 5. Source Maps
        for match in self.sourcemap_regex.finditer(content):
            map_ref = match.group(1).strip()
            # If relative, resolve against script_url
            full_map_url = urllib.parse.urljoin(script_url, map_ref)
            sourcemaps.append(full_map_url)

        return {
            "subdomains": sorted(list(subdomains)),
            "cloud_assets": sorted(list(cloud_assets)),
            "endpoints": sorted(list(endpoints)),
            "secrets": secrets,
            "sourcemaps": sourcemaps,
        }

    async def process_tasks(self):
        """Process queued dynamic_js_extract tasks."""
        task = await self.get_next_task("dynamic_js_extract")
        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        target_url = task.get("url")

        if not target_url:
            target_url = f"https://{target}"

        logger.info(f"Starting Dynamic JS Extraction on {target_url} (Root: {root_domain})")

        try:
            # 1. Capture dynamic scripts via headless browser
            scripts = await self.capture_dynamic_scripts(target_url)
            
            # If HTTPS fails with 0 scripts, attempt HTTP fallback
            if not scripts and target_url.startswith("https://"):
                fallback_url = f"http://{target}"
                logger.info(f"No scripts captured on HTTPS, trying HTTP fallback: {fallback_url}")
                scripts = await self.capture_dynamic_scripts(fallback_url)
                if scripts:
                    target_url = fallback_url

            all_subdomains: Set[str] = set()
            all_cloud_assets: Set[str] = set()
            all_endpoints: Set[str] = set()
            all_secrets: List[dict] = []
            all_sourcemaps: List[str] = []
            script_summaries: List[dict] = []

            # 2. Analyze all captured scripts
            for script_url, content in scripts.items():
                analysis = self.extract_from_script(script_url, content, root_domain)
                
                all_subdomains.update(analysis["subdomains"])
                all_cloud_assets.update(analysis["cloud_assets"])
                all_endpoints.update(analysis["endpoints"])
                all_secrets.extend(analysis["secrets"])
                all_sourcemaps.extend(analysis["sourcemaps"])

                script_summaries.append({
                    "url": script_url,
                    "size_bytes": len(content),
                    "subdomains_found": len(analysis["subdomains"]),
                    "endpoints_found": len(analysis["endpoints"]),
                    "secrets_found": len(analysis["secrets"]),
                    "has_sourcemap": len(analysis["sourcemaps"]) > 0,
                })

            # 3. Auto-Register newly discovered subdomains into MongoDB
            new_subdomains_added = 0
            if all_subdomains:
                now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                sub_objs = [{"name": s, "added_at": now_str, "discovered_by": "dynamic_js_collector"} for s in all_subdomains]
                res = await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$addToSet": {"infrastructure.subdomains": {"$each": sub_objs}}}
                )
                new_subdomains_added = res.modified_count

            # 4. Generate Centralized Hunting Leads
            # A) In-Scope Subdomains discovered in JS
            for sub in all_subdomains:
                await self.create_alert(
                    title=f"JS Discovery: Hidden Subdomain",
                    description=f"Subdomain {sub} was dynamically requested or referenced inside JavaScript runtime bundles of {target}.",
                    target=sub,
                    risk_level="low",
                    details=f"Target: {target}\nSubdomain: {sub}\nSource: Dynamic JS Network Interception ({target_url})",
                    exploitation_suggestions=(
                        "### Hidden Subdomain Exploitation\n\n"
                        "1. **Reconnaissance**: Scan this newly found subdomain for active ports and services.\n"
                        "2. **Authentication**: Check if internal endpoints or staging dashboards are exposed on this host.\n"
                        "3. **Virtual Host Fuzzing**: Test host headers against primary web servers."
                    )
                )

            # B) Cloud Storage Assets
            for cloud in all_cloud_assets:
                await self.create_alert(
                    title=f"JS Discovery: Cloud Storage Asset",
                    description=f"Cloud storage bucket or CDN endpoint ({cloud}) was identified in JavaScript code of {target}.",
                    target=cloud,
                    risk_level="medium",
                    details=f"Target: {target}\nCloud Asset: {cloud}\nSource: Dynamic JS Analysis",
                    exploitation_suggestions=(
                        "### Cloud Storage Verification\n\n"
                        "1. **Public Read Check**: Verify if the S3 bucket or Azure blob container allows unauthenticated listing.\n"
                        "2. **Permissions Review**: Test write permissions to verify bucket hijacking resistance."
                    )
                )

            # C) Sensitive Secrets & Credentials
            seen_secrets = set()
            for sec in all_secrets:
                sec_val = sec["value"]
                if sec_val in seen_secrets:
                    continue
                seen_secrets.add(sec_val)
                await self.create_alert(
                    title=f"JS Discovery: Hardcoded {sec['type']}",
                    description=f"Potential sensitive credential or API token ({sec['type']}) found in JavaScript code on {target}.",
                    target=target,
                    risk_level="high",
                    details=f"Secret Type: {sec['type']}\nSecret Value: {sec_val[:4]}...{sec_val[-4:] if len(sec_val) > 8 else ''}\nSource: {target_url}",
                    exploitation_suggestions=(
                        "### Credential Verification\n\n"
                        "1. **Verify Token Scope**: Check permissions and access limits granted to this token.\n"
                        "2. **Revocation**: Rotate exposed API keys immediately if valid."
                    )
                )

            # D) Exposed Source Maps (.js.map)
            for sm in all_sourcemaps:
                await self.create_alert(
                    title=f"JS Discovery: Exposed Source Map",
                    description=f"JavaScript source map reference detected at {sm}. Source maps can expose unminified original source trees.",
                    target=target,
                    risk_level="medium",
                    details=f"Source Map URL: {sm}\nHost: {target}",
                    exploitation_suggestions=(
                        "### Source Map Decompilation\n\n"
                        "1. **Unpack Source**: Use tools like `shuji` or `sourcemapper` to reconstruct original TypeScript/JavaScript source files.\n"
                        "2. **Code Audit**: Inspect comments, internal API paths, and developer notes in the reconstructed source."
                    )
                )

            # 5. Store aggregated findings in domain document
            recon_summary = {
                "scanned_at": datetime.datetime.utcnow().isoformat(),
                "target_url": target_url,
                "total_scripts_intercepted": len(scripts),
                "scripts": script_summaries,
                "extracted_subdomains": sorted(list(all_subdomains)),
                "extracted_cloud_assets": sorted(list(all_cloud_assets)),
                "extracted_endpoints": sorted(list(all_endpoints))[:500],
                "extracted_secrets_count": len(all_secrets),
                "sourcemaps": all_sourcemaps
            }

            await self.domains_col.update_one(
                {"domain": root_domain},
                {"$set": {"infrastructure.dynamic_js": recon_summary}}
            )

            logger.info(
                f"Dynamic JS Recon Complete for {target}: "
                f"{len(scripts)} scripts, {len(all_subdomains)} subdomains, "
                f"{len(all_endpoints)} endpoints, {len(all_secrets)} secrets."
            )

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error during Dynamic JS extraction on {target}: {e}", exc_info=True)
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )


if __name__ == "__main__":
    agent = DynamicJsCollectorAgent()
    asyncio.run(agent.main_loop())
