import asyncio
import base64
import datetime
import json
import os
import re
import sys
import urllib.parse
import httpx
from typing import Dict, List, Set, Tuple, Optional, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger
from playwright.async_api import async_playwright
from api_schema_discovery import ApiSchemaDiscovery


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
      5. OpenAPI / Swagger & GraphQL schemas
    """

    def __init__(self):
        super().__init__("dynamic_js_collector", "Dynamic JS Recon & Extractor")
        self.api_discovery = ApiSchemaDiscovery()
        
        # High-confidence regex for common credentials / tokens in JS
        self.secret_patterns = {
            "Google API Key": re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b'),
            "AWS Access Key": re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
            "AWS Secret Key": re.compile(r'(?i)(?:aws_secret_access_key|aws_secret_key|secret[_-]?access[_-]?key|aws_sec(?:ret)?|secret[_-]?key)[\s:=\x22\x27\`]+([A-Za-z0-9/+=]{40})(?:[^\w/+=]|$)'),
            "JWT Token": re.compile(r'\beyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*\b'),
            "Bearer Token": re.compile(r'\bBearer\s+(eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*|[A-Za-z0-9_\-\.]{25,})\b'),
            "Stripe Key": re.compile(r'\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b'),
            "Firebase Key": re.compile(r'\b[a-zA-Z0-9]{40}:APA91b[a-zA-Z0-9-_]{134}\b'),
            "Slack Webhook": re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'),
            "GitHub Token": re.compile(r'\bgh[opsu]_[0-9a-zA-Z]{36}\b'),
            "SSH Private Key": re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
        }

        # Comprehensive regex patterns for Cloud Object Storage and Providers
        self.cloud_patterns = [
            # AWS S3 (virtual-hosted style)
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.s3(?:[.-][a-zA-Z0-9\-]+)?\.amazonaws\.com\b', re.IGNORECASE),
                "provider": "AWS S3",
                "type": "virtual_host",
                "url_template": "https://{bucket}.s3.amazonaws.com/"
            },
            # AWS S3 (path-style)
            {
                "pattern": re.compile(r'(?<![.\w])s3(?:[.-][a-zA-Z0-9\-]+)?\.amazonaws\.com/([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
                "provider": "AWS S3",
                "type": "path_style",
                "url_template": "https://s3.amazonaws.com/{bucket}/"
            },
            # Google Cloud Storage (virtual-host)
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.storage\.googleapis\.com\b', re.IGNORECASE),
                "provider": "Google Cloud Storage",
                "type": "virtual_host",
                "url_template": "https://{bucket}.storage.googleapis.com/"
            },
            # Google Cloud Storage (path-style)
            {
                "pattern": re.compile(r'(?<![.\w])storage\.googleapis\.com/([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
                "provider": "Google Cloud Storage",
                "type": "path_style",
                "url_template": "https://storage.googleapis.com/{bucket}/"
            },
            # Azure Blob Storage
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.blob\.core\.windows\.net\b', re.IGNORECASE),
                "provider": "Azure Blob",
                "type": "virtual_host",
                "url_template": "https://{bucket}.blob.core.windows.net/?comp=list"
            },
            # Azure Edge CDN
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.azureedge\.net\b', re.IGNORECASE),
                "provider": "Azure Edge",
                "type": "virtual_host",
                "url_template": "https://{bucket}.azureedge.net/"
            },
            # DigitalOcean Spaces
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.([a-z0-9\-]+)\.digitaloceanspaces\.com\b', re.IGNORECASE),
                "provider": "DigitalOcean Spaces",
                "type": "do_spaces",
                "url_template": "https://{bucket}.{region}.digitaloceanspaces.com/"
            },
            # Backblaze B2 S3 API
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.s3\.[a-z0-9\-]+\.backblazeb2\.com\b', re.IGNORECASE),
                "provider": "Backblaze B2",
                "type": "virtual_host",
                "url_template": "https://{raw}/"
            },
            # Wasabi Cloud Storage
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.s3(?:[.-][a-zA-Z0-9\-]+)?\.wasabisys\.com\b', re.IGNORECASE),
                "provider": "Wasabi",
                "type": "virtual_host",
                "url_template": "https://{raw}/"
            },
            # Cloudflare R2
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.r2\.cloudflarestorage\.com\b', re.IGNORECASE),
                "provider": "Cloudflare R2",
                "type": "virtual_host",
                "url_template": "https://{bucket}.r2.cloudflarestorage.com/"
            },
            # Firebase Realtime DB
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.firebaseio\.com\b', re.IGNORECASE),
                "provider": "Firebase",
                "type": "virtual_host",
                "url_template": "https://{bucket}.firebaseio.com/.json"
            },
            # CloudFront Distributions
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.cloudfront\.net\b', re.IGNORECASE),
                "provider": "AWS CloudFront",
                "type": "cdn",
                "url_template": "https://{bucket}.cloudfront.net/"
            },
        ]

        # Regex for API endpoints
        self.api_endpoint_regex = re.compile(
            r'(?:["\'`])((?:/api/|/v[0-9]+/|/graphql|/rest/|/auth/|/oauth/|/v[0-9]+\.[0-9]+/)[a-zA-Z0-9_\-\./?=&%#]+)(?:["\'`])'
        )

        # Source Map directive regex
        self.sourcemap_regex = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)')

    @staticmethod
    def decode_jwt(jwt_str: str) -> dict:
        """
        Decode header and payload of a JWT token using base64url.
        Preserves original raw token even if decoding fails.
        """
        parts = jwt_str.strip().split('.')
        result = {
            "type": "jwt",
            "raw": jwt_str,
            "header": None,
            "payload": None,
            "signature": parts[2] if len(parts) > 2 else "",
            "error": None
        }

        def b64url_decode(s: str) -> str:
            pad = '=' * ((4 - len(s) % 4) % 4)
            return base64.urlsafe_b64decode(s + pad).decode('utf-8', errors='replace')

        if len(parts) >= 1 and parts[0]:
            try:
                h_text = b64url_decode(parts[0])
                try:
                    result["header"] = json.loads(h_text)
                except Exception:
                    result["header"] = h_text
            except Exception as e:
                result["error"] = f"Header decode error: {e}"

        if len(parts) >= 2 and parts[1]:
            try:
                p_text = b64url_decode(parts[1])
                try:
                    result["payload"] = json.loads(p_text)
                except Exception:
                    result["payload"] = p_text
            except Exception as e:
                err_msg = f"Payload decode error: {e}"
                result["error"] = f"{result['error']}; {err_msg}" if result.get("error") else err_msg

        return result

    @staticmethod
    def decode_base64(candidate: str) -> Optional[dict]:
        """
        Validate and decode candidate base64 strings with false-positive filtering.
        Threshold: minimum 12 characters, valid length, non-hex, printable UTF-8.
        """
        cand = candidate.strip()
        if len(cand) < 12 or len(cand) % 4 == 1:
            return None
        # Reject pure hex hashes (MD5, SHA1, SHA256)
        if re.fullmatch(r'[0-9a-fA-F]+', cand):
            return None
        # Reject repetitive character strings (e.g. AAAA...)
        if len(set(cand)) <= 3:
            return None
        # Reject pure lowercase or pure uppercase alphabetic identifiers
        if cand.isalpha() and (cand.islower() or cand.isupper()):
            return None

        pad_len = (4 - len(cand) % 4) % 4
        padded = cand + ('=' * pad_len)
        try:
            raw_bytes = base64.b64decode(padded, validate=True)
            if len(raw_bytes) < 4:
                return None

            decoded_text = raw_bytes.decode('utf-8', errors='strict')
            # Check printable characters ratio (rejects binary blobs, images, compiled code)
            printable = sum(1 for c in decoded_text if 32 <= ord(c) <= 126 or c in '\r\n\t')
            if printable / len(decoded_text) < 0.90:
                return None

            trimmed = decoded_text.strip()
            if len(trimmed) < 3:
                return None

            category = "text"
            parsed_json = None
            if (trimmed.startswith('{') and trimmed.endswith('}')) or (trimmed.startswith('[') and trimmed.endswith(']')):
                try:
                    parsed_json = json.loads(trimmed)
                    category = "json"
                except Exception:
                    pass
            elif re.match(r'^https?://', trimmed) or (trimmed.startswith('/') and '/' in trimmed[1:]):
                category = "url"
            elif any(k in trimmed.lower() for k in ["bearer ", "token", "key=", "secret", "password", "api_key", "auth:"]):
                category = "credential"

            return {
                "type": "base64",
                "category": category,
                "raw": cand,
                "decoded": trimmed,
                "json": parsed_json,
                "error": None
            }
        except Exception:
            return None

    async def probe_cloud_asset(self, client: httpx.AsyncClient, asset_info: dict) -> dict:
        """
        Active security probe for a discovered cloud storage asset.
        Evaluates whether the bucket is:
          - 'open': publicly readable / directory listing exposed (ALERT)
          - 'vulnerable_takeover': 404 NoSuchBucket, claimable/hijackable (ALERT)
          - 'secured': 401/403 AccessDenied or private (NO ALERT per configuration)
          - 'cdn': CDN distribution endpoint
        """
        probe_url = asset_info["probe_url"]
        provider = asset_info["provider"]
        raw = asset_info["raw"]

        result = {
            **asset_info,
            "status": "secured",
            "http_status": None,
            "is_open": False,
            "is_takeover": False,
            "is_secured": False,
            "details": ""
        }

        # Don't probe CloudFront distributions for bucket directory listing
        if provider == "AWS CloudFront" or asset_info.get("type") == "cdn":
            result["status"] = "cdn"
            result["is_secured"] = True
            result["details"] = "CDN distribution endpoint"
            return result

        try:
            res = await client.get(
                probe_url,
                timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                follow_redirects=True
            )
            result["http_status"] = res.status_code
            text = res.text[:2500]

            if provider in ["AWS S3", "DigitalOcean Spaces", "Backblaze B2", "Wasabi", "Cloudflare R2"]:
                if res.status_code == 200 and ("<ListBucketResult" in text or "<ListAllMyBucketsResult" in text or "<Key>" in text):
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Public directory listing allowed (HTTP 200). Objects and keys readable unauthenticated."
                elif res.status_code == 404 and ("<Code>NoSuchBucket</Code>" in text or "BucketDoesNotExist" in text):
                    result["status"] = "vulnerable_takeover"
                    result["is_takeover"] = True
                    result["details"] = "Bucket does not exist (HTTP 404 NoSuchBucket). Dangling reference vulnerable to bucket takeover."
                elif res.status_code in [401, 403] or "<Code>AccessDenied</Code>" in text:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"Bucket is private and protected (HTTP {res.status_code} AccessDenied)."
                else:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"HTTP {res.status_code} (access restricted)."

            elif provider == "Google Cloud Storage":
                if res.status_code == 200 and ("<ListBucketResult" in text or '"items":' in text):
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "GCS bucket is publicly listable (HTTP 200)."
                elif res.status_code == 404 and ("NoSuchBucket" in text or "Not Found" in text):
                    result["status"] = "vulnerable_takeover"
                    result["is_takeover"] = True
                    result["details"] = "GCS bucket does not exist (HTTP 404). Vulnerable to bucket claiming/takeover."
                else:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"GCS bucket is private/restricted (HTTP {res.status_code})."

            elif provider == "Azure Blob":
                if res.status_code == 200 and "<EnumerationResults" in text:
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Azure Blob container allows public enumeration (HTTP 200)."
                elif res.status_code == 404 and ("AccountNotFound" in text or "ResourceNotFound" in text):
                    result["status"] = "vulnerable_takeover"
                    result["is_takeover"] = True
                    result["details"] = "Azure storage account not found (HTTP 404). Potential bucket takeover."
                else:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"Azure Blob is private/restricted (HTTP {res.status_code})."

            elif provider == "Firebase":
                if res.status_code == 200 and "error" not in text and text.strip() not in ["null", ""]:
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Firebase Realtime DB allows public unauthenticated reads (HTTP 200)."
                elif "Permission denied" in text or res.status_code in [401, 403]:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = "Firebase security rules active (Permission denied)."
                else:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"Firebase restricted (HTTP {res.status_code})."

            else:
                result["status"] = "secured"
                result["is_secured"] = True
                result["details"] = f"HTTP {res.status_code}"

        except Exception as e:
            # Network failure or timeout: treat as non-accessible / secured to avoid false alarms
            result["status"] = "secured"
            result["is_secured"] = True
            result["details"] = f"Probe connection error: {str(e)}"

        return result

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
                        "--ignore-ssl-errors=yes",
                        "--ignore-certificate-errors-spki-list",
                        "--allow-insecure-localhost",
                        "--allow-running-insecure-content",
                        "--disable-web-security"
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

    def extract_from_script(self, script_url: str, content: str, root_domain: str, target_url: str = "") -> dict:
        """
        Analyze the full text of a JavaScript file for subdomains, endpoints,
        secrets, and source map references.
        """
        subdomains: Set[str] = set()
        cloud_assets: Set[str] = set()
        endpoints: Dict[str, dict] = {}
        secrets: List[dict] = []
        sourcemaps: List[str] = []

        # Determine origin domain / base URL for relative paths
        is_inline = "#inline-script-" in script_url
        clean_script_url = script_url.split("#inline-script-")[0]
        parsed_script = urllib.parse.urlparse(clean_script_url)
        script_host = parsed_script.hostname or ""

        target_base = target_url.rstrip("/") if target_url else ""
        if target_base:
            parsed_target = urllib.parse.urlparse(target_base)
            target_host = parsed_target.hostname or ""
            target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        else:
            target_host = ""
            target_origin = ""

        # Check if the script itself is 1st-party
        is_first_party_script = is_inline or (
            script_host == root_domain
            or script_host.endswith("." + root_domain)
            or (target_host and (script_host == target_host or script_host.endswith("." + target_host)))
        )

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

        # 2. Third-Party Cloud Assets & Object Storage Buckets
        cloud_assets_dict: Dict[str, dict] = {}
        for rule in self.cloud_patterns:
            for match in rule["pattern"].finditer(content):
                raw_match = match.group(0).lower().strip("/")
                bucket_name = match.group(1).lower()

                # Filter out common false-positive names / noise
                if bucket_name in ["s3", "storage", "blob", "com", "www", "static", "assets", "public", "dev", "prod", "null", "undefined"]:
                    continue

                if rule["type"] == "do_spaces":
                    region = match.group(2).lower()
                    probe_url = rule["url_template"].format(bucket=bucket_name, region=region)
                elif "{bucket}" in rule["url_template"]:
                    probe_url = rule["url_template"].format(bucket=bucket_name)
                else:
                    probe_url = rule["url_template"].format(raw=raw_match)

                cloud_assets_dict[raw_match] = {
                    "raw": raw_match,
                    "bucket_name": bucket_name,
                    "provider": rule["provider"],
                    "probe_url": probe_url,
                    "type": rule["type"]
                }

        # 3. API Endpoints
        # Helper to register an endpoint
        def add_endpoint(full_url: str, path: str, host: str, is_in_scope: bool):
            if full_url and full_url not in endpoints:
                endpoints[full_url] = {
                    "url": full_url,
                    "path": path,
                    "host": host,
                    "is_in_scope": is_in_scope,
                    "source_script": script_url
                }

        # 3a. From relative quoted paths
        for match in self.api_endpoint_regex.finditer(content):
            ep_path = match.group(1)
            if len(ep_path) < 150 and not ep_path.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.svg', '.woff', '.woff2', '.ttf')):
                # Ensure clean path format
                clean_path = ep_path if ep_path.startswith('/') else f"/{ep_path}"
                if is_first_party_script:
                    base_origin = target_origin or f"https://{root_domain}"
                    host = target_host or root_domain
                    full_url = f"{base_origin}{clean_path}"
                    add_endpoint(full_url, clean_path, host, True)
                else:
                    # 3rd-party vendor script (e.g., gstatic.com / recaptcha, cookielaw.org)
                    script_origin = f"{parsed_script.scheme}://{parsed_script.netloc}" if parsed_script.netloc else ""
                    full_url = f"{script_origin}{clean_path}" if script_origin else clean_path
                    add_endpoint(full_url, clean_path, script_host, False)

        # 3b. From absolute URLs
        abs_urls = re.findall(r'https?://[^\s"\'`<>]+', content)
        for u in abs_urls:
            try:
                parsed = urllib.parse.urlparse(u)
                path = parsed.path
                if any(path.startswith(prefix) for prefix in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/auth/', '/oauth/']):
                    full_ep_url = u.split('#')[0]
                    u_host = parsed.hostname or ""
                    is_scope = (
                        u_host == root_domain
                        or u_host.endswith("." + root_domain)
                        or (target_host and (u_host == target_host or u_host.endswith("." + target_host)))
                    )
                    if len(full_ep_url) < 250:
                        add_endpoint(full_ep_url, path, u_host, is_scope)
            except Exception:
                pass

        # 4. Secrets
        for sec_name, pattern in self.secret_patterns.items():
            for match in pattern.finditer(content):
                m_str = match.group(0).strip()
                if match.groups():
                    m_str = match.group(1).strip()
                
                # Strip wrapping quotes
                m_str = m_str.strip('"\'`')

                # Reject URLs, file paths, and assets
                if m_str.startswith(("http://", "https://", "/", "./", "../")) or "://" in m_str:
                    continue
                if any(m_str.lower().endswith(ext) for ext in [".js", ".css", ".html", ".png", ".jpg", ".jpeg", ".svg", ".json", ".map", ".wasm"]):
                    continue

                # Reject code identifiers, function names, and common false positives
                low = m_str.lower()
                if any(kw in low for kw in ["recaptcha", "challenge", "qrcode", "hidden", "javascript", "function", "undefined", "null", "placeholder", "default"]):
                    continue

                # Bearer Token validation
                if sec_name == "Bearer Token":
                    token_part = m_str[7:].strip() if m_str.lower().startswith("bearer ") else m_str
                    if token_part.lower() in ["token", "undefined", "null", "string", "test", "bearer", "accesstoken", "access_token", "jwt", "auth"]:
                        continue
                    if len(token_part) < 20:
                        continue

                # Reject pure alphabetical camelCase/PascalCase identifiers
                if re.match(r'^[a-zA-Z]+$', m_str) and sec_name not in ["SSH Private Key"]:
                    continue

                if len(m_str) >= 8 and not any(ch in m_str for ch in ["{", "}", "[", "]", ";", " "]):
                    # Real AWS Secret Keys are base64-encoded random bytes (160-bit) with high entropy
                    if sec_name == "AWS Secret Key":
                        if not (any(c.isupper() for c in m_str) and any(c.islower() for c in m_str) and any(c.isdigit() for c in m_str)):
                            continue

                    # Capture surrounding context for precise location & searching
                    start_idx = max(0, match.start() - 70)
                    end_idx = min(len(content), match.end() + 70)
                    raw_context = content[start_idx:end_idx].replace('\r', ' ').replace('\n', ' ').strip()

                    secrets.append({
                        "type": sec_name,
                        "value": m_str,
                        "source_script": script_url,
                        "context": raw_context
                    })

        # 5. Source Maps
        for match in self.sourcemap_regex.finditer(content):
            map_ref = match.group(1).strip()
            # If relative, resolve against script_url
            full_map_url = urllib.parse.urljoin(script_url, map_ref)
            sourcemaps.append(full_map_url)

        # 6. JWT Tokens (extract, decode header & payload, preserve raw even if decoding error)
        jwt_pattern = self.secret_patterns.get("JWT Token")
        seen_jwt_raw = set()
        jwts: List[dict] = []
        if jwt_pattern:
            for m in jwt_pattern.findall(content):
                jwt_str = str(m).strip()
                if jwt_str not in seen_jwt_raw and len(jwt_str) > 20:
                    seen_jwt_raw.add(jwt_str)
                    jwt_obj = self.decode_jwt(jwt_str)
                    jwt_obj["source_script"] = script_url
                    jwts.append(jwt_obj)

        # 7. Base64 Strings (extract, decode, validate, and preserve high-value tokens)
        base64_strings: List[dict] = []
        seen_b64_raw = set()

        # Match quoted candidate strings of length >= 12
        for match in re.finditer(r'["\'`]([A-Za-z0-9+/]{12,}={0,2})["\'`]', content):
            cand = match.group(1).strip()
            if cand in seen_b64_raw or cand in seen_jwt_raw or cand.startswith('eyJ'):
                continue
            seen_b64_raw.add(cand)
            b64_info = self.decode_base64(cand)
            if b64_info:
                b64_info["source_script"] = script_url
                base64_strings.append(b64_info)
                # If the decoded string is an API endpoint or URL, add it to endpoints
                dec_text = b64_info.get("decoded", "")
                if dec_text.startswith("http://") or dec_text.startswith("https://"):
                    try:
                        parsed_u = urllib.parse.urlparse(dec_text)
                        u_host = parsed_u.hostname or ""
                        is_scope = (
                            u_host == root_domain
                            or u_host.endswith("." + root_domain)
                            or (target_host and (u_host == target_host or u_host.endswith("." + target_host)))
                        )
                        add_endpoint(dec_text, parsed_u.path or "/", u_host, is_scope)
                    except Exception:
                        pass
                elif dec_text.startswith("/") and len(dec_text) < 150 and not dec_text.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.svg', '.woff', '.ttf')):
                    base_origin = target_origin or f"https://{root_domain}"
                    add_endpoint(f"{base_origin}{dec_text}", dec_text, target_host or root_domain, is_first_party_script)

        # Also check for HTTP Authorization Basic headers or atob() calls
        for match in re.finditer(r'(?:Basic\s+|atob\s*\(\s*["\'`])([A-Za-z0-9+/=]{8,})', content, re.IGNORECASE):
            cand = match.group(1).strip()
            if cand not in seen_b64_raw and cand not in seen_jwt_raw and not cand.startswith('eyJ'):
                seen_b64_raw.add(cand)
                b64_info = self.decode_base64(cand)
                if not b64_info:
                    # Keep high-value token even if non-printable
                    b64_info = {
                        "type": "base64",
                        "category": "credential",
                        "raw": cand,
                        "decoded": None,
                        "error": "Non-standard or binary encoding"
                    }
                b64_info["source_script"] = script_url
                base64_strings.append(b64_info)

        return {
            "subdomains": sorted(list(subdomains)),
            "cloud_assets": list(cloud_assets_dict.values()),
            "endpoints": list(endpoints.values()),
            "secrets": secrets,
            "sourcemaps": sourcemaps,
            "jwts": jwts,
            "base64_strings": base64_strings,
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
            all_cloud_assets: Dict[str, dict] = {}
            all_endpoints: Dict[str, dict] = {}
            all_secrets: List[dict] = []
            all_sourcemaps: List[str] = []
            all_jwts: Dict[str, dict] = {}
            all_base64: Dict[str, dict] = {}
            script_summaries: List[dict] = []

            # 2. Analyze all captured scripts
            for script_url, content in scripts.items():
                analysis = self.extract_from_script(script_url, content, root_domain, target_url=target_url)
                
                all_subdomains.update(analysis["subdomains"])
                for ca in analysis["cloud_assets"]:
                    all_cloud_assets[ca["raw"]] = ca
                for ep_item in analysis["endpoints"]:
                    ep_url = ep_item["url"]
                    if ep_url not in all_endpoints:
                        all_endpoints[ep_url] = ep_item
                all_secrets.extend(analysis["secrets"])
                all_sourcemaps.extend(analysis["sourcemaps"])
                for j in analysis.get("jwts", []):
                    if j["raw"] not in all_jwts:
                        all_jwts[j["raw"]] = j
                for b in analysis.get("base64_strings", []):
                    if b["raw"] not in all_base64:
                        all_base64[b["raw"]] = b

                script_summaries.append({
                    "url": script_url,
                    "is_inline": "#inline-script-" in script_url,
                    "size_bytes": len(content),
                    "subdomains_found": len(analysis["subdomains"]),
                    "endpoints_found": len(analysis["endpoints"]),
                    "secrets_found": len(analysis["secrets"]),
                    "jwts_found": len(analysis.get("jwts", [])),
                    "base64_found": len(analysis.get("base64_strings", [])),
                    "has_sourcemap": len(analysis["sourcemaps"]) > 0,
                })

            # Active Cloud Storage Permission Probing
            probed_cloud_assets: List[dict] = []
            if all_cloud_assets:
                logger.info(f"Active probing {len(all_cloud_assets)} discovered cloud storage assets for {target}...")
                async with httpx.AsyncClient(verify=False, timeout=10.0) as probe_client:
                    probe_tasks = [self.probe_cloud_asset(probe_client, ca) for ca in all_cloud_assets.values()]
                    probed_results = await asyncio.gather(*probe_tasks, return_exceptions=True)
                    for res in probed_results:
                        if isinstance(res, dict):
                            probed_cloud_assets.append(res)

            # 3. Auto-Register newly discovered subdomains into MongoDB and Queue for Scanning
            new_subdomains_added = 0
            if all_subdomains:
                domain_doc = await self.domains_col.find_one({"domain": root_domain})
                is_single = (domain_doc or {}).get("single_domain_only", False)

                if not is_single:
                    existing_subs = set()
                    if domain_doc:
                        infra = domain_doc.get("infrastructure", {})
                        if isinstance(infra, dict):
                            for s in infra.get("subdomains", []):
                                if isinstance(s, dict) and s.get("name"):
                                    existing_subs.add(s["name"].strip().lower())
                                elif isinstance(s, str) and s.strip():
                                    existing_subs.add(s.strip().lower())
                        for s in domain_doc.get("subdomains", []):
                            if isinstance(s, dict) and s.get("subdomain"):
                                existing_subs.add(s["subdomain"].strip().lower())
                            elif isinstance(s, str) and s.strip():
                                existing_subs.add(s.strip().lower())
                        for sys_item in domain_doc.get("systems", []):
                            if isinstance(sys_item, dict) and sys_item.get("target"):
                                existing_subs.add(sys_item["target"].strip().lower())
                        for w in domain_doc.get("web_applications", []):
                            if isinstance(w, dict) and w.get("target"):
                                existing_subs.add(w["target"].strip().lower())

                    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    subs_to_push = []
                    tasks_to_queue = []

                    for s in all_subdomains:
                        s_clean = s.strip().lower().rstrip(".")
                        # Strict scope check: must strictly match root_domain (*.root_domain)
                        if not self.is_in_scope(s_clean, root_domain, single_domain_only=False):
                            continue
                        if s_clean == root_domain.strip().lower():
                            continue
                        # Deduplication: avoid duplicates
                        if s_clean in existing_subs:
                            continue

                        existing_subs.add(s_clean)
                        subs_to_push.append({
                            "name": s_clean,
                            "added_at": now_str,
                            "discovered_by": "dynamic_js_collector"
                        })

                        # Queue for verification/scan if not already queued
                        exists_task = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": s_clean,
                            "task_type": {"$in": ["verification", "scan"]}
                        })
                        if not exists_task:
                            tasks_to_queue.append({
                                "root_domain": root_domain,
                                "target": s_clean,
                                "task_type": "verification",
                                "status": "pending",
                                "priority": 0,
                                "created_at": datetime.datetime.utcnow()
                            })

                    if subs_to_push:
                        new_subdomains_added = 0
                        for sub_item in subs_to_push:
                            res = await self.domains_col.update_one(
                                {"domain": root_domain, "infrastructure.subdomains.name": {"$ne": sub_item["name"]}},
                                {"$push": {"infrastructure.subdomains": sub_item}}
                            )
                            if res.modified_count > 0:
                                new_subdomains_added += 1
                        logger.info(f"Registered {new_subdomains_added} new in-scope subdomains into inventory for {root_domain}.")

                    if tasks_to_queue:
                        await self.tasks_col.insert_many(tasks_to_queue)
                        logger.info(f"Queued {len(tasks_to_queue)} verification tasks for newly found subdomains of {root_domain}.")

            # 4. Generate Centralized Hunting Leads
            # Subdomain discovery alerts omitted per configuration (subdomains are directly queued for scanning).

            # B) Cloud Storage Assets Alerting

            # IMPORTANT: Per configuration, do NOT alert if secured.
            # Only alert if the bucket is unauthenticated public (leak) or 404 (takeover).
            for probed in probed_cloud_assets:
                if probed.get("is_secured") or probed.get("status") in ["secured", "cdn"]:
                    logger.info(f"Cloud storage asset '{probed['raw']}' ({probed['provider']}) is SECURED - added to domain inventory, skipping alert.")
                    continue

                if probed.get("is_open"):
                    await self.create_alert(
                        title=f"Cloud Storage Leak: Publicly Accessible {probed['provider']} Bucket",
                        description=f"{probed['provider']} bucket '{probed['raw']}' was found in JavaScript on {target} and allows UNRESTRICTED public listing and object downloads.",
                        target=probed["raw"],
                        risk_level="critical",
                        details=f"Target: {target}\nBucket URL: {probed['probe_url']}\nProvider: {probed['provider']}\nStatus: {probed.get('details')}\nSource: Dynamic JS Analysis ({target_url})",
                        exploitation_suggestions=(
                            "### Public Cloud Storage Exploitation & Remediation\n\n"
                            "1. **Enumerate Bucket Contents**: Inspect the bucket XML/JSON directory listing to identify exposed backups, database dumps, customer files, or credentials.\n"
                            "2. **Check Write Permissions**: Test whether unauthenticated HTTP PUT or AWS CLI `aws s3 cp` allows uploading files.\n"
                            "3. **Remediation**: Enable 'Block Public Access' and enforce restricted IAM access policies immediately."
                        ),
                        alert_type="js_cloud_storage_leaks"
                    )
                elif probed.get("is_takeover"):
                    await self.create_alert(
                        title=f"Cloud Storage Takeover: Unclaimed {probed['provider']} Bucket",
                        description=f"{probed['provider']} bucket '{probed['raw']}' referenced in JavaScript on {target} returned 404 (NoSuchBucket). An attacker can register this bucket to hijack frontend assets or host payloads.",
                        target=probed["raw"],
                        risk_level="high",
                        details=f"Target: {target}\nBucket URL: {probed['probe_url']}\nProvider: {probed['provider']}\nStatus: {probed.get('details')}\nSource: Dynamic JS Analysis ({target_url})",
                        exploitation_suggestions=(
                            "### Cloud Bucket Takeover Remediation\n\n"
                            "1. **Register Name Immediately**: Claim the bucket name in the relevant cloud provider before external threat actors discover it.\n"
                            "2. **Code Cleanup**: Remove obsolete dangling references from frontend JavaScript bundles."
                        ),
                        alert_type="js_cloud_storage_takeover"
                    )

            # C) Sensitive Secrets & Credentials
            seen_secrets = set()
            for sec in all_secrets:
                sec_val = sec["value"]
                sec_source = sec.get("source_script") or target_url
                sec_context = sec.get("context", "")

                sec_key = (sec["type"], sec_val, sec_source)
                if sec_key in seen_secrets:
                    continue
                seen_secrets.add(sec_key)

                context_section = f"\n\n**Code Snippet / Surrounding Context:**\n```javascript\n...{sec_context}...\n```" if sec_context else ""

                details_text = (
                    f"**Secret Type:** `{sec['type']}`\n\n"
                    f"**Secret Value:** `{sec_val}`\n\n"
                    f"**Script File:** [{sec_source}]({sec_source})\n\n"
                    f"**Target Application:** [{target_url}]({target_url})"
                    f"{context_section}"
                )

                await self.create_alert(
                    title=f"JS Discovery: Hardcoded {sec['type']}",
                    description=f"Potential sensitive credential or API token ({sec['type']}) found in {sec_source} on {target}.",
                    target=target,
                    risk_level="high",
                    details=details_text,
                    exploitation_suggestions=(
                        "### Credential Verification & Search Guide\n\n"
                        f"1. **Locate in Script**: Open [{sec_source}]({sec_source}) in your browser or DevTools and search (`Ctrl+F` / `Cmd+F`) for:\n"
                        f"   ```text\n   {sec_val}\n   ```\n\n"
                        "2. **Verify Token Scope**: Check permissions, authorized APIs, and access limits granted to this token.\n\n"
                        "3. **Revocation & Remediation**: Rotate exposed credentials immediately and remove them from client-side bundles."
                    ),
                    alert_type="js_hardcoded_secrets"
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
                    ),
                    extra_key=sm,
                    alert_type="js_source_maps"
                )
                # Automatically recover and decompile source code from exposed source map
                try:
                    from source_map_unpacker import SourceMapUnpacker
                    unpacker = SourceMapUnpacker()
                    await unpacker.unpack_url(sm, target=target)
                except Exception as sm_err:
                    logger.warning(f"Auto source map unpacking error for {sm}: {sm_err}")

            # E) Exposed JWT Tokens
            for jwt in list(all_jwts.values())[:10]:
                payload_summary = ""
                if jwt.get("decoded_payload"):
                    if isinstance(jwt["decoded_payload"], dict):
                        payload_summary = ", ".join(f"{k}={v}" for k, v in list(jwt["decoded_payload"].items())[:4])
                    else:
                        payload_summary = str(jwt["decoded_payload"])[:80]
                await self.create_alert(
                    title=f"JS Discovery: Exposed JWT Token",
                    description=f"Exposed JSON Web Token (JWT) identified in JavaScript on {target}." + (f" Claims: {payload_summary}" if payload_summary else ""),
                    target=target,
                    risk_level="medium",
                    details=f"Target: {target}\nRaw Token: {jwt['raw'][:40]}...\nHeader: {jwt.get('decoded_header')}\nPayload: {jwt.get('decoded_payload')}\nSource: {jwt.get('source_script')}",
                    exploitation_suggestions=(
                        "### JWT Security Review\n\n"
                        "1. **Inspect Claims**: Check if token grants unauthorized roles, admin claims, or sensitive scopes.\n"
                        "2. **Expiration**: Verify if token has expired or remains active indefinitely.\n"
                        "3. **Signature Flaws**: Check if 'alg' header allows 'none' or if secret key is weak."
                    ),
                    alert_type="js_jwt_tokens"
                )

            # F) Auto-discover OpenAPI / Swagger specifications and GraphQL endpoints
            api_res = None
            try:
                logger.info(f"Probing OpenAPI & GraphQL endpoints on {target_url}...")
                api_res = await self.api_discovery.discover(target_url)

                # Emit alerts if Swagger/OpenAPI spec found
                if api_res.get("openapi_specs"):
                    for spec in api_res["openapi_specs"]:
                        await self.create_alert(
                            title="API Discovery: Exposed OpenAPI/Swagger Spec",
                            description=f"Exposed API Specification found at {spec['url']} with {spec.get('routes_count', 0)} endpoints documented.",
                            target=target,
                            risk_level="medium",
                            details=(
                                f"Specification URL: {spec['url']}\n"
                                f"Title: {spec.get('title')}\n"
                                f"Version: {spec.get('version')}\n"
                                f"Total Routes: {spec.get('routes_count', 0)}\n"
                                f"Sample Routes:\n" + "\n".join([f"  {r.get('method')} {r.get('path')}" for r in spec.get('routes', [])[:10]])
                            ),
                            exploitation_suggestions=(
                                "### API Specification Security Review\n\n"
                                "1. **Analyze Endpoints**: Review uncovered internal, admin, or debug endpoints.\n"
                                "2. **Check Authentication**: Verify whether all sensitive routes enforce authentication/authorization tokens.\n"
                                "3. **Test Parameter Tampering**: Review request parameter schemas for missing server-side validation or mass assignment vulnerabilities."
                            ),
                            alert_type="api_spec_discovered"
                        )

                # Emit alerts if GraphQL introspection is enabled
                if api_res.get("graphql_endpoints"):
                    for gql in api_res["graphql_endpoints"]:
                        if gql.get("introspection_enabled"):
                            await self.create_alert(
                                title="API Discovery: GraphQL Schema Introspection Enabled",
                                description=f"GraphQL endpoint at {gql['url']} has public schema introspection enabled ({gql.get('queries_count', 0)} queries, {gql.get('mutations_count', 0)} mutations).",
                                target=target,
                                risk_level="medium",
                                details=(
                                    f"GraphQL Endpoint: {gql['url']}\n"
                                    f"Introspection Enabled: True\n"
                                    f"Available Queries ({gql.get('queries_count', 0)}): {', '.join(gql.get('queries', [])[:15])}\n"
                                    f"Available Mutations ({gql.get('mutations_count', 0)}): {', '.join(gql.get('mutations', [])[:15])}\n"
                                    f"Total Types: {gql.get('total_types', 0)}"
                                ),
                                exploitation_suggestions=(
                                    "### GraphQL Security Review\n\n"
                                    "1. **Audit Mutations**: Check sensitive mutation operations (e.g. user creation, password resets, payment updates) for authorization bypass.\n"
                                    "2. **Production Hardening**: Disable schema introspection in production environments to prevent schema disclosure."
                                ),
                                alert_type="graphql_introspection_enabled"
                            )
                        elif gql.get("ide_exposed"):
                            await self.create_alert(
                                title="API Discovery: GraphQL IDE Exposed",
                                description=f"GraphQL interactive IDE/Playground exposed at {gql['url']}.",
                                target=target,
                                risk_level="low",
                                details=f"Target URL: {gql['url']}\nIDE Exposed: True",
                                exploitation_suggestions="Disable public interactive GraphQL playground/GraphiQL console on production systems.",
                                alert_type="graphql_ide_exposed"
                            )
            except Exception as api_err:
                logger.warning(f"API & GraphQL auto-discovery error on {target_url}: {api_err}")

            # 5. Store aggregated findings in domain document & web application inventory
            s3_items = []
            azure_items = []
            gcp_items = []
            other_items = []

            for c in probed_cloud_assets:
                asset_obj = {
                    "name": c.get("bucket_name") or c["raw"],
                    "raw": c["raw"],
                    "url": c.get("probe_url") or f"https://{c['raw']}",
                    "provider": c["provider"],
                    "status": c["status"],           # "secured", "open", "vulnerable_takeover", "cdn"
                    "http_status": c.get("http_status"),
                    "details": c.get("details", ""),
                    "source_app": target,
                    "discovered_by": "dynamic_js_collector",
                    "discovered_at": datetime.datetime.utcnow().isoformat()
                }
                if c["provider"] == "AWS S3":
                    s3_items.append(asset_obj)
                elif c["provider"] in ["Azure Blob", "Azure Edge"]:
                    azure_items.append(asset_obj)
                elif c["provider"] == "Google Cloud Storage":
                    gcp_items.append(asset_obj)
                else:
                    other_items.append(asset_obj)

            # A) Update infrastructure.cloud_footprint (Domain Inventory with URL & source deduplication)
            if s3_items or azure_items or gcp_items or other_items:
                doc = await self.domains_col.find_one({"domain": root_domain}, {"infrastructure.cloud_footprint": 1})
                existing_cf = (doc or {}).get("infrastructure", {}).get("cloud_footprint") or {}

                def merge_buckets(existing_list, new_items):
                    merged = {}
                    for item in (existing_list or []):
                        if isinstance(item, dict):
                            u = (item.get("url") or item.get("raw") or item.get("name") or "").strip().lower().rstrip("/")
                            src = (item.get("source_app") or "").strip().lower()
                            if u:
                                merged[(u, src)] = item
                    for item in new_items:
                        u = (item.get("url") or item.get("raw") or item.get("name") or "").strip().lower().rstrip("/")
                        src = (item.get("source_app") or "").strip().lower()
                        if u:
                            merged[(u, src)] = item
                    return list(merged.values())

                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {
                        "infrastructure.cloud_footprint.s3_buckets": merge_buckets(existing_cf.get("s3_buckets"), s3_items),
                        "infrastructure.cloud_footprint.azure_blobs": merge_buckets(existing_cf.get("azure_blobs"), azure_items),
                        "infrastructure.cloud_footprint.gcp_buckets": merge_buckets(existing_cf.get("gcp_buckets"), gcp_items),
                        "infrastructure.cloud_footprint.other_buckets": merge_buckets(existing_cf.get("other_buckets"), other_items),
                    }}
                )

                if target and target.lower() != root_domain.lower():
                    t_doc = await self.domains_col.find_one({"domain": target}, {"infrastructure.cloud_footprint": 1})
                    if t_doc:
                        t_existing_cf = (t_doc or {}).get("infrastructure", {}).get("cloud_footprint") or {}
                        await self.domains_col.update_one(
                            {"domain": target},
                            {"$set": {
                                "infrastructure.cloud_footprint.s3_buckets": merge_buckets(t_existing_cf.get("s3_buckets"), s3_items),
                                "infrastructure.cloud_footprint.azure_blobs": merge_buckets(t_existing_cf.get("azure_blobs"), azure_items),
                                "infrastructure.cloud_footprint.gcp_buckets": merge_buckets(t_existing_cf.get("gcp_buckets"), gcp_items),
                                "infrastructure.cloud_footprint.other_buckets": merge_buckets(t_existing_cf.get("other_buckets"), other_items),
                            }}
                        )

            # C) Store dynamic JS summary
            recon_summary = {
                "scanned_at": datetime.datetime.utcnow().isoformat(),
                "target_url": target_url,
                "total_scripts_intercepted": len(scripts),
                "scripts": script_summaries,
                "extracted_subdomains": sorted(list(all_subdomains)),
                "extracted_cloud_assets": [
                    {
                        "raw": p["raw"],
                        "name": p.get("bucket_name") or p["raw"],
                        "provider": p["provider"],
                        "status": p["status"],
                        "http_status": p.get("http_status"),
                        "url": p.get("probe_url"),
                        "details": p.get("details", "")
                    }
                    for p in probed_cloud_assets
                ],
                "cloud_assets_count": len(probed_cloud_assets),
                "cloud_open_count": sum(1 for p in probed_cloud_assets if p.get("is_open")),
                "cloud_takeover_count": sum(1 for p in probed_cloud_assets if p.get("is_takeover")),
                "cloud_secured_count": sum(1 for p in probed_cloud_assets if p.get("is_secured")),
                "extracted_endpoints": sorted(
                    list(all_endpoints.values()),
                    key=lambda x: (not x.get("is_in_scope", False), x.get("url", ""))
                )[:500],
                "extracted_secrets": all_secrets[:200],
                "extracted_secrets_count": len(all_secrets),
                "extracted_jwts": list(all_jwts.values())[:50],
                "jwt_count": len(all_jwts),
                "extracted_base64": list(all_base64.values())[:100],
                "base64_count": len(all_base64),
                "sourcemaps": all_sourcemaps,
                "api_specifications": (api_res.get("openapi_specs") if api_res else []) or [],
                "api_ui_endpoints": (api_res.get("api_ui_endpoints") if api_res else []) or [],
                "graphql_endpoints": (api_res.get("graphql_endpoints") if api_res else []) or [],
                "api_discovered_routes": (api_res.get("discovered_routes") if api_res else []) or []
            }

            # Attach findings to the specific web application entry in web_applications
            webapp_set = {"web_applications.$.dynamic_js": recon_summary}
            if probed_cloud_assets:
                webapp_set["web_applications.$.cloud_assets"] = [
                    {
                        "name": p.get("bucket_name") or p["raw"],
                        "raw": p["raw"],
                        "url": p.get("probe_url") or f"https://{p['raw']}",
                        "provider": p["provider"],
                        "status": p["status"],
                        "http_status": p.get("http_status"),
                        "details": p.get("details", "")
                    }
                    for p in probed_cloud_assets
                ]
            res = await self.domains_col.update_one(
                {"domain": root_domain, "web_applications.target": target},
                {"$set": webapp_set}
            )
            if res.matched_count == 0:
                # If target was not found by exact web_applications.target, try by URL hostname
                res2 = await self.domains_col.update_one(
                    {"domain": root_domain, "web_applications.url": {"$regex": f"://{re.escape(target)}(/|$|:)"}},
                    {"$set": webapp_set}
                )
                if res2.matched_count == 0:
                    # Push as a web application entry so findings are strictly preserved on this specific target
                    new_app = {
                        "target": target,
                        "url": target_url,
                        "dynamic_js": recon_summary
                    }
                    if probed_cloud_assets:
                        new_app["cloud_assets"] = webapp_set.get("web_applications.$.cloud_assets", [])
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$push": {"web_applications": new_app}}
                    )

            # Store in domain-level document ONLY if the scanned target was the root domain itself
            if target.strip().lower() == root_domain.strip().lower():
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {
                        "infrastructure.dynamic_js": recon_summary,
                        "dynamic_js": recon_summary
                    }}
                )

            # Store any discovered API specs and GraphQL endpoints at the domain level for fast querying
            if api_res and (api_res.get("openapi_specs") or api_res.get("graphql_endpoints") or api_res.get("api_ui_endpoints")):
                add_to_set = {}
                if api_res.get("openapi_specs"):
                    add_to_set["api_specifications"] = {"$each": api_res["openapi_specs"]}
                if api_res.get("graphql_endpoints"):
                    add_to_set["graphql_endpoints"] = {"$each": api_res["graphql_endpoints"]}
                if api_res.get("api_ui_endpoints"):
                    add_to_set["api_ui_endpoints"] = {"$each": api_res["api_ui_endpoints"]}
                if add_to_set:
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$addToSet": add_to_set}
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
