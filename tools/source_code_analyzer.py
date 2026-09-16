import os
import sys
import re
import json
import base64
import logging
import asyncio
import argparse
from typing import Dict, List, Optional, Any, Set
from bson import ObjectId

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger
from source_map_unpacker import is_application_source

# Extensions suitable for static code inspection
SCANNABLE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".json", ".html", ".env", ".yml", ".yaml"
}

# Ignore file paths that are purely build artifacts or translation bundles
EXCLUDED_SUBSTRINGS = [
    "/locale/", "/locales/", "/i18n/", ".min.js", "moment/locale",
    "/coverage/", "/.git/", "package-lock.json"
]

class SourceCodeAnalyzer(BaseAgent):
    """
    Static code analyzer that parses recovered source code trees to detect:
    - Backend API endpoints and HTTP methods
    - Client-side Single Page Application (SPA) routes
    - External service hostnames and URLs
    - WebSocket and realtime connection endpoints
    - Sensitive credentials, API keys, tokens, and cloud storage references (mirroring dynamic_js_collector)
    """
    def __init__(self):
        super().__init__("source_code_analyzer", "Source Code Route & Secret Analyzer")
        self.source_maps_col = self.db["recovered_source_maps"]

        # High-confidence credential and secret patterns (aligned with dynamic_js_collector)
        self.secret_patterns = {
            "Google API Key": re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b'),
            "AWS Access Key": re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
            "AWS Secret Key": re.compile(r'(?i)(?:aws_secret_access_key|aws_secret_key|secret[_-]?access[_-]?key|aws_sec(?:ret)?|secret[_-]?key)[\s:=\x22\x27\`]+([A-Za-z0-9/+=]{40})(?:[^\w/+=]|$)'),
            "JWT Token": re.compile(r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b'),
            "Bearer Token": re.compile(r'\bBearer\s+[A-Za-z0-9-._~+/]+=*\b'),
            "Stripe Key": re.compile(r'\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b'),
            "Firebase Key": re.compile(r'\b[a-zA-Z0-9]{40}:APA91b[a-zA-Z0-9-_]{134}\b'),
            "Slack Webhook": re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'),
            "GitHub Token": re.compile(r'\bgh[opsu]_[0-9a-zA-Z]{36}\b'),
            "SSH Private Key": re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
            "Generic API Key": re.compile(r'(?i)(?:api[_-]?key|apikey|app[_-]?key)[\s:=\x22\x27\`]+([A-Za-z0-9_\-]{16,})'),
            "Generic Secret/Token": re.compile(r'(?i)(?:client[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?token|private[_-]?key)[\s:=\x22\x27\`]+([A-Za-z0-9_\-\.]{16,})'),
            "Hardcoded Password": re.compile(r'(?i)(?:db[_-]?password|database[_-]?password|root[_-]?password|admin[_-]?password)[\s:=\x22\x27\`]+([^\s\x22\x27\`]{6,})'),
        }

        # Comprehensive cloud storage asset patterns
        self.cloud_patterns = [
            {"provider": "AWS S3", "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.s3(?:[.-][a-zA-Z0-9\-]+)?\.amazonaws\.com\b', re.IGNORECASE)},
            {"provider": "Google Cloud Storage", "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.storage\.googleapis\.com\b', re.IGNORECASE)},
            {"provider": "Azure Blob", "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.blob\.core\.windows\.net\b', re.IGNORECASE)},
            {"provider": "Firebase DB", "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.firebaseio\.com\b', re.IGNORECASE)},
            {"provider": "DigitalOcean Spaces", "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.([a-z0-9\-]+)\.digitaloceanspaces\.com\b', re.IGNORECASE)},
            {"provider": "Cloudflare R2", "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.r2\.cloudflarestorage\.com\b', re.IGNORECASE)},
            {"provider": "AWS CloudFront", "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.cloudfront\.net\b', re.IGNORECASE)}
        ]

    @staticmethod
    def decode_jwt(jwt_str: str) -> dict:
        """
        Decode header and payload of a JWT token using base64url.
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
                result["error"] = f"Payload decode error: {e}"

        return result

    def is_scannable_file(self, rel_path: str) -> bool:
        _, ext = os.path.splitext(rel_path.lower())
        if ext not in SCANNABLE_EXTENSIONS:
            return False
        for excl in EXCLUDED_SUBSTRINGS:
            if excl in rel_path.lower():
                return False
        return True

    def extract_routes_from_file(self, file_path: str, rel_path: str, target: str) -> List[Dict[str, Any]]:
        """
        Analyze an individual file and return discovered routes and endpoints.
        """
        findings = []
        is_app = is_application_source(rel_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            logger.debug(f"Error reading {file_path} for route analysis: {e}")
            return findings

        re_react_route = re.compile(r'path\s*=\s*[\'"`]([^\'"`]+)[\'"`]')
        re_route_obj = re.compile(r'path\s*:\s*[\'"`]([^\'"`]+)[\'"`]')
        re_router_push = re.compile(r'(?:push|navigate|replace)\(\s*[\'"`](/[^\'"`]+)[\'"`]')

        re_api_path = re.compile(r'[\'"`](/(?:api|v[0-9]+|rest|graphql|oauth|auth)/[^\'"`\s]+)[\'"`]')
        re_template_api = re.compile(r'`(?:\$\{[^}]+\})?(/(?:api|v[0-9]+|rest|graphql|oauth|auth)/[^`\s]+)`')
        re_endpoint_const = re.compile(r'const\s+[A-Z0-9_]*ENDPOINT\s*=\s*[`\'"]([^\'"`]+)[`\'"]')

        re_http_client = re.compile(
            r'(?:axios|http|\$http|request|client|api)\.(get|post|put|delete|patch|options|head)\s*\(\s*(?:[^,\)]*,\s*)?[\'"`]([^\'"`]+)[\'"`]',
            re.IGNORECASE
        )
        re_fetch_call = re.compile(r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]')

        re_external_url = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\'"\s`<>)]*)?')
        re_websocket = re.compile(r'[\'"`](wss?://[^\'"`\s]+)[\'"`]')

        seen_in_file: Set[str] = set()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            snippet = stripped[:160]

            # --- Check Client Routes ---
            for m in re_react_route.finditer(line):
                path = m.group(1).strip()
                if path and path not in {"*", "/"}:
                    key = f"CLIENT_ROUTE:{path}"
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        findings.append({
                            "category": "client_route",
                            "method": "ROUTE",
                            "path": path,
                            "file": rel_path,
                            "line": line_num,
                            "snippet": snippet,
                            "is_app": is_app,
                            "target_url": f"https://{target}{path if path.startswith('/') else '/' + path}"
                        })

            for m in re_route_obj.finditer(line):
                path = m.group(1).strip()
                if path and path.startswith("/") and len(path) > 1:
                    key = f"CLIENT_ROUTE:{path}"
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        findings.append({
                            "category": "client_route",
                            "method": "ROUTE",
                            "path": path,
                            "file": rel_path,
                            "line": line_num,
                            "snippet": snippet,
                            "is_app": is_app,
                            "target_url": f"https://{target}{path}"
                        })

            for m in re_router_push.finditer(line):
                path = m.group(1).strip()
                if path and not path.startswith("//"):
                    clean_p = re.sub(r'\$\{[^}]+\}', ':param', path)
                    key = f"CLIENT_ROUTE:{clean_p}"
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        findings.append({
                            "category": "client_route",
                            "method": "NAVIGATE",
                            "path": clean_p,
                            "file": rel_path,
                            "line": line_num,
                            "snippet": snippet,
                            "is_app": is_app,
                            "target_url": f"https://{target}{clean_p}"
                        })

            # --- Check API Endpoints ---
            for m in re_api_path.finditer(line):
                path = m.group(1).strip()
                method = "GET"
                for verb in ["post", "put", "delete", "patch"]:
                    if verb in line.lower():
                        method = verb.upper()
                        break
                clean_p = re.sub(r'\$\{[^}]+\}', ':param', path)
                key = f"API:{method}:{clean_p}"
                if key not in seen_in_file:
                    seen_in_file.add(key)
                    findings.append({
                        "category": "api_endpoint",
                        "method": method,
                        "path": clean_p,
                        "file": rel_path,
                        "line": line_num,
                        "snippet": snippet,
                        "is_app": is_app,
                        "target_url": f"https://{target}{clean_p}"
                    })

            for m in re_template_api.finditer(line):
                path = m.group(1).strip()
                clean_p = re.sub(r'\$\{[^}]+\}', ':param', path)
                key = f"API:TEMPLATE:{clean_p}"
                if key not in seen_in_file:
                    seen_in_file.add(key)
                    findings.append({
                        "category": "api_endpoint",
                        "method": "API",
                        "path": clean_p,
                        "file": rel_path,
                        "line": line_num,
                        "snippet": snippet,
                        "is_app": is_app,
                        "target_url": f"https://{target}{clean_p}"
                    })

            for m in re_endpoint_const.finditer(line):
                val = m.group(1).strip()
                clean_val = re.sub(r'\$\{[^}]+\}', '', val)
                if clean_val.startswith("/"):
                    path = clean_val
                elif "://" in clean_val:
                    path = clean_val
                else:
                    path = f"/{clean_val}"
                key = f"ENDPOINT_CONST:{path}"
                if key not in seen_in_file and len(path) > 2:
                    seen_in_file.add(key)
                    cat = "external_url" if "://" in path else "api_endpoint"
                    findings.append({
                        "category": cat,
                        "method": "CONST",
                        "path": path,
                        "file": rel_path,
                        "line": line_num,
                        "snippet": snippet,
                        "is_app": is_app,
                        "target_url": path if "://" in path else f"https://{target}{path}"
                    })

            # --- Check HTTP Client calls ---
            for m in re_http_client.finditer(line):
                method = m.group(1).upper()
                raw_path = m.group(2).strip()
                if raw_path and not raw_path.endswith((".png", ".jpg", ".svg", ".css", ".ico")):
                    clean_p = re.sub(r'\$\{[^}]+\}', ':param', raw_path)
                    key = f"HTTP_CLIENT:{method}:{clean_p}"
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        cat = "external_url" if "://" in clean_p else "api_endpoint"
                        findings.append({
                            "category": cat,
                            "method": method,
                            "path": clean_p,
                            "file": rel_path,
                            "line": line_num,
                            "snippet": snippet,
                            "is_app": is_app,
                            "target_url": clean_p if "://" in clean_p else f"https://{target}{clean_p if clean_p.startswith('/') else '/' + clean_p}"
                        })

            for m in re_fetch_call.finditer(line):
                raw_path = m.group(1).strip()
                if raw_path and raw_path.startswith("/") and not raw_path.endswith((".png", ".jpg", ".svg", ".css", ".ico")):
                    clean_p = re.sub(r'\$\{[^}]+\}', ':param', raw_path)
                    key = f"FETCH:GET:{clean_p}"
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        findings.append({
                            "category": "api_endpoint",
                            "method": "FETCH",
                            "path": clean_p,
                            "file": rel_path,
                            "line": line_num,
                            "snippet": snippet,
                            "is_app": is_app,
                            "target_url": f"https://{target}{clean_p}"
                        })

            # --- Check External URLs ---
            for m in re_external_url.finditer(line):
                ext_url = m.group(0).rstrip("'\";,)>`")
                ignore_domains = [
                    "w3.org", "schema.org", "github.com", "npmjs.com",
                    "reactjs.org", "google.com/recaptcha", "sentry.io",
                    "unpkg.com", "jsdelivr.net", "cloudflare.com", "mozilla.org"
                ]
                if any(ign in ext_url.lower() for ign in ignore_domains):
                    continue
                if target and target.lower() in ext_url.lower():
                    continue

                key = f"EXT:{ext_url}"
                if key not in seen_in_file:
                    seen_in_file.add(key)
                    findings.append({
                        "category": "external_url",
                        "method": "EXTERNAL",
                        "path": ext_url,
                        "file": rel_path,
                        "line": line_num,
                        "snippet": snippet,
                        "is_app": is_app,
                        "target_url": ext_url
                    })

            # --- Check WebSockets ---
            for m in re_websocket.finditer(line):
                ws_url = m.group(1).strip()
                key = f"WS:{ws_url}"
                if key not in seen_in_file:
                    seen_in_file.add(key)
                    findings.append({
                        "category": "websocket",
                        "method": "WS",
                        "path": ws_url,
                        "file": rel_path,
                        "line": line_num,
                        "snippet": snippet,
                        "is_app": is_app,
                        "target_url": ws_url
                    })

        return findings

    def extract_secrets_from_file(self, file_path: str, rel_path: str, target: str) -> List[Dict[str, Any]]:
        """
        Analyze an individual file and return discovered secrets, credentials, tokens, and cloud assets.
        """
        secrets = []
        is_app = is_application_source(rel_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            logger.debug(f"Error reading {file_path} for secret analysis: {e}")
            return secrets

        # Known placeholder / sample values to skip
        placeholder_terms = [
            "your_api_key", "your-api-key", "my_api_key", "xxxxxx", "abcdef",
            "123456789", "00000000", "placeholder", "fake_key", "dummy_key",
            "example.com", "test_key", "sample_key", "your_token", "change_me"
        ]

        seen_secrets_in_file: Set[str] = set()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            snippet = stripped[:180]

            # 1. Standard Secret Patterns
            for stype, pattern in self.secret_patterns.items():
                for m in pattern.finditer(line):
                    # Handle groups if regex has capturing group, else full match
                    val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    val = val.strip().strip("'\"`")
                    if not val or len(val) < 6:
                        continue

                    # Filter out placeholders
                    if any(ph in val.lower() for ph in placeholder_terms):
                        continue

                    # For JWT: inspect claims
                    details = None
                    if stype == "JWT Token":
                        try:
                            decoded = self.decode_jwt(val)
                            details = {
                                "header": decoded.get("header"),
                                "payload": decoded.get("payload")
                            }
                        except Exception:
                            pass

                    dedup_key = f"{stype}:{val}"
                    if dedup_key not in seen_secrets_in_file:
                        seen_secrets_in_file.add(dedup_key)
                        secrets.append({
                            "type": stype,
                            "value": val,
                            "file": rel_path,
                            "line": line_num,
                            "snippet": snippet,
                            "is_app": is_app,
                            "details": details
                        })

            # 2. Cloud Storage Reference Patterns
            for cloud in self.cloud_patterns:
                for m in cloud["pattern"].finditer(line):
                    raw_match = m.group(0).strip().strip("'\"`")
                    bucket_name = m.group(1) if m.lastindex and m.lastindex >= 1 else raw_match
                    
                    if not bucket_name or any(ph in bucket_name.lower() for ph in placeholder_terms):
                        continue

                    dedup_key = f"CLOUD:{cloud['provider']}:{bucket_name}"
                    if dedup_key not in seen_secrets_in_file:
                        seen_secrets_in_file.add(dedup_key)
                        secrets.append({
                            "type": f"Cloud Asset ({cloud['provider']})",
                            "value": raw_match,
                            "file": rel_path,
                            "line": line_num,
                            "snippet": snippet,
                            "is_app": is_app,
                            "details": {"provider": cloud["provider"], "bucket": bucket_name}
                        })

        return secrets

    def analyze_source_tree(self, src_dir: str, target: str) -> Dict[str, Any]:
        """
        Walk all files in the extracted directory and aggregate discovered routes and secrets.
        """
        all_routes = []
        all_secrets = []

        if not os.path.exists(src_dir):
            logger.warning(f"Source directory does not exist: {src_dir}")
            return {
                "routes": [],
                "stats": {"total": 0, "api_endpoints": 0, "client_routes": 0, "external_urls": 0},
                "secrets": [],
                "secrets_stats": {"total": 0, "by_type": {}, "app_secrets_count": 0}
            }

        for root, _, files in os.walk(src_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, src_dir).replace("\\", "/")

                if not self.is_scannable_file(rel_path):
                    continue

                # 1. Extract Routes
                file_routes = self.extract_routes_from_file(full_path, rel_path, target)
                all_routes.extend(file_routes)

                # 2. Extract Secrets & Credentials
                file_secrets = self.extract_secrets_from_file(full_path, rel_path, target)
                all_secrets.extend(file_secrets)

        # Deduplicate and sort routes
        deduped_routes = {}
        for item in all_routes:
            dedup_key = f"{item['category']}:{item['method']}:{item['path']}"
            if dedup_key not in deduped_routes:
                deduped_routes[dedup_key] = item
            else:
                if item["is_app"] and not deduped_routes[dedup_key]["is_app"]:
                    deduped_routes[dedup_key] = item

        routes = list(deduped_routes.values())
        routes.sort(key=lambda x: (not x["is_app"], x["category"], x["path"].lower()))

        api_count = sum(1 for r in routes if r["category"] == "api_endpoint")
        client_count = sum(1 for r in routes if r["category"] == "client_route")
        external_count = sum(1 for r in routes if r["category"] == "external_url")
        ws_count = sum(1 for r in routes if r["category"] == "websocket")

        # Deduplicate and sort secrets
        deduped_secrets = {}
        for s in all_secrets:
            s_key = f"{s['type']}:{s['value']}"
            if s_key not in deduped_secrets:
                deduped_secrets[s_key] = s
            else:
                if s["is_app"] and not deduped_secrets[s_key]["is_app"]:
                    deduped_secrets[s_key] = s

        secrets = list(deduped_secrets.values())
        secrets.sort(key=lambda x: (not x["is_app"], x["type"], x["file"].lower(), x["line"]))

        secrets_by_type = {}
        for s in secrets:
            t = s["type"]
            secrets_by_type[t] = secrets_by_type.get(t, 0) + 1

        return {
            "routes": routes,
            "stats": {
                "total": len(routes),
                "api_endpoints": api_count,
                "client_routes": client_count,
                "external_urls": external_count,
                "websocket_endpoints": ws_count,
                "app_routes_count": sum(1 for r in routes if r["is_app"])
            },
            "secrets": secrets,
            "secrets_stats": {
                "total": len(secrets),
                "by_type": secrets_by_type,
                "app_secrets_count": sum(1 for s in secrets if s["is_app"])
            }
        }

    async def analyze_source_map_doc(self, sm_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze an existing recovered source map record in MongoDB and persist findings.
        """
        map_id = sm_doc["_id"]
        target = sm_doc.get("target") or "unknown_target"
        src_dir = sm_doc.get("src_dir") or os.path.join(sm_doc.get("disk_dir", ""), "extracted")

        logger.info(f"Analyzing recovered source tree for {target} at {src_dir}...")
        analysis = self.analyze_source_tree(src_dir, target)

        update_payload = {
            "routes_analysis": analysis["routes"],
            "routes_stats": analysis["stats"],
            "routes_count": analysis["stats"]["total"],
            "api_endpoints_count": analysis["stats"]["api_endpoints"],
            "client_routes_count": analysis["stats"]["client_routes"],
            "secrets_analysis": analysis.get("secrets", []),
            "secrets_stats": analysis.get("secrets_stats", {}),
            "secrets_count": analysis.get("secrets_stats", {}).get("total", 0),
            "analyzed_at": asyncio.get_event_loop().time()
        }

        await self.source_maps_col.update_one(
            {"_id": map_id if isinstance(map_id, ObjectId) else ObjectId(map_id)},
            {"$set": update_payload}
        )

        try:
            await self.db["domains"].update_many(
                {"domain": target, "web_applications.recovered_source_maps.id": str(map_id)},
                {"$set": {
                    "web_applications.$[elem].routes_count": analysis["stats"]["total"],
                    "web_applications.$[elem].api_endpoints_count": analysis["stats"]["api_endpoints"],
                    "web_applications.$[elem].secrets_count": analysis["secrets_stats"]["total"]
                }},
                array_filters=[{"elem.recovered_source_maps.id": str(map_id)}]
            )
        except Exception as dom_err:
            logger.debug(f"Domain update notice for {target}: {dom_err}")

        # Update matching leads with route and secret statistics
        try:
            await self.leads_col.update_many(
                {"recovered_source_map_id": str(map_id)},
                {"$set": {
                    "source_map_routes_count": analysis["stats"]["total"],
                    "source_map_api_endpoints_count": analysis["stats"]["api_endpoints"],
                    "source_map_secrets_count": analysis["secrets_stats"]["total"]
                }}
            )
        except Exception as lead_err:
            logger.debug(f"Lead update notice for {target}: {lead_err}")

        logger.info(
            f"Analysis complete for {target}: {analysis['stats']['total']} routes, "
            f"{analysis['secrets_stats']['total']} secrets/credentials discovered!"
        )
        return analysis

    async def analyze_all_source_maps(self) -> Dict[str, int]:
        """
        Iterate over all recovered source maps in MongoDB and run route + secret analysis.
        """
        cursor = self.source_maps_col.find({})
        total = 0
        analyzed = 0
        async for doc in cursor:
            total += 1
            try:
                await self.analyze_source_map_doc(doc)
                analyzed += 1
            except Exception as err:
                logger.error(f"Failed to analyze source map {doc.get('_id')}: {err}")
        return {"total": total, "analyzed": analyzed}


async def main():
    parser = argparse.ArgumentParser(description="Analyze recovered source maps for routes, APIs, and secrets.")
    parser.add_argument("--all", action="store_true", help="Analyze all recovered source maps in database")
    parser.add_argument("--map-id", type=str, help="Specific source map ObjectId to analyze")
    parser.add_argument("--target", type=str, help="Target domain name to filter by")
    args = parser.parse_args()

    analyzer = SourceCodeAnalyzer()

    if args.all:
        logger.info("Starting batch route and secret analysis for all recovered source maps...")
        res = await analyzer.analyze_all_source_maps()
        logger.info(f"Batch analysis completed: {res['analyzed']}/{res['total']} analyzed successfully.")
    elif args.map_id:
        doc = await analyzer.source_maps_col.find_one({"_id": ObjectId(args.map_id)})
        if not doc:
            logger.error(f"Source map not found for ID: {args.map_id}")
            return
        await analyzer.analyze_source_map_doc(doc)
    elif args.target:
        cursor = analyzer.source_maps_col.find({"target": args.target})
        count = 0
        async for doc in cursor:
            await analyzer.analyze_source_map_doc(doc)
            count += 1
        logger.info(f"Analyzed {count} source maps for target {args.target}")
    else:
        parser.print_help()

if __name__ == "__main__":
    asyncio.run(main())
