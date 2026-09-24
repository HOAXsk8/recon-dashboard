import os
import sys
import json
import re
import zipfile
import hashlib
import datetime
import logging
import asyncio
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any, Set

import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger

# Directory where recovered source trees are unpacked
DEFAULT_OUTPUT_DIR = os.environ.get("RECOVERED_SOURCES_DIR", "/app/recovered_sources")

LANGUAGE_EXTENSIONS = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "vue",
    ".json": "json",
    ".css": "css",
    ".scss": "scss",
    ".sass": "sass",
    ".less": "less",
    ".html": "html",
    ".htm": "html",
    ".svg": "xml",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".md": "markdown",
    ".env": "config",
    ".sql": "sql",
    ".graphql": "graphql",
    ".gql": "graphql"
}

def detect_language(filepath: str) -> str:
    """Determine syntax highlighting language from file extension."""
    _, ext = os.path.splitext(filepath.lower())
    return LANGUAGE_EXTENSIONS.get(ext, "text")

def clean_source_path(raw_path: str) -> str:
    """
    Sanitize and normalize paths found inside source map `sources` array.
    Strips protocol prefixes, webpack namespaces, turbopack prefixes, and relative traversal.
    """
    if not raw_path:
        return "unknown_file.js"

    # Replace backslashes
    path = raw_path.replace("\\", "/")

    # Strip query strings or hashes
    if "?" in path:
        path = path.split("?")[0]
    if "#" in path:
        path = path.split("#")[0]

    # Remove known bundler protocol/namespace prefixes
    prefixes_to_strip = [
        "webpack://_N_E/",
        "webpack:///",
        "webpack://",
        "turbopack:///",
        "turbopack://",
        "vite:///",
        "vite://",
        "meteor:///",
        "meteor://",
        "file:///",
        "file://",
        "ng:///",
        "ng://",
    ]
    for prefix in prefixes_to_strip:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    # If it was an absolute URL like https://domain.com/foo/bar.js, strip the protocol
    if "://" in path:
        try:
            parsed = urllib.parse.urlparse(path)
            path = f"{parsed.netloc}{parsed.path}"
        except Exception:
            path = re.sub(r'^[a-zA-Z]+://', '', path)

    # Strip leading dot-slashes and relative traversals
    while path.startswith("./") or path.startswith("/"):
        path = path.lstrip("./").lstrip("/")

    # Replace leading ../ sequences
    path = re.sub(r'^(\.\./)+', '', path)
    path = re.sub(r'/\.\./', '/', path)

    # Sanitize invalid characters
    path = re.sub(r'[:*?"<>|]', '_', path)

    # If empty after sanitization, fallback
    if not path or path == ".":
        path = "index.js"

    return path

def is_application_source(cleaned_path: str) -> bool:
    """
    Determine if a file is proprietary application code versus third-party vendor code.
    """
    lower = cleaned_path.lower()
    vendor_indicators = [
        "node_modules/",
        "webpack/runtime",
        "webpack/bootstrap",
        "[external]",
        "vendor/",
        "packages/vendor/",
        "bower_components/",
        "~/",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "unpkg.com"
    ]
    for ind in vendor_indicators:
        if ind in lower:
            return False
    return True


class SourceMapUnpacker(BaseAgent):
    def __init__(self, output_dir: str = DEFAULT_OUTPUT_DIR):
        super().__init__("source_map_unpacker", "Source Map Recovery Agent")
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.source_maps_col = self.db["recovered_source_maps"]
        self.last_error: Optional[str] = None

    async def fetch_source_map_content(self, url: str) -> Optional[dict]:
        """
        Download and parse the source map JSON payload.
        Handles Brotli/gzip/deflate, XSSI prefixes, and redirects.
        """
        self.last_error = None
        url = url.strip().rstrip(".,;:)'\"")
        has_brotli = False
        try:
            import brotli
            has_brotli = True
        except ImportError:
            pass

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br" if has_brotli else "gzip, deflate"
        }
        
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=35.0) as client:
            try:
                logger.info(f"Fetching source map from: {url}")
                resp = await client.get(url, headers=headers)
                if resp.status_code == 403:
                    self.last_error = f"HTTP 403 Forbidden: The remote host or CDN (e.g. Vercel/Cloudflare) actively blocks public access to this source map file."
                    logger.warning(f"HTTP 403 Forbidden fetching source map from {url}")
                    return None
                elif resp.status_code == 404:
                    self.last_error = f"HTTP 404 Not Found: The source map file does not exist on the remote server."
                    logger.warning(f"HTTP 404 Not Found fetching source map from {url}")
                    return None
                elif resp.status_code != 200:
                    self.last_error = f"HTTP {resp.status_code} Error: Server responded with status code {resp.status_code}."
                    logger.warning(f"HTTP {resp.status_code} fetching source map from {url}")
                    return None
                
                content_encoding = resp.headers.get("content-encoding", "").lower()
                text = ""
                # Attempt manual Brotli decompression if needed
                if content_encoding == "br" and has_brotli:
                    try:
                        import brotli
                        text = brotli.decompress(resp.content).decode("utf-8", errors="replace")
                    except Exception:
                        text = resp.text
                else:
                    text = resp.text

                if not text:
                    self.last_error = "Remote server returned an empty response body."
                    logger.warning(f"Empty response body for source map: {url}")
                    return None
                
                # Strip XSSI prefixes if present, e.g. )]}', or )]}'
                clean_text = text.strip()
                if clean_text.startswith(")]}',") or clean_text.startswith(")]}'"):
                    clean_text = re.sub(r"^\)]}'?,?", "", clean_text).strip()
                
                # Parse JSON
                try:
                    data = json.loads(clean_text)
                    if isinstance(data, dict) and ("sources" in data or "sections" in data):
                        return data
                    else:
                        self.last_error = "Invalid source map format: payload does not contain a 'sources' or 'sections' array."
                        logger.warning(f"Invalid source map structure for {url}")
                        return None
                except json.JSONDecodeError as err:
                    self.last_error = f"JSON decode failed: {err}"
                    logger.error(f"JSON decode failed for {url}: {err}")
                    return None
            except httpx.ConnectTimeout:
                self.last_error = "Connection timed out while connecting to remote host."
                logger.error(f"Connect timeout fetching source map {url}")
                return None
            except Exception as e:
                self.last_error = f"Network/Request error: {str(e)}"
                logger.error(f"Network error fetching source map {url}: {e}")
                return None

    async def unpack_url(self, source_map_url: str, target: Optional[str] = None, lead_id: Optional[str] = None) -> Optional[dict]:
        """
        Main entry point to recover, extract, and index a source map.
        """
        if not target:
            try:
                target = urllib.parse.urlparse(source_map_url).hostname or "unknown_target"
            except Exception:
                target = "unknown_target"

        clean_target = re.sub(r'[^a-zA-Z0-9_.-]', '_', target)
        url_hash = hashlib.md5(source_map_url.encode("utf-8")).hexdigest()[:10]
        
        # Check if already unpacked in database
        existing = await self.source_maps_col.find_one({"source_map_url": source_map_url})
        if existing and existing.get("total_files", 0) > 0 and os.path.exists(existing.get("disk_dir", "")):
            logger.info(f"Source map already recovered for {source_map_url} (ID: {existing['_id']})")
            # Ensure lead is linked if lead_id was provided
            if lead_id:
                await self._link_to_lead(lead_id, str(existing["_id"]), existing)
            return existing

        data = await self.fetch_source_map_content(source_map_url)
        if not data:
            return None

        # Extract map filename
        map_filename = os.path.basename(urllib.parse.urlparse(source_map_url).path) or "bundle.js.map"
        clean_map_slug = re.sub(r'[^a-zA-Z0-9_.-]', '_', map_filename.replace(".map", ""))
        
        target_dir = os.path.join(self.output_dir, clean_target, f"{clean_map_slug}_{url_hash}")
        src_dir = os.path.join(target_dir, "extracted")
        os.makedirs(src_dir, exist_ok=True)

        sources = data.get("sources", [])
        sources_content = data.get("sourcesContent", []) or []

        # Some source maps use `sections` (indexed source maps)
        if not sources and "sections" in data:
            sources = []
            sources_content = []
            for section in data.get("sections", []):
                sec_map = section.get("map", {})
                sec_sources = sec_map.get("sources", [])
                sec_content = sec_map.get("sourcesContent", []) or []
                sources.extend(sec_sources)
                sources_content.extend(sec_content)

        total_sources = len(sources)
        if total_sources == 0:
            logger.warning(f"No sources defined in source map: {source_map_url}")
            return None

        file_tree = []
        cached_files = {} # Store top readable application files in MongoDB for instant preview
        languages_detected = set()
        app_files_count = 0
        vendor_files_count = 0
        written_paths = set()

        for idx, raw_path in enumerate(sources):
            clean_path = clean_source_path(raw_path)
            content = sources_content[idx] if idx < len(sources_content) else None
            
            # If no sourcesContent was provided, we still have the file path name
            if content is None:
                content = f"// [Source Map Info: Original source content not embedded for {raw_path}]\n"

            is_app = is_application_source(clean_path)
            if is_app:
                app_files_count += 1
            else:
                vendor_files_count += 1

            lang = detect_language(clean_path)
            if is_app and lang != "text":
                languages_detected.add(lang)

            # Avoid collisions
            unique_clean_path = clean_path
            counter = 1
            while unique_clean_path in written_paths:
                base, ext = os.path.splitext(clean_path)
                unique_clean_path = f"{base}_{counter}{ext}"
                counter += 1
            written_paths.add(unique_clean_path)

            # Write file to disk
            disk_filepath = os.path.join(src_dir, unique_clean_path)
            try:
                os.makedirs(os.path.dirname(disk_filepath), exist_ok=True)
                with open(disk_filepath, "w", encoding="utf-8", errors="replace") as f:
                    f.write(content)
            except Exception as write_err:
                logger.debug(f"Failed to write extracted file {unique_clean_path}: {write_err}")

            file_size = len(content.encode("utf-8"))
            lines_count = content.count("\n") + 1

            file_tree.append({
                "path": unique_clean_path,
                "size": file_size,
                "lines": lines_count,
                "language": lang,
                "is_app": is_app,
                "preview": content[:200]
            })

            # Cache first 60 application source files under 100KB in database for ultra-fast instant view
            if is_app and len(cached_files) < 60 and file_size < 100 * 1024:
                cached_files[unique_clean_path] = content

        # Create a downloadable .zip archive of the extracted source code
        zip_path = os.path.join(target_dir, f"{clean_map_slug}_recovered.zip")
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(src_dir):
                    for file in files:
                        full_p = os.path.join(root, file)
                        rel_p = os.path.relpath(full_p, src_dir)
                        zipf.write(full_p, arcname=rel_p)
            zip_size = os.path.getsize(zip_path)
        except Exception as zip_err:
            logger.error(f"Error packaging ZIP for {source_map_url}: {zip_err}")
            zip_size = 0

        # Sort file tree: application files first, then alphabetical
        file_tree.sort(key=lambda x: (not x["is_app"], x["path"].lower()))

        now_str = datetime.datetime.utcnow().isoformat()
        record = {
            "target": target,
            "source_map_url": source_map_url,
            "map_name": map_filename,
            "total_files": total_sources,
            "app_files_count": app_files_count,
            "vendor_files_count": vendor_files_count,
            "has_embedded_source": len(sources_content) > 0,
            "languages": sorted(list(languages_detected)),
            "recovered_at": now_str,
            "disk_dir": target_dir,
            "src_dir": src_dir,
            "zip_path": zip_path,
            "zip_size": zip_size,
            "file_tree": file_tree,
            "cached_files": cached_files
        }

        domain_doc = await self.get_root_domain_for_target(target)
        if domain_doc and domain_doc.get("workspace_id"):
            record["workspace_id"] = str(domain_doc["workspace_id"])

        result = await self.source_maps_col.update_one(
            {"source_map_url": source_map_url},
            {"$set": record},
            upsert=True
        )
        record_id = str(result.upserted_id or (await self.source_maps_col.find_one({"source_map_url": source_map_url}))["_id"])
        record["_id"] = record_id

        logger.info(
            f"Successfully recovered source map for {target} -> "
            f"{total_sources} files ({app_files_count} app source, {vendor_files_count} vendor) | ZIP: {zip_size}B"
        )

        # Automatically analyze source code for API endpoints, client routes, and external URLs
        try:
            from source_code_analyzer import SourceCodeAnalyzer
            analyzer = SourceCodeAnalyzer()
            analysis = await analyzer.analyze_source_map_doc(record)
            record["routes_analysis"] = analysis["routes"]
            record["routes_stats"] = analysis["stats"]
            record["routes_count"] = analysis["stats"]["total"]
            record["api_endpoints_count"] = analysis["stats"]["api_endpoints"]
            record["client_routes_count"] = analysis["stats"]["client_routes"]
        except Exception as analyze_err:
            logger.error(f"Error analyzing routes for {target}: {analyze_err}")

        # 1. Update matching alerts in leads collection
        await self._link_to_lead(lead_id, record_id, record)

        # 2. Update web_applications overview in domains collection
        await self._update_domain_web_apps(target, record_id, record)

        return record

    async def _link_to_lead(self, lead_id: Optional[str], record_id: str, record: dict):
        """Link the recovered source map to corresponding lead document(s)."""
        from bson import ObjectId
        escaped_url = re.escape(record.get("source_map_url", ""))
        or_clauses = [
            {"details": {"$regex": escaped_url}},
            {"description": {"$regex": escaped_url}}
        ]
        if lead_id:
            try:
                or_clauses.append({"_id": ObjectId(lead_id)})
            except Exception:
                pass
        
        target = record.get("target")
        if target:
            or_clauses.append({
                "target": target,
                "title": {"$regex": "Source Map", "$options": "i"}
            })

        update_fields = {
            "recovered_source_map_id": record_id,
            "source_map_files_count": record.get("total_files", 0),
            "source_map_app_files_count": record.get("app_files_count", 0),
            "source_map_languages": record.get("languages", []),
            "source_map_routes_count": record.get("routes_count", 0),
            "source_map_api_endpoints_count": record.get("api_endpoints_count", 0),
            "source_map_secrets_count": record.get("secrets_count", 0)
        }

        routes_summary_line = ""
        if record.get("routes_count", 0) > 0:
            routes_summary_line = f"- **Routes & APIs**: **{record.get('routes_count', 0)}** discovered ({record.get('api_endpoints_count', 0)} API endpoints, {record.get('client_routes_count', 0)} SPA client routes).\n"
        secrets_summary_line = ""
        if record.get("secrets_count", 0) > 0:
            secrets_summary_line = f"- **Secrets & Keys**: **{record.get('secrets_count', 0)}** exposed credentials / tokens detected.\n"

        notes_append = (
            f"\n\n### Recovered Source Code\n\n"
            f"- **{record.get('total_files', 0)} Original Source Files** extracted ({record.get('app_files_count', 0)} Application code files).\n"
            f"{routes_summary_line}"
            f"{secrets_summary_line}"
            f"- **Languages / Frameworks**: {', '.join(record.get('languages', [])) or 'JavaScript'}\n"
            f"- **Source Package**: Full repository reconstructed and available for instant browsing & ZIP download."
        )

        # Update all matching leads
        leads_cursor = self.leads_col.find({"$or": or_clauses})
        async for lead_doc in leads_cursor:
            doc_update = dict(update_fields)
            if "Recovered Source Code" not in (lead_doc.get("exploitation_suggestions") or ""):
                doc_update["exploitation_suggestions"] = (lead_doc.get("exploitation_suggestions") or "") + notes_append
            await self.leads_col.update_one(
                {"_id": lead_doc["_id"]},
                {"$set": doc_update}
            )

    async def _update_domain_web_apps(self, target: str, record_id: str, record: dict):
        """Register the recovered source map under the domain's web applications."""
        target_lower = target.lower().strip()
        summary_entry = {
            "id": record_id,
            "source_map_url": record.get("source_map_url"),
            "map_name": record.get("map_name"),
            "total_files": record.get("total_files", 0),
            "app_files_count": record.get("app_files_count", 0),
            "languages": record.get("languages", []),
            "recovered_at": record.get("recovered_at"),
            "zip_size": record.get("zip_size", 0),
            "routes_count": record.get("routes_count", 0),
            "api_endpoints_count": record.get("api_endpoints_count", 0)
        }

        # Match domain where target matches domain or a web_application
        domain_doc = await self.domains_col.find_one({
            "$or": [
                {"domain": target_lower},
                {"web_applications.target": target_lower}
            ]
        })

        if domain_doc:
            web_apps = domain_doc.get("web_applications", [])
            matched = False
            for wa in web_apps:
                wa_target = (wa.get("target") or "").lower().strip()
                if wa_target == target_lower or wa_target == f"https://{target_lower}" or wa_target == f"http://{target_lower}":
                    if "recovered_source_maps" not in wa:
                        wa["recovered_source_maps"] = []
                    # Avoid duplicates
                    wa["recovered_source_maps"] = [
                        m for m in wa["recovered_source_maps"] if m.get("source_map_url") != record.get("source_map_url")
                    ]
                    wa["recovered_source_maps"].append(summary_entry)
                    matched = True
                    break

            if not matched and web_apps:
                # Add to first web app if none explicitly matched target
                if "recovered_source_maps" not in web_apps[0]:
                    web_apps[0]["recovered_source_maps"] = []
                web_apps[0]["recovered_source_maps"] = [
                    m for m in web_apps[0]["recovered_source_maps"] if m.get("source_map_url") != record.get("source_map_url")
                ]
                web_apps[0]["recovered_source_maps"].append(summary_entry)

            await self.domains_col.update_one(
                {"_id": domain_doc["_id"]},
                {"$set": {"web_applications": web_apps}}
            )

    async def gather_and_unpack_all(self, recreate_alerts: bool = True, force_reanalyze: bool = False, concurrency: int = 6):
        """
        Gather all .js.map files discovered across domains, web applications, and alerts.
        Re-creates alerts for any that were deleted by the user, unpacks them, and
        runs the source code analyzer to detect routes and secrets.
        """
        logger.info("Gathering all discovered .js.map files across the workspace...")
        
        # 1. Map of target -> set of source map URLs
        target_map_urls: Dict[str, Set[str]] = {}

        # 1a. From domains.web_applications
        domains_cursor = self.domains_col.find({})
        async for domain_doc in domains_cursor:
            dom_name = domain_doc.get("domain") or "unknown_domain"
            for wa in domain_doc.get("web_applications", []):
                t = wa.get("target") or dom_name
                djs = wa.get("dynamic_js") or {}
                for sm in djs.get("sourcemaps", []):
                    if sm and ".map" in sm:
                        clean_sm = sm.strip().rstrip(".,;:)'\"")
                        target_map_urls.setdefault(t, set()).add(clean_sm)

        # 1b. From existing leads
        leads_cursor = self.leads_col.find({"title": {"$regex": "Source Map", "$options": "i"}})
        async for lead in leads_cursor:
            t = lead.get("target") or "unknown_target"
            text_blob = f"{lead.get('details', '')} {lead.get('description', '')}"
            m = re.search(r'Source Map URL:\s*(https?://[^\s\r\n]+)', text_blob, re.I)
            if not m:
                m = re.search(r'(https?://[^\s\r\n\'\"<>]+\.map[^\s\r\n\'\"<>]*)', text_blob, re.I)
            if m:
                clean_sm = m.group(1).rstrip(".,;:)'\"")
                target_map_urls.setdefault(t, set()).add(clean_sm)

        # 1c. From existing recovered_source_maps
        sm_cursor = self.source_maps_col.find({})
        async for sm_doc in sm_cursor:
            t = sm_doc.get("target") or "unknown_target"
            u = sm_doc.get("source_map_url")
            if u:
                clean_sm = u.strip().rstrip(".,;:)'\"")
                target_map_urls.setdefault(t, set()).add(clean_sm)

        total_unique = sum(len(urls) for urls in target_map_urls.values())
        logger.info(f"Gathered {total_unique} source map instances across {len(target_map_urls)} targets.")

        # Flatten list of (target, url) pairs
        tasks_list = []
        for t, urls in target_map_urls.items():
            for u in urls:
                tasks_list.append((t, u))

        semaphore = asyncio.Semaphore(concurrency)
        success_count = 0
        recreated_alerts_count = 0
        failed_count = 0

        async def process_one(target: str, sm_url: str):
            nonlocal success_count, recreated_alerts_count, failed_count
            async with semaphore:
                # 2. Check/recreate alert if requested
                lead_id = None
                escaped_url = re.escape(sm_url)
                existing_lead = await self.leads_col.find_one({
                    "$or": [
                        {"details": {"$regex": escaped_url}},
                        {"description": {"$regex": escaped_url}}
                    ]
                })

                if existing_lead:
                    lead_id = str(existing_lead["_id"])
                elif recreate_alerts:
                    # Check global alert settings before recreating alert
                    can_alert = True
                    try:
                        settings_doc = await self.settings_col.find_one({"key": "global_settings"})
                        if settings_doc and "alerts" in settings_doc:
                            val = settings_doc["alerts"].get("js_source_maps")
                            if val is False or str(val).lower() == "false" or val == 0:
                                can_alert = False
                    except Exception:
                        pass

                    if can_alert:
                        fp = hashlib.sha256(f"{target}|JS Discovery: Exposed Source Map|{sm_url}".encode()).hexdigest()
                        # Remove from suppressed if present
                        await self.fingerprints_col.delete_one({"fingerprint": fp})
                        
                        new_lead = {
                            "title": "JS Discovery: Exposed Source Map",
                            "description": f"JavaScript source map reference detected at {sm_url}. Source maps can expose unminified original source trees.",
                            "target": target,
                            "risk_level": "medium",
                            "status": "new",
                            "source": "Dynamic JS Recon & Extractor",
                            "timestamp": datetime.datetime.utcnow().isoformat(),
                            "details": f"Source Map URL: {sm_url}\nHost: {target}",
                            "exploitation_suggestions": (
                                "### Source Map Decompilation\n\n"
                                "1. **Unpack Source**: Use tools like `shuji` or `sourcemapper` to reconstruct original TypeScript/JavaScript source files.\n"
                                "2. **Code Audit**: Inspect comments, internal API paths, and developer notes in the reconstructed source."
                            ),
                            "fingerprint": fp,
                            "acknowledged": False,
                            "response_size": 0,
                            "alert_type": "js_source_maps"
                        }
                        ins = await self.leads_col.insert_one(new_lead)
                        lead_id = str(ins.inserted_id)
                        recreated_alerts_count += 1

                # 3. Unpack source map
                try:
                    res = await self.unpack_url(sm_url, target=target, lead_id=lead_id)
                    if res:
                        if force_reanalyze:
                            try:
                                from source_code_analyzer import SourceCodeAnalyzer
                                analyzer = SourceCodeAnalyzer()
                                await analyzer.analyze_source_map_doc(res)
                            except Exception as reanalyze_err:
                                logger.warning(f"Re-analysis error for {sm_url}: {reanalyze_err}")
                        success_count += 1
                    else:
                        failed_count += 1
                except Exception as unpack_err:
                    logger.error(f"Error unpacking {sm_url} on {target}: {unpack_err}")
                    failed_count += 1

        # Run all concurrently with semaphore
        await asyncio.gather(*(process_one(t, u) for t, u in tasks_list))

        logger.info(
            f"Gather & Unpack Complete: {success_count} unpacked successfully, "
            f"{failed_count} failed/404, {recreated_alerts_count} alerts recreated."
        )
        return {
            "total_gathered": total_unique,
            "success": success_count,
            "failed": failed_count,
            "recreated_alerts": recreated_alerts_count
        }

    async def backfill_all_alerts(self):
        """
        Legacy backfill helper, forwards to gather_and_unpack_all.
        """
        return await self.gather_and_unpack_all(recreate_alerts=True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Recover source code from JavaScript source maps")
    parser.add_argument("--url", help="URL of the .js.map file to recover")
    parser.add_argument("--target", help="Target hostname/domain", default=None)
    parser.add_argument("--backfill", action="store_true", help="Backfill and unpack all existing source map alerts")
    parser.add_argument("--gather-all", action="store_true", help="Gather all .js.map files across workspace and unpack")
    parser.add_argument("--recreate-alerts", action="store_true", default=True, help="Recreate deleted alerts in leads collection")
    parser.add_argument("--force", action="store_true", help="Force re-analysis of routes and secrets")
    parser.add_argument("--concurrency", type=int, default=6, help="Number of concurrent workers (default 6)")

    args = parser.parse_args()
    unpacker = SourceMapUnpacker()

    async def main():
        if args.gather_all or args.backfill:
            print("[*] Gathering all discovered .js.map files across all targets and web applications...")
            res = await unpacker.gather_and_unpack_all(
                recreate_alerts=args.recreate_alerts,
                force_reanalyze=args.force,
                concurrency=args.concurrency
            )
            print(f"\n[+] Processing Summary:")
            print(f"    Total unique map instances: {res.get('total_gathered')}")
            print(f"    Successfully unpacked:      {res.get('success')}")
            print(f"    Failed / 404 targets:       {res.get('failed')}")
            print(f"    Alerts recreated:           {res.get('recreated_alerts')}")
        elif args.url:
            res = await unpacker.unpack_url(args.url, target=args.target)
            if res:
                print(f"\n[+] Successfully recovered source code!")
                print(f"    Target: {res.get('target')}")
                print(f"    Total files: {res.get('total_files')}")
                print(f"    App code files: {res.get('app_files_count')}")
                print(f"    Vendor files: {res.get('vendor_files_count')}")
                print(f"    Languages: {', '.join(res.get('languages', []))}")
                print(f"    Extracted tree: {res.get('src_dir')}")
                print(f"    Downloadable ZIP: {res.get('zip_path')} ({res.get('zip_size')} bytes)")
            else:
                print(f"\n[-] Failed to recover source code from {args.url}")
        else:
            parser.print_help()

    asyncio.run(main())
