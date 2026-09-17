import asyncio
import datetime
import logging
import json
import os
import base64
import hashlib
import secrets
import urllib.parse
from collections import Counter
import httpx
from base_agent import BaseAgent, logger

DIR_WORDLIST = "/app/wordlists/common-dirs.txt"
FILE_WORDLIST = "/app/wordlists/common-files.txt"

# Curated high-impact sensitive files scanned across EVERY discovered directory
CURATED_SENSITIVE_FILES = [
    # Environment & Secrets
    ".env", ".env.local", ".env.production", ".env.dev", ".env.stage", ".env.backup", ".env.old",
    ".git/config", ".git/HEAD", ".gitignore", ".htaccess", ".htpasswd", ".DS_Store", ".npmrc",
    "web.config", "web.config.bak", "settings.py", "settings.json", "secrets.json", "credentials.json",
    "parameters.yml", "database.yml", "config.json", "config.php", "config.php.bak", "config.yaml",
    "config.yml", "configuration.php", "appsettings.json", "appsettings.Development.json",
    
    # Backups & Dumps
    "backup.zip", "backup.tar.gz", "backup.tgz", "backup.sql", "dump.sql", "db.sql", "database.sql",
    "database.sqlite", "data.sql", "site.zip", "app.zip", "old.zip", "archive.zip", "1.zip", "temp.zip",
    "backup.bak", "backup.old", "db.sqlite3", "dump.tar.gz",
    
    # Admin & Portals
    "admin.php", "admin.html", "admin.jsp", "admin.aspx", "login.php", "login.html", "login.jsp",
    "auth.php", "dashboard.php", "dashboard.html", "users.php", "manage.php", "portal.php",
    "control.php", "master.php", "panel.php", "root.php", "console",
    
    # APIs & Schemas
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "api.json", "schema.json",
    "swagger-ui.html", "api-docs", "graphql", "graphiql",
    
    # Diagnostics & Internal
    "phpinfo.php", "info.php", "version.txt", "readme.txt", "readme.md", "changelog.txt",
    "robots.txt", "sitemap.xml", "health", "healthz", "metrics", "actuator/health", "actuator/env",
    "actuator", "server-status", "debug", "test.php", "test.html",
    
    # Common entrypoints & assets
    "index.php", "index.html", "main.js", "app.js", "api.php", "upload.php", "download.php"
]

class DirectoryHunterAgent(BaseAgent):
    def __init__(self):
        super().__init__("directory_hunter", "Directory & File Hunter")
        self.alert_hashes_col = self.db["alert_hashes"]

    def build_curated_wordlist_for_dir(self, d_clean: str = "", tech_stack: list = None) -> str:
        """
        Build a high-speed targeted file wordlist for a discovered directory.
        Merges curated sensitive files, directory-contextual filenames, and technology-adaptive extensions.
        Writes to a temporary file and returns the file path.
        """
        words = list(CURATED_SENSITIVE_FILES)
        base_label = d_clean.split("/")[-1].lower() if d_clean else ""

        # Contextual filenames matching the directory name
        if base_label:
            words.extend([
                f"{base_label}.php", f"{base_label}.html", f"{base_label}.json",
                f"{base_label}.js", f"{base_label}.bak", f"{base_label}.zip",
                f"{base_label}.sql", f"{base_label}.txt", f"{base_label}.xml"
            ])

        # Technology-specific extensions
        tech_str = " ".join(str(t).lower() for t in (tech_stack or []))
        if "php" in tech_str or "wordpress" in tech_str:
            words.extend([
                "wp-config.php.bak", "wp-config.php~", "readme.html", "license.txt",
                "xmlrpc.php", "functions.php", "db.php", "connect.php"
            ])
        if "asp" in tech_str or "iis" in tech_str or "windows" in tech_str:
            words.extend([
                "web.config", "web.config.bak", "global.asax", "default.aspx", "index.aspx"
            ])
        if "spring" in tech_str or "java" in tech_str or "tomcat" in tech_str:
            words.extend([
                "actuator/env", "actuator/health", "actuator/heapdump", "actuator/mappings",
                "application.properties", "application.yml", "pom.xml"
            ])
        if "node" in tech_str or "express" in tech_str:
            words.extend(["package.json", "package-lock.json", ".npmrc", "server.js", "app.js"])
        if "python" in tech_str or "django" in tech_str or "flask" in tech_str:
            words.extend(["settings.py", "wsgi.py", "requirements.txt", ".env"])

        # Deduplicate while preserving order
        deduped = list(dict.fromkeys(words))
        wl_path = f"/tmp/curated_wl_{os.getpid()}_{base_label or 'root'}.txt"
        try:
            with open(wl_path, "w") as f:
                f.write("\n".join(deduped) + "\n")
            return wl_path
        except Exception as e:
            logger.debug(f"Error writing curated wordlist: {e}")
            return FILE_WORDLIST if os.path.exists(FILE_WORDLIST) else "wordlists/common-files.txt"

    async def probe_soft_404_lengths(self, base_url: str):
        """
        Probe random non-existent paths to detect baseline catch-all / custom-404 response sizes.
        Returns a set of sizes (in bytes) representing soft-404 or custom redirect pages.
        """
        soft_404_lengths = set()
        test_tokens = [
            f"rnd_soft404_{secrets.token_hex(6)}",
            f"test_probe_{secrets.token_hex(6)}.html"
        ]

        try:
            async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
                for token in test_tokens:
                    probe_url = f"{base_url.rstrip('/')}/{token}"
                    resp = await client.get(probe_url)
                    body_len = len(resp.content)
                    if body_len > 0:
                        soft_404_lengths.add(body_len)
                        logger.info(f"Soft-404 probe on {base_url}: detected baseline length {body_len} (Status {resp.status_code})")
        except Exception as e:
            logger.debug(f"Soft-404 probe exception on {base_url}: {e}")

        return soft_404_lengths

    @staticmethod
    def filter_duplicate_lengths(items, baseline_lengths=None, threshold=3):
        """
        Exclude responses with identical lengths that indicate catch-all / soft-404 pages.
        - Any length appearing >= threshold times across the items is excluded.
        - Any length in baseline_lengths is excluded.
        - For 200 status codes with identical non-zero length, threshold is 2 (excluding custom 200 redirects).
        """
        if not items:
            return []

        baseline_lengths = set(baseline_lengths or [])

        # Count frequencies of lengths (> 0 bytes)
        length_counts = Counter(item.get("length", 0) for item in items if item.get("length", 0) > 0)
        status_200_len_counts = Counter(
            item.get("length", 0) for item in items 
            if item.get("status") == 200 and item.get("length", 0) > 0
        )

        catch_all_lengths = set(baseline_lengths)
        for length, count in length_counts.items():
            if count >= threshold:
                catch_all_lengths.add(length)

        for length, count in status_200_len_counts.items():
            if count >= 2:
                catch_all_lengths.add(length)

        if catch_all_lengths:
            suppressed_count = sum(1 for item in items if item.get("length", 0) in catch_all_lengths)
            logger.info(
                f"Soft-404 Length Filter: Excluded {suppressed_count} false positive item(s) "
                f"matching duplicate lengths: {sorted(list(catch_all_lengths))[:10]}"
            )

        return [item for item in items if item.get("length", 0) not in catch_all_lengths]

    async def run_ffuf_recursive(self, base_url, task_id=None, tech_stack=None):
        logger.info(f"Phase 1: Recursive directory mapping on {base_url}")
        
        discovered_dirs = set([""]) # Always start with root
        results = []
        
        dir_wl = DIR_WORDLIST if os.path.exists(DIR_WORDLIST) else "wordlists/common-dirs.txt"
        if not os.path.exists(dir_wl):
            logger.warning(f"Wordlist {dir_wl} not found, skipping directory mapping.")
            return results, discovered_dirs

        # Pre-flight probe for root soft-404 baseline lengths
        root_baseline = await self.probe_soft_404_lengths(base_url)

        # Phase 1: Map directory structure recursively
        cmd = [
            "ffuf", "-w", dir_wl, "-u", f"{base_url}/FUZZ",
            "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac",
            "-recursion", "-recursion-depth", "2", "-t", "40"
        ]
        if root_baseline:
            cmd.extend(["-fs", ",".join(str(l) for l in root_baseline)])
        
        try:
            stdout, _ = await self.run_command(cmd, timeout=600)
            if stdout:
                for line in stdout.splitlines():
                    try:
                        data = json.loads(line.strip())
                        res_list = data['results'] if 'results' in data else [data]
                        for r in res_list:
                            full_url = r['url']
                            rel_path = full_url.replace(base_url, "").lstrip("/")
                            # Track discovered item
                            results.append({
                                "path": rel_path,
                                "directory": "",
                                "status": r['status'],
                                "length": r.get('length', 0),
                                "words": r.get('words', 0)
                            })
                    except: continue
        except Exception as e:
            logger.error(f"Recursive directory hunt error: {e}")

        # Filter duplicate lengths from Phase 1 before choosing candidate directories for Phase 2
        filtered_p1 = self.filter_duplicate_lengths(results, baseline_lengths=root_baseline, threshold=3)
        for r in filtered_p1:
            clean_d = r["path"].strip("/")
            # If path doesn't look like a file with a known static extension, treat as directory
            if not re.search(r'\.(html|htm|js|css|png|jpg|jpeg|svg|gif|ico|woff|woff2|ttf|map)$', clean_d, re.I):
                discovered_dirs.add(clean_d)

        logger.info(f"Discovered {len(discovered_dirs)} total directories on {base_url}. Starting Phase 2: File search in each directory.")

        # Phase 2: Exhaustive File Search inside EVERY discovered directory
        full_file_wl = FILE_WORDLIST if os.path.exists(FILE_WORDLIST) else "wordlists/common-files.txt"
        has_full_wl = os.path.exists(full_file_wl)
        
        # Priority keywords that warrant the full dictionary
        priority_keywords = [
            "admin", "api", "login", "auth", "config", "backup", "v1", "v2",
            "upload", "portal", "test", "dev", "private", "internal", "secret"
        ]

        # Sort: Root first, then priority directories, then remaining directories
        def dir_priority(d: str):
            d_lower = d.lower()
            if not d:
                return (0, 0)
            if any(kw in d_lower for kw in priority_keywords):
                return (1, len(d.split("/")))
            return (2, len(d.split("/")))

        all_dirs = sorted(list(discovered_dirs), key=dir_priority)

        for d_path in all_dirs:
            # Heartbeat update to prevent task timeouts during multi-directory searches
            if task_id:
                try:
                    await self.tasks_col.update_one(
                        {"_id": task_id},
                        {"$set": {"last_activity": datetime.datetime.utcnow()}}
                    )
                except Exception:
                    pass

            target_url = f"{base_url}/{d_path}".rstrip("/")
            logger.info(f"Phase 2: Searching files in directory: {target_url or '/'}")

            # Per-directory baseline soft-404 detection
            dir_baseline = await self.probe_soft_404_lengths(target_url)

            # Determine whether to use full dictionary or curated targeted dictionary
            is_priority = (not d_path) or any(kw in d_path.lower() for kw in priority_keywords)
            temp_wl_to_cleanup = None

            if is_priority and has_full_wl:
                active_wl = full_file_wl
            else:
                active_wl = self.build_curated_wordlist_for_dir(d_path, tech_stack)
                temp_wl_to_cleanup = active_wl

            cmd_file = [
                "ffuf", "-w", active_wl, "-u", f"{target_url}/FUZZ",
                "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac", "-t", "40"
            ]
            if dir_baseline:
                cmd_file.extend(["-fs", ",".join(str(l) for l in dir_baseline)])

            try:
                stdout_f, _ = await self.run_command(cmd_file, timeout=60)
                if stdout_f:
                    for line in stdout_f.splitlines():
                        try:
                            data = json.loads(line.strip())
                            res_list = data['results'] if 'results' in data else [data]
                            for r in res_list:
                                f_url = r['url']
                                f_rel_path = f_url.replace(base_url, "").lstrip("/")
                                results.append({
                                    "path": f_rel_path,
                                    "directory": d_path,
                                    "status": r['status'],
                                    "length": r.get('length', 0),
                                    "words": r.get('words', 0)
                                })
                        except: continue
            except Exception as e:
                logger.error(f"File search error for directory {target_url}: {e}")
            finally:
                if temp_wl_to_cleanup and temp_wl_to_cleanup.startswith("/tmp/"):
                    try:
                        os.remove(temp_wl_to_cleanup)
                    except Exception:
                        pass

        # Deduplicate results by path while preserving directory metadata
        unique_results = {}
        for r in results:
            p = r['path']
            if p not in unique_results or (not unique_results[p].get("directory") and r.get("directory")):
                unique_results[p] = {
                    "directory": r.get("directory", ""),
                    "status": r['status'],
                    "length": r.get('length', 0),
                    "words": r.get('words', 0)
                }

        all_items = [{"path": k, **v} for k, v in unique_results.items()]
        # Final pass: exclude duplicate response lengths across all results
        final_filtered = self.filter_duplicate_lengths(all_items, baseline_lengths=root_baseline, threshold=3)
        return final_filtered, discovered_dirs

    async def create_alert_for_item(self, root_domain, target, item, url):
        """Create a lead/alert for a newly discovered file/directory using the centralized alerting system."""
        full_discovery_url = f"{url}/{item['path']}".replace("//", "/").replace(":/", "://")
        path_lower = item['path'].lower()
        title = f"Sensitive Discovery: {item['path']}"
        risk = "medium"

        # Categorize sensitivity risk
        critical_patterns = [
            ".env", ".git", ".aws", "credentials", "id_rsa", "master.key", 
            "dump.sql", "backup.zip", "database.sqlite", "backup.tar", "database.sql"
        ]
        high_patterns = [
            "config", "web.config", "settings.py", "backup", "secret", "private", 
            "admin", "login", "password", ".htpasswd", ".htaccess", "shadow", "passwd"
        ]
        medium_patterns = [
            "swagger", "openapi", "actuator", "phpinfo", "info.php", "metrics", "healthz"
        ]

        if any(p in path_lower for p in critical_patterns):
            risk = "high"
            title = f"CRITICAL File Exposed: {item['path']}"
        elif any(p in path_lower for p in high_patterns):
            risk = "high"
            title = f"High-Risk File Exposed: {item['path']}"
        elif any(p in path_lower for p in medium_patterns):
            risk = "medium"
            title = f"Diagnostic/API Endpoint Exposed: {item['path']}"

        dir_info = f" inside directory `/{item.get('directory')}/`" if item.get('directory') else ""
        description = f"Web path discovered{dir_info}: {item['path']} (HTTP {item['status']}, {item.get('length', 0)}B)"
        details = (
            f"A sensitive file or path was discovered at {full_discovery_url} with HTTP status {item['status']} "
            f"and response size {item.get('length', 0)} bytes."
        )
        exploitation = (
            f"### Verification & Exploitation Guidance\n\n"
            f"1. **Navigate to Resource**: [{full_discovery_url}]({full_discovery_url})\n"
            f"2. **Assess Exposure**: Check if credentials, database dumps, configuration parameters, or unauthenticated admin portals are accessible.\n"
            f"3. **Remediation**: Restrict access at the web server/reverse proxy layer (return 404 or enforce IP/token authentication) or remove the sensitive file.\n"
            f"4. **Host Context**: Discovered on `{target}` ({root_domain})."
        )

        await self.create_alert(title, description, target, risk, details, exploitation, response_size=item.get('length', 0))

    async def process_tasks(self):
        task = await self.get_next_task("directory_hunt")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        protocol = task.get("protocol", "http")
        port = task.get("port", 80)
        
        # Build URL. Handle standard ports cleanly.
        if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
            url = f"{protocol}://{target}"
        else:
            url = f"{protocol}://{target}:{port}"

        try:
            # Query web_applications for target's detected tech stack
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            target_tech = []
            if domain_doc:
                for app in domain_doc.get("web_applications", []):
                    if app.get("target") == target:
                        target_tech = app.get("tech_stack", [])
                        break

            found_items, discovered_dirs = await self.run_ffuf_recursive(
                url,
                task_id=task["_id"],
                tech_stack=target_tech
            )
            
            # Update web_applications in the domains collection
            if domain_doc:
                web_apps = domain_doc.get("web_applications", [])
                app_found = False

                # Build structured discovered_directories records
                dir_records = []
                for d in sorted(discovered_dirs):
                    files_in_d = sum(1 for item in found_items if item.get("directory") == d)
                    dir_records.append({
                        "path": d or "/",
                        "files_found": files_in_d,
                        "scanned_at": datetime.datetime.utcnow().isoformat()
                    })

                for app in web_apps:
                    if app.get("target") == target:
                        # Update existing app
                        existing_files = {f["path"]: f for f in app.get("sensitive_files", [])}
                        
                        for item in found_items:
                            path = item["path"]
                            if path not in existing_files:
                                # New discovery! Create an alert
                                await self.create_alert_for_item(root_domain, target, item, url)
                                
                                # Trigger 403 bypass for forbidden paths
                                if item["status"] == 403:
                                    exists_bypass = await self.tasks_col.find_one({
                                        "root_domain": root_domain,
                                        "target": target,
                                        "path": path,
                                        "task_type": "bypass_403"
                                    })
                                    if not exists_bypass:
                                        await self.tasks_col.insert_one({
                                            "root_domain": root_domain,
                                            "target": target,
                                            "path": path,
                                            "base_url": url,
                                            "task_type": "bypass_403",
                                            "status": "pending",
                                            "created_at": datetime.datetime.utcnow()
                                        })
                                        logger.info(f"Queued 403 BYPASS task for {url}/{path}")
                            
                            # Preserve directory and length in stored record
                            existing_files[path] = {
                                "path": path,
                                "directory": item.get("directory", ""),
                                "status": item["status"],
                                "length": item.get("length", 0)
                            }
                        
                        app["sensitive_files"] = list(existing_files.values())
                        app["discovered_directories"] = dir_records
                        app_found = True
                        break
                
                if not app_found:
                    # Create new app entry
                    for item in found_items:
                        path = item["path"]
                        await self.create_alert_for_item(root_domain, target, item, url)

                        if item["status"] == 403:
                            exists_bypass = await self.tasks_col.find_one({
                                "root_domain": root_domain,
                                "target": target,
                                "path": path,
                                "task_type": "bypass_403"
                            })
                            if not exists_bypass:
                                await self.tasks_col.insert_one({
                                    "root_domain": root_domain,
                                    "target": target,
                                    "path": path,
                                    "base_url": url,
                                    "task_type": "bypass_403",
                                    "status": "pending",
                                    "created_at": datetime.datetime.utcnow()
                                })
                                logger.info(f"Queued 403 BYPASS task for {url}/{path}")
                        
                    web_apps.append({
                        "target": target,
                        "url": url,
                        "discovered_directories": dir_records,
                        "sensitive_files": [
                            {
                                "path": item["path"],
                                "directory": item.get("directory", ""),
                                "status": item["status"],
                                "length": item.get("length", 0)
                            }
                            for item in found_items
                        ],
                        "tech_stack": [],
                        "security_headers": {}
                    })
                
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {"web_applications": web_apps}}
                )
            
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            logger.info(f"Completed directory hunt for {url}. Found {len(found_items)} files across {len(discovered_dirs)} directories.")

            # Check if this was the last task for the root domain
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in directory hunt for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = DirectoryHunterAgent()
    asyncio.run(agent.main_loop())
