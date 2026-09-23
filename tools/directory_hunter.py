import asyncio
import datetime
import logging
import json
import os
import re
import base64
import hashlib
import secrets
import urllib.parse
from collections import Counter
import httpx
from base_agent import BaseAgent, logger

DIR_WORDLIST = "/app/wordlists/common-dirs.txt"
DIRBUSTER_DIR_WORDLIST = "/app/wordlists/DirBuster-2007_directory-list-2.3-small.txt"
COMBINED_DIR_WORDLIST = "/app/wordlists/combined-dirs.txt"
FILE_WORDLIST = "/app/wordlists/common-files.txt"

LOCAL_DIR_WORDLIST = "wordlists/common-dirs.txt"
LOCAL_DIRBUSTER_DIR_WORDLIST = "wordlists/DirBuster-2007_directory-list-2.3-small.txt"
LOCAL_COMBINED_DIR_WORDLIST = "wordlists/combined-dirs.txt"
LOCAL_FILE_WORDLIST = "wordlists/common-files.txt"

SECLISTS_DIRBUSTER_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt"

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
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt", "health", "healthz", "metrics", "actuator/health", "actuator/env",
    "actuator", "server-status", "debug", "test.php", "test.html",
    
    # Common entrypoints & assets
    "index.php", "index.html", "main.js", "app.js", "api.php", "upload.php", "download.php"
]

class DirectoryHunterAgent(BaseAgent):
    def __init__(self):
        super().__init__("directory_hunter", "Directory & File Hunter")
        self.alert_hashes_col = self.db["alert_hashes"]

    def get_directory_wordlist(self) -> str:
        """
        Locates or builds the consolidated directory wordlist.
        Combines common-dirs.txt (raft-small) and DirBuster-2007_directory-list-2.3-small.txt
        into a deduplicated, clean list without comments or leading slashes.
        Auto-downloads DirBuster list from SecLists if missing.
        """
        # 1. Check for DirBuster wordlist, download if completely absent
        dirbuster_path = None
        for p in [
            DIRBUSTER_DIR_WORDLIST,
            "/app/wordlists/directory-list-2.3-small.txt",
            LOCAL_DIRBUSTER_DIR_WORDLIST,
            "wordlists/directory-list-2.3-small.txt"
        ]:
            if os.path.exists(p):
                dirbuster_path = p
                break

        if not dirbuster_path:
            # Attempt to download into the wordlists directory
            target_dest = DIRBUSTER_DIR_WORDLIST if os.path.exists("/app/wordlists") else LOCAL_DIRBUSTER_DIR_WORDLIST
            try:
                os.makedirs(os.path.dirname(target_dest), exist_ok=True)
                logger.info(f"Downloading DirBuster-2007_directory-list-2.3-small.txt from SecLists to {target_dest}...")
                import urllib.request
                urllib.request.urlretrieve(SECLISTS_DIRBUSTER_URL, target_dest)
                dirbuster_path = target_dest
                logger.info(f"Successfully downloaded DirBuster list ({os.path.getsize(target_dest)} bytes)")
            except Exception as e:
                logger.warning(f"Failed to auto-download DirBuster list from SecLists: {e}")

        # 2. Collect available directory sources
        sources = []
        for p in [DIR_WORDLIST, LOCAL_DIR_WORDLIST]:
            if os.path.exists(p):
                sources.append(p)
                break

        if dirbuster_path and os.path.exists(dirbuster_path) and dirbuster_path not in sources:
            sources.append(dirbuster_path)

        if not sources:
            return ""

        if len(sources) == 1:
            return sources[0]

        # 3. Determine combined wordlist path
        base_dir = os.path.dirname(sources[0])
        combined_path = os.path.join(base_dir, "combined-dirs.txt")

        try:
            # If combined wordlist exists and is newer than all source files, reuse it
            if os.path.exists(combined_path):
                comb_mtime = os.path.getmtime(combined_path)
                if all(comb_mtime >= os.path.getmtime(s) for s in sources):
                    return combined_path

            # Merge and deduplicate while preserving priority order
            words = []
            for src in sources:
                with open(src, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip().lstrip("/")
                        if line and not line.startswith("#"):
                            words.append(line)

            deduped = list(dict.fromkeys(words))
            os.makedirs(os.path.dirname(combined_path), exist_ok=True)
            with open(combined_path, "w", encoding="utf-8") as f:
                f.write("\n".join(deduped) + "\n")
            logger.info(f"Generated consolidated directory wordlist at {combined_path} ({len(deduped)} paths from {', '.join(os.path.basename(s) for s in sources)})")
            return combined_path
        except Exception as e:
            # Fallback to /tmp if wordlists dir is read-only
            try:
                tmp_path = "/tmp/combined-dirs.txt"
                words = []
                for src in sources:
                    with open(src, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip().lstrip("/")
                            if line and not line.startswith("#"):
                                words.append(line)
                deduped = list(dict.fromkeys(words))
                with open(tmp_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(deduped) + "\n")
                logger.info(f"Generated consolidated directory wordlist in /tmp: {tmp_path} ({len(deduped)} paths)")
                return tmp_path
            except Exception as ex:
                logger.warning(f"Error creating combined wordlist: {ex}")
                return sources[0]

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

    async def fetch_robots_and_sitemaps(self, base_url: str, target: str):
        """
        Discovers, fetches, and parses robots.txt and sitemap.xml files.
        Extracts paths from Disallow/Allow/Sitemap directives in robots.txt
        and <loc> elements in sitemap.xml files.
        Concurrently probes discovered paths to obtain their actual HTTP status and lengths.
        Returns a dict with extracted items, discovered directories, and stats.
        """
        logger.info(f"Phase 0: Checking robots.txt and sitemaps for {base_url}")
        items = []
        discovered_dirs = set()
        robots_paths = set()
        sitemap_paths = set()
        candidate_sitemaps = set()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        robots_meta = {"present": False, "paths_extracted": 0, "sitemaps_declared": 0}
        sitemap_meta = {"present": False, "paths_extracted": 0, "sitemaps_parsed": 0}

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True, headers=headers) as client:
            # 1. Fetch & parse robots.txt
            robots_url = f"{base_url.rstrip('/')}/robots.txt"
            try:
                r_resp = await client.get(robots_url)
                if r_resp.status_code == 200 and r_resp.content:
                    body_text = r_resp.text
                    has_robots_keywords = bool(re.search(r'(user-agent|disallow|allow|sitemap):', body_text, re.I))
                    is_html = "<!doctype html" in body_text.lower() or ("<html" in body_text.lower() and "<body" in body_text.lower())

                    if has_robots_keywords or not is_html:
                        robots_meta["present"] = True
                        items.append({
                            "path": "robots.txt",
                            "directory": "",
                            "status": 200,
                            "length": len(r_resp.content),
                            "source": "robots.txt",
                            "words": len(body_text.split())
                        })

                        for raw_line in body_text.splitlines():
                            line = raw_line.split("#")[0].strip()
                            if not line:
                                continue

                            # Check Disallow / Allow directives
                            match_dir = re.match(r'^(disallow|allow):\s*(.+)$', line, re.I)
                            if match_dir:
                                p = match_dir.group(2).strip()
                                p = p.rstrip("$").rstrip("*").strip()
                                p = p.split("?")[0].strip()
                                p = p.lstrip("/")
                                if p and p != "/":
                                    robots_paths.add(p)
                                    dir_part = p.rstrip("/").rsplit("/", 1)[0] if "/" in p.rstrip("/") else (p if p.endswith("/") else "")
                                    if dir_part:
                                        discovered_dirs.add(dir_part.strip("/"))

                            # Check Sitemap directive
                            match_sm = re.match(r'^sitemap:\s*(.+)$', line, re.I)
                            if match_sm:
                                sm = match_sm.group(1).strip()
                                if sm.startswith("http://") or sm.startswith("https://"):
                                    candidate_sitemaps.add(sm)
                                elif sm.startswith("/"):
                                    candidate_sitemaps.add(f"{base_url.rstrip('/')}{sm}")

                        robots_meta["paths_extracted"] = len(robots_paths)
                        robots_meta["sitemaps_declared"] = len(candidate_sitemaps)
                        logger.info(f"robots.txt parsed: {len(robots_paths)} paths, {len(candidate_sitemaps)} sitemaps declared")
            except Exception as e:
                logger.debug(f"robots.txt fetch error on {base_url}: {e}")

            # 2. Add default sitemap candidate locations
            candidate_sitemaps.add(f"{base_url.rstrip('/')}/sitemap.xml")
            candidate_sitemaps.add(f"{base_url.rstrip('/')}/sitemap_index.xml")
            candidate_sitemaps.add(f"{base_url.rstrip('/')}/sitemap.txt")

            # 3. Fetch & parse sitemaps (limit to at most 6 sitemaps)
            processed_sitemaps = set()
            sitemaps_queue = list(candidate_sitemaps)[:6]

            while sitemaps_queue and len(processed_sitemaps) < 6:
                sm_url = sitemaps_queue.pop(0)
                if sm_url in processed_sitemaps:
                    continue
                processed_sitemaps.add(sm_url)

                try:
                    sm_resp = await client.get(sm_url)
                    if sm_resp.status_code == 200 and sm_resp.content:
                        sm_text = sm_resp.text
                        is_xml = ("<urlset" in sm_text) or ("<sitemapindex" in sm_text) or ("<loc>" in sm_text)
                        is_txt = sm_url.endswith(".txt") and bool(re.search(r'https?://[^\s]+', sm_text))

                        if is_xml or is_txt:
                            sitemap_meta["present"] = True
                            sitemap_meta["sitemaps_parsed"] += 1

                            rel_sm = sm_url.replace(base_url, "").lstrip("/") if base_url in sm_url else sm_url.split("/")[-1]
                            items.append({
                                "path": rel_sm,
                                "directory": "",
                                "status": 200,
                                "length": len(sm_resp.content),
                                "source": "sitemap.xml",
                                "words": len(sm_text.split())
                            })

                            target_host = (target.split(":")[0]).lower()

                            if is_xml:
                                locs = re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', sm_text, re.I)
                                for loc in locs:
                                    loc_clean = loc.strip()
                                    if loc_clean.lower().endswith(".xml") or "sitemap" in loc_clean.lower():
                                        if loc_clean not in processed_sitemaps and len(sitemaps_queue) < 6:
                                            sitemaps_queue.append(loc_clean)
                                    else:
                                        try:
                                            parsed = urllib.parse.urlparse(loc_clean)
                                            parsed_host = (parsed.hostname or "").lower()
                                            if not parsed_host or parsed_host == target_host or parsed_host.endswith(f".{target_host}"):
                                                p = parsed.path.lstrip("/")
                                                if p:
                                                    sitemap_paths.add(p)
                                                    if "/" in p:
                                                        discovered_dirs.add(p.rsplit("/", 1)[0].strip("/"))
                                        except Exception:
                                            pass
                            elif is_txt:
                                for line in sm_text.splitlines():
                                    line = line.strip()
                                    if line.startswith("http://") or line.startswith("https://") or line.startswith("/"):
                                        try:
                                            parsed = urllib.parse.urlparse(line)
                                            parsed_host = (parsed.hostname or "").lower()
                                            if not parsed_host or parsed_host == target_host or parsed_host.endswith(f".{target_host}"):
                                                p = parsed.path.lstrip("/")
                                                if p:
                                                    sitemap_paths.add(p)
                                                    if "/" in p:
                                                        discovered_dirs.add(p.rsplit("/", 1)[0].strip("/"))
                                        except Exception:
                                            pass
                except Exception as e:
                    logger.debug(f"Sitemap fetch error on {sm_url}: {e}")

            sitemap_meta["paths_extracted"] = len(sitemap_paths)
            logger.info(f"Sitemaps parsed: {sitemap_meta['sitemaps_parsed']} sitemap(s), {len(sitemap_paths)} total page path(s)")

            # 3.5 Fetch & parse security.txt (RFC 9116 /.well-known/security.txt and legacy /security.txt)
            security_meta = {"present": False, "url": None, "contacts": [], "policies": []}
            security_paths = set()
            sec_urls = [
                f"{base_url.rstrip('/')}/.well-known/security.txt",
                f"{base_url.rstrip('/')}/security.txt"
            ]
            for sec_url in sec_urls:
                try:
                    sec_resp = await client.get(sec_url)
                    if sec_resp.status_code == 200 and sec_resp.content:
                        sec_text = sec_resp.text
                        has_sec_keywords = bool(re.search(r'(contact|policy|encryption|acknowledgments|canonical):', sec_text, re.I))
                        is_html = "<!doctype html" in sec_text.lower() or ("<html" in sec_text.lower() and "<body" in sec_text.lower())
                        if has_sec_keywords or not is_html:
                            security_meta["present"] = True
                            security_meta["url"] = sec_url
                            rel_sec = ".well-known/security.txt" if "/.well-known/" in sec_url else "security.txt"
                            dir_sec = ".well-known" if "/.well-known/" in sec_url else ""
                            if dir_sec:
                                discovered_dirs.add(dir_sec)

                            items.append({
                                "path": rel_sec,
                                "directory": dir_sec,
                                "status": 200,
                                "length": len(sec_resp.content),
                                "source": "security.txt",
                                "words": len(sec_text.split())
                            })

                            # Parse directives and extract local policy/contact URLs
                            for sline in sec_text.splitlines():
                                sline = sline.strip()
                                match_field = re.match(r'^(contact|policy|acknowledgments|hiring|canonical):\s*(.+)$', sline, re.I)
                                if match_field:
                                    field_name, field_val = match_field.groups()
                                    field_val = field_val.strip()
                                    if field_name.lower() == "contact":
                                        security_meta["contacts"].append(field_val)
                                    elif field_name.lower() == "policy":
                                        security_meta["policies"].append(field_val)

                                    if field_val.startswith("http://") or field_val.startswith("https://") or field_val.startswith("/"):
                                        try:
                                            p_parsed = urllib.parse.urlparse(field_val)
                                            p_host = (p_parsed.hostname or "").lower()
                                            t_host = (target.split(":")[0]).lower()
                                            if not p_host or p_host == t_host or p_host.endswith(f".{t_host}"):
                                                clean_sec_path = p_parsed.path.lstrip("/")
                                                if clean_sec_path and clean_sec_path not in robots_paths and clean_sec_path not in sitemap_paths and clean_sec_path not in security_paths:
                                                    security_paths.add(clean_sec_path)
                                                    if "/" in clean_sec_path:
                                                        discovered_dirs.add(clean_sec_path.rsplit("/", 1)[0].strip("/"))
                                        except Exception:
                                            pass

                            logger.info(f"security.txt discovered at {sec_url}")
                            if "/.well-known/" in sec_url:
                                break
                except Exception as e:
                    logger.debug(f"security.txt fetch error on {sec_url}: {e}")

            # 4. Probing discovered paths
            paths_to_probe = []
            for p in sorted(list(robots_paths)):
                paths_to_probe.append((p, "robots.txt"))
            for p in sorted(list(sitemap_paths)):
                if p not in robots_paths:
                    paths_to_probe.append((p, "sitemap.xml"))
            for p in sorted(list(security_paths)):
                if p not in robots_paths and p not in sitemap_paths:
                    paths_to_probe.append((p, "security.txt"))

            paths_to_probe = paths_to_probe[:150]
            logger.info(f"Probing {len(paths_to_probe)} paths extracted from robots.txt, sitemaps, and security.txt...")

            sem = asyncio.Semaphore(15)

            async def probe_one(p_tuple):
                path_str, src = p_tuple
                probe_url = f"{base_url.rstrip('/')}/{path_str}"
                status = 200
                length = 0
                async with sem:
                    try:
                        r = await client.head(probe_url, timeout=5.0, follow_redirects=True)
                        if r.status_code == 405:
                            r = await client.get(probe_url, timeout=5.0, follow_redirects=True)
                        status = r.status_code
                        length = int(r.headers.get("content-length") or len(r.content or b""))
                    except Exception:
                        status = 200
                        length = 0

                dir_part = path_str.rstrip("/").rsplit("/", 1)[0] if "/" in path_str.rstrip("/") else ""
                return {
                    "path": path_str,
                    "directory": dir_part,
                    "status": status,
                    "length": length,
                    "source": src
                }

            if paths_to_probe:
                probed_results = await asyncio.gather(*[probe_one(pt) for pt in paths_to_probe], return_exceptions=True)
                for pr in probed_results:
                    if isinstance(pr, dict):
                        items.append(pr)

        return {
            "items": items,
            "discovered_dirs": discovered_dirs,
            "robots_txt": robots_meta,
            "sitemap": sitemap_meta,
            "security_txt": security_meta
        }

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

    async def run_ffuf_recursive(self, base_url, task_id=None, tech_stack=None, initial_dirs=None):
        logger.info(f"Phase 1: Recursive directory mapping on {base_url}")
        
        discovered_dirs = set([""]) # Always start with root
        if initial_dirs:
            for d in initial_dirs:
                if d and isinstance(d, str):
                    clean_d = d.strip('/')
                    if clean_d and not re.search(r'\.(html|htm|js|css|png|jpg|jpeg|svg|gif|ico|woff|woff2|ttf|map|json|txt|xml|pdf)$', clean_d, re.I):
                        discovered_dirs.add(clean_d)
        results = []
        
        dir_wl = self.get_directory_wordlist()
        if not dir_wl or not os.path.exists(dir_wl):
            logger.warning(f"Directory wordlist not found, skipping directory mapping.")
            return results, discovered_dirs

        # Pre-flight probe for root soft-404 baseline lengths
        root_baseline = await self.probe_soft_404_lengths(base_url)

        # Phase 1: Map directory structure recursively
        cmd = [
            "ffuf", "-w", dir_wl, "-u", f"{base_url}/FUZZ",
            "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac", "-ic",
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
        full_file_wl = FILE_WORDLIST if os.path.exists(FILE_WORDLIST) else (LOCAL_FILE_WORDLIST if os.path.exists(LOCAL_FILE_WORDLIST) else "wordlists/common-files.txt")
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
                "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac", "-ic", "-t", "40"
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

        alert_type = "sensitive_files_critical"
        if any(p in path_lower for p in critical_patterns):
            risk = "high"
            title = f"CRITICAL File Exposed: {item['path']}"
            alert_type = "sensitive_files_critical"
        elif any(p in path_lower for p in high_patterns):
            risk = "high"
            title = f"High-Risk File Exposed: {item['path']}"
            alert_type = "sensitive_files_high"
        elif any(p in path_lower for p in medium_patterns):
            risk = "medium"
            title = f"Diagnostic/API Endpoint Exposed: {item['path']}"
            alert_type = "sensitive_files_diagnostic"

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

        await self.create_alert(title, description, target, risk, details, exploitation, response_size=item.get('length', 0), alert_type=alert_type)

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

            # Phase 0: Robots.txt & Sitemap extraction
            rb_data = await self.fetch_robots_and_sitemaps(url, target)
            rb_items = rb_data.get("items", [])
            rb_dirs = rb_data.get("discovered_dirs", set())

            # Phase 1 & 2: ffuf directory mapping and file brute-force
            found_items, discovered_dirs = await self.run_ffuf_recursive(
                url,
                task_id=task["_id"],
                tech_stack=target_tech,
                initial_dirs=rb_dirs
            )
            discovered_dirs.update(rb_dirs)

            # Deduplicate and combine findings
            all_found_dict = {}
            for item in rb_items:
                all_found_dict[item["path"]] = item
            for item in found_items:
                p = item["path"]
                if p in all_found_dict:
                    src = all_found_dict[p].get("source")
                    all_found_dict[p] = item
                    if src:
                        all_found_dict[p]["source"] = src
                else:
                    all_found_dict[p] = item

            combined_items = list(all_found_dict.values())
            
            # Update web_applications in the domains collection
            if domain_doc:
                web_apps = domain_doc.get("web_applications", [])
                app_found = False

                # Build structured discovered_directories records
                dir_records = []
                for d in sorted(discovered_dirs):
                    files_in_d = sum(1 for item in combined_items if item.get("directory") == d)
                    dir_records.append({
                        "path": d or "/",
                        "files_found": files_in_d,
                        "scanned_at": datetime.datetime.utcnow().isoformat()
                    })

                for app in web_apps:
                    if app.get("target") == target:
                        # Update existing app
                        existing_files = {f["path"]: f for f in app.get("sensitive_files", [])}
                        
                        for item in combined_items:
                            path = item["path"]
                            if path not in existing_files:
                                # For items discovered via robots/sitemap, only alert on sensitive patterns to avoid alert spam
                                is_rb_src = item.get("source") in ["robots.txt", "sitemap.xml", "security.txt"]
                                is_sensitive = any(pat in path.lower() for pat in [
                                    ".env", ".git", "admin", "login", "config", "backup", "secret", "private", "api", "swagger", "actuator"
                                ])
                                if not is_rb_src or is_sensitive or item.get("status") in [401, 403]:
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
                            
                            # Preserve directory, length, and source in stored record
                            existing_files[path] = {
                                "path": path,
                                "directory": item.get("directory", ""),
                                "status": item["status"],
                                "length": item.get("length", 0),
                                "source": item.get("source", "dir_hunt")
                            }
                        
                        app["sensitive_files"] = list(existing_files.values())
                        app["discovered_directories"] = dir_records
                        if rb_data.get("robots_txt"):
                            app["robots_txt"] = rb_data["robots_txt"]
                        if rb_data.get("sitemap"):
                            app["sitemap"] = rb_data["sitemap"]
                        if rb_data.get("security_txt"):
                            app["security_txt"] = rb_data["security_txt"]
                        app_found = True
                        break
                
                if not app_found:
                    # Create new app entry
                    for item in combined_items:
                        path = item["path"]
                        is_rb_src = item.get("source") in ["robots.txt", "sitemap.xml", "security.txt"]
                        is_sensitive = any(pat in path.lower() for pat in [
                            ".env", ".git", "admin", "login", "config", "backup", "secret", "private", "api", "swagger", "actuator"
                        ])
                        if not is_rb_src or is_sensitive or item.get("status") in [401, 403]:
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
                                "length": item.get("length", 0),
                                "source": item.get("source", "dir_hunt")
                            }
                            for item in combined_items
                        ],
                        "robots_txt": rb_data.get("robots_txt", {}),
                        "sitemap": rb_data.get("sitemap", {}),
                        "security_txt": rb_data.get("security_txt", {}),
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
