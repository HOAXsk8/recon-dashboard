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

class DirectoryHunterAgent(BaseAgent):
    def __init__(self):
        super().__init__("directory_hunter", "Directory & File Hunter")
        self.alert_hashes_col = self.db["alert_hashes"]

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

    async def run_ffuf_recursive(self, base_url, task_id=None):
        logger.info(f"Phase 1: Recursive directory mapping on {base_url}")
        
        discovered_dirs = set([""]) # Start with root
        results = []
        
        dir_wl = DIR_WORDLIST if os.path.exists(DIR_WORDLIST) else "wordlists/common-dirs.txt"
        if not os.path.exists(dir_wl):
            logger.warning(f"Wordlist {dir_wl} not found, skipping directory mapping.")
            return results, discovered_dirs

        # Pre-flight probe for soft-404 baseline lengths
        baseline_lengths = await self.probe_soft_404_lengths(base_url)

        # Phase 1: Map directory structure recursively
        cmd = [
            "ffuf", "-w", dir_wl, "-u", f"{base_url}/FUZZ",
            "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac",
            "-recursion", "-recursion-depth", "2", "-t", "40"
        ]
        if baseline_lengths:
            cmd.extend(["-fs", ",".join(str(l) for l in baseline_lengths)])
        
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
                            results.append({
                                "path": rel_path, 
                                "status": r['status'],
                                "length": r.get('length', 0),
                                "words": r.get('words', 0)
                            })
                    except: continue
        except Exception as e:
            logger.error(f"Recursive directory hunt error: {e}")

        # Filter duplicate lengths from Phase 1 before choosing candidate directories for Phase 2
        filtered_p1 = self.filter_duplicate_lengths(results, baseline_lengths=baseline_lengths, threshold=3)
        for r in filtered_p1:
            discovered_dirs.add(r["path"])

        logger.info(f"Discovered {len(discovered_dirs)} total directories/paths (after length filter). Starting Phase 2: File discovery.")
        
        # Phase 2: File discovery on prioritized directories to avoid exponential wildcard traps
        file_wl = FILE_WORDLIST if os.path.exists(FILE_WORDLIST) else "wordlists/common-files.txt"
        if not os.path.exists(file_wl):
            return filtered_p1, discovered_dirs

        # Prioritize root + top candidate directories (up to 12 max)
        priority_keywords = ["admin", "api", "login", "auth", "config", "backup", "v1", "v2", "upload", "portal", "test", "dev"]
        selected_dirs = [""]  # Always include root
        for d in sorted(discovered_dirs, key=lambda x: (len(x.split("/")), x)):
            d_clean = d.strip("/")
            if not d_clean:
                continue
            if "/" not in d_clean or any(kw in d_clean.lower() for kw in priority_keywords):
                if d_clean not in selected_dirs:
                    selected_dirs.append(d_clean)
            if len(selected_dirs) >= 12:
                break

        logger.info(f"Phase 2: Scanning {len(selected_dirs)} prioritized directories for files on {base_url}.")

        for d_path in selected_dirs:
            if task_id:
                try:
                    await self.tasks_col.update_one(
                        {"_id": task_id},
                        {"$set": {"last_activity": datetime.datetime.utcnow()}}
                    )
                except Exception:
                    pass

            target_url = f"{base_url}/{d_path}".rstrip("/")
            logger.info(f"Scanning for files in: {target_url}")
            
            cmd_file = [
                "ffuf", "-w", file_wl, "-u", f"{target_url}/FUZZ",
                "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac", "-t", "40"
            ]
            if baseline_lengths:
                cmd_file.extend(["-fs", ",".join(str(l) for l in baseline_lengths)])
            
            try:
                stdout_f, _ = await self.run_command(cmd_file, timeout=45)
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
                                    "status": r['status'],
                                    "length": r.get('length', 0),
                                    "words": r.get('words', 0)
                                })
                        except: continue
            except Exception as e:
                logger.error(f"File hunt error for {target_url}: {e}")

        # Deduplicate results by path
        unique_results = {}
        for r in results:
            unique_results[r['path']] = {
                "status": r['status'],
                "length": r.get('length', 0),
                "words": r.get('words', 0)
            }
            
        all_items = [{"path": k, **v} for k, v in unique_results.items()]
        # Final pass: exclude duplicate response lengths across all results
        final_filtered = self.filter_duplicate_lengths(all_items, baseline_lengths=baseline_lengths, threshold=3)
        return final_filtered, discovered_dirs

    async def create_alert_for_item(self, root_domain, target, item, url):
        """Create a lead/alert for a newly discovered file/directory using the centralized alerting system."""
        full_discovery_url = f"{url}/{item['path']}".replace("//", "/").replace(":/", "://")
        
        title = f"Sensitive Discovery: {item['path']}"
        risk = "medium"
        
        # Escalate risk for sensitive patterns
        sensitive_patterns = [".env", "config", "backup", ".git", ".sql", "admin", "login", "password", "secret", "private"]
        if any(p in item['path'].lower() for p in sensitive_patterns):
            risk = "high"
        
        description = f"New web path found: {item['path']} ({item['status']}, {item.get('length', 0)}B)"
        details = f"A new directory/file was discovered at {full_discovery_url} with status code {item['status']} (length: {item.get('length', 0)} bytes)."
        exploitation = f"### Exploitation Guidance\n\n1. **Verify Exposure**: Navigate to [{full_discovery_url}]({full_discovery_url}) to see what data is exposed.\n2. **Check Content**: If it's a directory, check for directory listing. If it's a file, check for sensitive configuration, credentials, or source code.\n3. **Context**: This was found on {target} as part of the {root_domain} infrastructure."

        await self.create_alert(title, description, target, risk, details, exploitation)

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
            found_items, _ = await self.run_ffuf_recursive(url, task_id=task["_id"])
            
            # Update web_applications in the domains collection
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            if domain_doc:
                web_apps = domain_doc.get("web_applications", [])
                app_found = False
                for app in web_apps:
                    if app.get("target") == target:
                        # Update existing app
                        existing_files = {f["path"]: f for f in app.get("sensitive_files", [])}
                        
                        for item in found_items:
                            path = item["path"]
                            if path not in existing_files:
                                # New discovery! Create an alert
                                await self.create_alert_for_item(root_domain, target, item, url)
                                
                                # Trigger JS mining for .js files
                                if path.lower().endswith(".js"):
                                    exists_js = await self.tasks_col.find_one({
                                        "root_domain": root_domain,
                                        "target": target,
                                        "path": path,
                                        "task_type": "js_mine"
                                    })
                                    if not exists_js:
                                        await self.tasks_col.insert_one({
                                            "root_domain": root_domain,
                                            "target": target,
                                            "path": path,
                                            "base_url": url,
                                            "task_type": "js_mine",
                                            "status": "pending",
                                            "created_at": datetime.datetime.utcnow()
                                        })
                                        logger.info(f"Queued JS MINE task for {url}/{path}")
                                
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
                            
                            # Preserve length in stored record
                            existing_files[path] = {
                                "path": path,
                                "status": item["status"],
                                "length": item.get("length", 0)
                            }
                        
                        app["sensitive_files"] = list(existing_files.values())
                        app_found = True
                        break
                
                if not app_found:
                    # Create new app entry
                    for item in found_items:
                        path = item["path"]
                        await self.create_alert_for_item(root_domain, target, item, url)
                        
                        if path.lower().endswith(".js"):
                            exists_js = await self.tasks_col.find_one({
                                "root_domain": root_domain,
                                "target": target,
                                "path": path,
                                "task_type": "js_mine"
                            })
                            if not exists_js:
                                await self.tasks_col.insert_one({
                                    "root_domain": root_domain,
                                    "target": target,
                                    "path": path,
                                    "base_url": url,
                                    "task_type": "js_mine",
                                    "status": "pending",
                                    "created_at": datetime.datetime.utcnow()
                                })
                                logger.info(f"Queued JS MINE task for {url}/{path}")

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
                        "sensitive_files": [
                            {
                                "path": item["path"],
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
            logger.info(f"Completed directory hunt for {url}. Found {len(found_items)} items (after soft-404 length filtering).")

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
