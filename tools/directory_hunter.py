import asyncio
import datetime
import logging
import json
import os
import base64
import hashlib
from base_agent import BaseAgent, logger

DIR_WORDLIST = "/app/wordlists/common-dirs.txt"
FILE_WORDLIST = "/app/wordlists/common-files.txt"

class DirectoryHunterAgent(BaseAgent):
    def __init__(self):
        super().__init__("directory_hunter", "Directory & File Hunter")
        self.alert_hashes_col = self.db["alert_hashes"]

    async def run_ffuf_recursive(self, base_url):
        logger.info(f"Phase 1: Recursive directory mapping on {base_url}")
        
        discovered_dirs = set([""]) # Start with root
        results = []
        
        dir_wl = DIR_WORDLIST if os.path.exists(DIR_WORDLIST) else "wordlists/common-dirs.txt"
        if not os.path.exists(dir_wl):
            logger.warning(f"Wordlist {dir_wl} not found, skipping directory mapping.")
            return results, discovered_dirs

        # Phase 1: Map directory structure recursively
        # -recursion handles the depth automatically
        cmd = [
            "ffuf", "-w", dir_wl, "-u", f"{base_url}/FUZZ",
            "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac",
            "-recursion", "-recursion-depth", "2", "-t", "40"
        ]
        
        try:
            stdout, _ = await self.run_command(cmd, timeout=600)
            if stdout:
                for line in stdout.splitlines():
                    try:
                        data = json.loads(line.strip())
                        # ffuf output can be one object or multiple
                        res_list = data['results'] if 'results' in data else [data]
                        for r in res_list:
                            # Extract full path relative to base_url
                            full_url = r['url']
                            rel_path = full_url.replace(base_url, "").lstrip("/")
                            
                            results.append({"path": rel_path, "status": r['status']})
                            
                            # If it looks like a directory, add to our list for Phase 2
                            # ffuf recursion already determines what is a directory
                            # We'll just collect everything found in Phase 1 as a candidate directory
                            discovered_dirs.add(rel_path)
                    except: continue
        except Exception as e:
            logger.error(f"Recursive directory hunt error: {e}")

        logger.info(f"Discovered {len(discovered_dirs)} total directories/paths. Starting Phase 2: File discovery.")
        
        # Phase 2: File discovery on every discovered directory
        file_wl = FILE_WORDLIST if os.path.exists(FILE_WORDLIST) else "wordlists/common-files.txt"
        if not os.path.exists(file_wl):
            return results, discovered_dirs

        for d_path in list(discovered_dirs):
            target_url = f"{base_url}/{d_path}".rstrip("/")
            logger.info(f"Scanning for files in: {target_url}")
            
            cmd_file = [
                "ffuf", "-w", file_wl, "-u", f"{target_url}/FUZZ",
                "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac", "-t", "40"
            ]
            
            try:
                # Shorter timeout per folder
                stdout_f, _ = await self.run_command(cmd_file, timeout=300)
                if stdout_f:
                    for line in stdout_f.splitlines():
                        try:
                            data = json.loads(line.strip())
                            res_list = data['results'] if 'results' in data else [data]
                            for r in res_list:
                                f_url = r['url']
                                f_rel_path = f_url.replace(base_url, "").lstrip("/")
                                results.append({"path": f_rel_path, "status": r['status']})
                        except: continue
            except Exception as e:
                logger.error(f"File hunt error for {target_url}: {e}")

        # Deduplicate results by path
        unique_results = {}
        for r in results:
            unique_results[r['path']] = r['status']
            
        return [{"path": k, "status": v} for k, v in unique_results.items()], discovered_dirs

    async def create_alert_for_item(self, root_domain, target, item, url):
        """Create a lead/alert for a newly discovered file/directory using the centralized alerting system."""
        # Suppress alerts for directory and file discoveries as requested.
        # Findings are still stored in the database under web_applications.sensitive_files.
        return
        
        full_discovery_url = f"{url}/{item['path']}".replace("//", "/").replace(":/", "://")
        
        title = f"Sensitive Discovery: {item['path']}"
        risk = "medium"
        
        # Escalate risk for sensitive patterns
        sensitive_patterns = [" .env", "config", "backup", ".git", ".sql", "admin", "login", "password", "secret", "private"]
        if any(p in item['path'].lower() for p in sensitive_patterns):
            risk = "high"
        
        description = f"New web path found: {item['path']} ({item['status']})"
        details = f"A new directory/file was discovered at {full_discovery_url} with status code {item['status']}."
        exploitation = f"### Exploitation Guidance\n\n1. **Verify Exposure**: Navigate to [{full_discovery_url}]({full_discovery_url}) to see what data is exposed.\n2. **Check Content**: If it's a directory, check for directory listing. If it's a file, check for sensitive configuration, credentials, or source code.\n3. **Context**: This was found on {target} as part of the {root_domain} infrastructure."

        await self.create_alert(title, description, target, risk, details, exploitation)

    async def process_tasks(self):
        task = await self.tasks_col.find_one_and_update(
            {"task_type": "directory_hunt", "status": "pending"},
            {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}},
            sort=[("created_at", 1)]
        )

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
            found_items, _ = await self.run_ffuf_recursive(url)
            
            # Update web_applications in the domains collection
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            if domain_doc:
                web_apps = domain_doc.get("web_applications", [])
                app_found = False
                for app in web_apps:
                    if app.get("target") == target:
                        # Update existing app
                        existing_files = {f["path"]: f["status"] for f in app.get("sensitive_files", [])}
                        
                        for item in found_items:
                            if item["path"] not in existing_files:
                                # This is a new discovery! Create an alert.
                                await self.create_alert_for_item(root_domain, target, item, url)
                                existing_files[item["path"]] = item["status"]
                                
                                # Trigger JS mining for .js files
                                if item["path"].lower().endswith(".js"):
                                    exists_js = await self.tasks_col.find_one({
                                        "root_domain": root_domain,
                                        "target": target,
                                        "path": item["path"],
                                        "task_type": "js_mine"
                                    })
                                    if not exists_js:
                                        await self.tasks_col.insert_one({
                                            "root_domain": root_domain,
                                            "target": target,
                                            "path": item["path"],
                                            "base_url": url,
                                            "task_type": "js_mine",
                                            "status": "pending",
                                            "created_at": datetime.datetime.utcnow()
                                        })
                                        logger.info(f"Queued JS MINE task for {url}/{item['path']}")
                                
                                # Trigger 403 bypass for forbidden paths
                                if item["status"] == 403:
                                    exists_bypass = await self.tasks_col.find_one({
                                        "root_domain": root_domain,
                                        "target": target,
                                        "path": item["path"],
                                        "task_type": "bypass_403"
                                    })
                                    if not exists_bypass:
                                        await self.tasks_col.insert_one({
                                            "root_domain": root_domain,
                                            "target": target,
                                            "path": item["path"],
                                            "base_url": url,
                                            "task_type": "bypass_403",
                                            "status": "pending",
                                            "created_at": datetime.datetime.utcnow()
                                        })
                                        logger.info(f"Queued 403 BYPASS task for {url}/{item['path']}")
                        
                        app["sensitive_files"] = [{"path": k, "status": v} for k, v in existing_files.items()]
                        app_found = True
                        break
                
                if not app_found:
                    # Create new app entry
                    for item in found_items:
                        await self.create_alert_for_item(root_domain, target, item, url)
                        
                        # Trigger JS mining for .js files
                        if item["path"].lower().endswith(".js"):
                            exists_js = await self.tasks_col.find_one({
                                "root_domain": root_domain,
                                "target": target,
                                "path": item["path"],
                                "task_type": "js_mine"
                            })
                            if not exists_js:
                                await self.tasks_col.insert_one({
                                    "root_domain": root_domain,
                                    "target": target,
                                    "path": item["path"],
                                    "base_url": url,
                                    "task_type": "js_mine",
                                    "status": "pending",
                                    "created_at": datetime.datetime.utcnow()
                                })
                                logger.info(f"Queued JS MINE task for {url}/{item['path']}")

                        # Trigger 403 bypass for forbidden paths
                        if item["status"] == 403:
                            exists_bypass = await self.tasks_col.find_one({
                                "root_domain": root_domain,
                                "target": target,
                                "path": item["path"],
                                "task_type": "bypass_403"
                            })
                            if not exists_bypass:
                                await self.tasks_col.insert_one({
                                    "root_domain": root_domain,
                                    "target": target,
                                    "path": item["path"],
                                    "base_url": url,
                                    "task_type": "bypass_403",
                                    "status": "pending",
                                    "created_at": datetime.datetime.utcnow()
                                })
                                logger.info(f"Queued 403 BYPASS task for {url}/{item['path']}")
                        
                    web_apps.append({
                        "target": target,
                        "url": url,
                        "sensitive_files": found_items,
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
            logger.info(f"Completed directory hunt for {url}. Found {len(found_items)} items.")

        except Exception as e:
            logger.error(f"Error in directory hunt for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = DirectoryHunterAgent()
    asyncio.run(agent.main_loop())
