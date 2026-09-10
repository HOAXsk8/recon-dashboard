import asyncio
import datetime
import logging
import json
import os
import re
from base_agent import BaseAgent, logger

IGNORE_PLUGINS = {
    "country", "ip", "title", "uncommonheaders", "strict-transport-security",
    "x-frame-options", "x-xss-protection", "x-content-type-options", "frame",
    "html5", "script", "cookies", "redirectlocation", "email", "allow",
    "meta-author", "open-graph-protocol", "content-security-policy",
    "access-control-allow-origin", "metagenerator", "x-ua-compatible",
    "passwordfield", "httponly", "x-powered-by", "httpserver", "hsts",
    "via", "x-backend-server", "x-forwarded-for"
}

def parse_tech_entry(entry):
    """
    Parses a technology string like 'WordPress:7.2', 'nginx/1.24', or 'PHP 8.1'.
    Returns (base_key_lower, display_name, version_str_or_None).
    """
    if not entry or not isinstance(entry, str):
        return None, None, None
    entry = entry.strip()
    if not entry:
        return None, None, None
    
    match = re.match(r"^([^:/\[]+)(?:[:/ ]v?([0-9]+(?:\.[0-9a-zA-Z_-]+)*))?", entry)
    if match:
        name = match.group(1).strip()
        version = match.group(2).strip() if match.group(2) else None
        return name.lower(), name, version
    return entry.lower(), entry, None

def merge_and_deduplicate_tech(*tech_sources):
    """
    Merge technology items from multiple sources (httpx list, whatweb plugins, server banner, db).
    Items can be strings (e.g. 'WordPress:7.2') or tuples (name, version).
    Deduplicates strictly by canonical lowercase base name, keeping the richest version and best casing.
    Excludes non-technology pseudo-plugins.
    """
    tech_map = {}
    for source in tech_sources:
        if not source:
            continue
        for item in source:
            if not item:
                continue
            if isinstance(item, tuple):
                name, version = item
                if not name or not isinstance(name, str):
                    continue
                base_key = name.lower().strip()
                display_name = name.strip()
            elif isinstance(item, str):
                base_key, display_name, version = parse_tech_entry(item)
            else:
                continue
            
            if not base_key or base_key in IGNORE_PLUGINS:
                continue
            
            if base_key not in tech_map:
                tech_map[base_key] = {"display_name": display_name, "version": version}
            else:
                curr = tech_map[base_key]
                # If incoming version is provided, prefer it if we don't have one or if it's more specific
                if version:
                    if not curr.get("version") or len(str(version)) > len(str(curr.get("version", ""))):
                        curr["version"] = version
                # Prefer title/uppercase casing (e.g. Nginx over nginx)
                if not curr["display_name"][0].isupper() and display_name[0].isupper():
                    curr["display_name"] = display_name

    result = []
    for key in sorted(tech_map.keys()):
        d = tech_map[key]
        disp = d["display_name"]
        ver = d.get("version")
        if ver:
            result.append(f"{disp}:{ver}")
        else:
            result.append(disp)
    return result

class TechFingerprinterAgent(BaseAgent):
    def __init__(self):
        super().__init__("tech_fingerprinter", "Technology Fingerprinter", type="script")

    async def run_httpx(self, url):
        logger.info(f"Running httpx fingerprinting on {url}")
        cmd = [
            "pd-httpx", "-u", url, "-td", "-title", "-server", "-sc", "-json", "-silent"
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=60)
            if stdout:
                return json.loads(stdout)
        except Exception as e:
            logger.error(f"httpx error for {url}: {e}")
        return None

    async def run_whatweb(self, url):
        logger.info(f"Running whatweb fingerprinting on {url}")
        cmd = [
            "whatweb", "--log-json=-", "-q", "-a", "1", url
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=60)
            if stdout:
                data = json.loads(stdout)
                if isinstance(data, list) and len(data) > 0:
                    return data[0]
                elif isinstance(data, dict):
                    return data
        except Exception as e:
            logger.error(f"whatweb error for {url}: {e}")
        return None

    def extract_security_headers(self, raw_headers):
        """Parse raw headers from httpx output to find security headers."""
        headers = {}
        if not raw_headers:
            return headers

        security_list = {
            "Strict-Transport-Security": "hsts",
            "Content-Security-Policy": "csp",
            "X-Frame-Options": "x_frame_options",
            "X-Content-Type-Options": "x_content_type_options",
            "X-XSS-Protection": "x_xss_protection",
            "Referrer-Policy": "referrer_policy"
        }

        normalized_headers = {k.lower(): v for k, v in raw_headers.items()}
        for h_name, key in security_list.items():
            val = normalized_headers.get(h_name.lower())
            if val:
                headers[key] = val
            else:
                headers[key] = None
        return headers

    async def create_tech_alert(self, root_domain, target, old_tech, new_tech, url):
        """Create a lead/alert for a changed technology stack using the centralized alerting system."""
        added = set(new_tech) - set(old_tech)
        removed = set(old_tech) - set(new_tech)
        
        if not added and not removed:
            return

        title = f"Tech Stack Change: {target}"
        changes = []
        if added:
            changes.append(f"Added: {', '.join(added)}")
        if removed:
            changes.append(f"Removed: {', '.join(removed)}")
        
        description = " | ".join(changes)
        details = f"A change in the technology stack was detected for {url}.\n\nPrevious stack: {', '.join(old_tech) or 'None'}\nNew stack: {', '.join(new_tech) or 'None'}"
        exploitation = f"### Tech Stack Analysis\n\n1. **Review Changes**: Analyze why these technologies were added or removed. New technologies might introduce new attack surfaces.\n2. **Version Check**: Check if the newly added technologies have known vulnerabilities (CVEs).\n3. **Consistency**: Ensure these changes align with known infrastructure updates."

        await self.create_alert(title, description, target, "medium", details, exploitation)

    async def create_header_alert(self, target, old_headers, new_headers, url):
        """Create a lead/alert for degraded security headers using the centralized alerting system."""
        regressions = []
        for key, name in [
            ("hsts", "Strict-Transport-Security"),
            ("csp", "Content-Security-Policy"),
            ("x_frame_options", "X-Frame-Options")
        ]:
            if old_headers.get(key) and not new_headers.get(key):
                regressions.append(name)
        
        if not regressions:
            return

        title = f"Security Header Regression: {target}"
        description = f"Removed: {', '.join(regressions)}"
        details = f"One or more security headers were removed from {url}.\n\nRegressions: {', '.join(regressions)}"
        exploitation = f"### Header Analysis\n\n1. **Check Config**: Verify if a recent server configuration change accidentally removed these headers.\n2. **Security Impact**: Removing {regressions} increases susceptibility to attacks like Clickjacking or XSS."

        await self.create_alert(title, description, target, "high", details, exploitation)

    async def process_tasks(self):
        task = await self.get_next_task("tech_fingerprint")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        protocol = task.get("protocol", "http")
        port = task.get("port", 80)
        
        # Build URL
        if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
            url = f"{protocol}://{target}"
        else:
            url = f"{protocol}://{target}:{port}"

        try:
            httpx_data = await self.run_httpx(url)
            whatweb_data = await self.run_whatweb(url)

            if not httpx_data and not whatweb_data:
                logger.warning(f"No fingerprint data obtained for {url}")
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
                )
                await self.check_completion(root_domain)
                return

            # Extract data from httpx
            httpx_tech = []
            server_banner = None
            security_headers = {}
            title = ""
            status_code = 200

            if httpx_data:
                httpx_tech = httpx_data.get("tech", [])
                server_banner = httpx_data.get("webserver") or httpx_data.get("server")
                raw_headers = httpx_data.get("headers", {})
                security_headers = self.extract_security_headers(raw_headers)
                title = httpx_data.get("title", "")
                status_code = httpx_data.get("status_code", 200)

            # Extract data from whatweb
            whatweb_tech_tuples = []
            whatweb_plugins_data = {}
            whatweb_status = None

            if whatweb_data:
                whatweb_status = whatweb_data.get("http_status")
                if not status_code and whatweb_status:
                    status_code = whatweb_status
                
                plugins = whatweb_data.get("plugins", {})
                whatweb_plugins_data = plugins

                # Fallback title if missing
                if not title and "Title" in plugins and plugins["Title"].get("string"):
                    title = plugins["Title"]["string"][0]
                
                # Fallback server if missing
                if not server_banner and "HTTPServer" in plugins and plugins["HTTPServer"].get("string"):
                    server_banner = plugins["HTTPServer"]["string"][0]

                for p_name, p_info in plugins.items():
                    if p_name.lower() in IGNORE_PLUGINS:
                        continue
                    ver = None
                    if isinstance(p_info, dict):
                        if p_info.get("version") and len(p_info["version"]) > 0:
                            ver = str(p_info["version"][0])
                        elif p_info.get("string") and len(p_info["string"]) > 0:
                            s_val = str(p_info["string"][0])
                            match = re.search(r"v?([0-9]+(?:\.[0-9a-zA-Z_-]+)+)", s_val)
                            if match:
                                ver = match.group(1)
                    whatweb_tech_tuples.append((p_name, ver))

            # Update web_applications in the domains collection
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            if domain_doc:
                web_apps = domain_doc.get("web_applications", [])
                app_found = False
                for app in web_apps:
                    if app.get("target") == target:
                        old_tech = app.get("tech_stack", [])
                        
                        # Merge and deduplicate across all sources
                        tech_stack = merge_and_deduplicate_tech(
                            old_tech,
                            httpx_tech,
                            whatweb_tech_tuples,
                            [server_banner] if server_banner else []
                        )
                        
                        tech_changed = set(old_tech) != set(tech_stack)
                        if tech_changed and old_tech:
                            await self.create_tech_alert(root_domain, target, old_tech, tech_stack, url)
                            # Force a re-run of directory hunt because the web app changed
                            await self.tasks_col.delete_many({
                                "root_domain": root_domain,
                                "target": target,
                                "port": port,
                                "task_type": "directory_hunt"
                            })
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "protocol": protocol,
                                "port": port,
                                "task_type": "directory_hunt",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Forced NEW directory hunt for {target}:{port} due to tech stack change.")
                        
                        # Check for header regressions
                        old_headers = app.get("security_headers", {})
                        if security_headers:
                            await self.create_header_alert(target, old_headers, security_headers, url)
                            app["security_headers"] = security_headers

                        # Update fields
                        app["tech_stack"] = tech_stack
                        if title:
                            app["title"] = title
                        if server_banner:
                            app["server"] = server_banner
                        if status_code:
                            app["status"] = status_code
                        if whatweb_data:
                            app["whatweb"] = {
                                "status": whatweb_status,
                                "plugins": whatweb_plugins_data
                            }
                        app_found = True
                        
                        # Queue JS Scrape for this target
                        exists_js = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": target,
                            "task_type": "js_scrape"
                        })
                        if not exists_js:
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "url": url,
                                "task_type": "js_scrape",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Queued JS SCRAPE for {url}")
                        break
                
                if not app_found:
                    tech_stack = merge_and_deduplicate_tech(
                        httpx_tech,
                        whatweb_tech_tuples,
                        [server_banner] if server_banner else []
                    )
                    new_app = {
                        "target": target,
                        "url": url,
                        "tech_stack": tech_stack,
                        "security_headers": security_headers,
                        "title": title,
                        "status": status_code,
                        "server": server_banner or "",
                        "sensitive_files": []
                    }
                    if whatweb_data:
                        new_app["whatweb"] = {
                            "status": whatweb_status,
                            "plugins": whatweb_plugins_data
                        }
                    web_apps.append(new_app)
                    
                    # Queue JS Scrape for NEW target
                    await self.tasks_col.insert_one({
                        "root_domain": root_domain,
                        "target": target,
                        "url": url,
                        "task_type": "js_scrape",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    })
                    logger.info(f"Queued JS SCRAPE for NEW app: {url}")
                
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {"web_applications": web_apps}}
                )
                logger.info(f"Updated tech stack for {url}: {tech_stack}")
        
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in tech fingerprint for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = TechFingerprinterAgent()
    asyncio.run(agent.main_loop())
