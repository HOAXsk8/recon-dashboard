import asyncio
import datetime
import logging
import re
import sys
import os
import urllib.parse
import urllib.request
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpx
from base_agent import BaseAgent, logger

class ArchiveHunterAgent(BaseAgent):
    def __init__(self):
        super().__init__("archive_hunter", "Passive Historical URL Hunter")
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json,text/html,*/*"
        }

    def _sync_fetch_alienvault(self, domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=100"
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.7.1", "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    urls = set()
                    for item in data.get("url_list", []):
                        u = item.get("url")
                        if u and isinstance(u, str) and u.startswith("http"):
                            urls.add(u.strip())
                    return urls
        except Exception as e:
            logger.warning(f"[{domain}] AlienVault OTX query error: {e}")
        return set()

    def _sync_fetch_wayback(self, domain):
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey&limit=100"
        req = urllib.request.Request(cdx_url, headers={"User-Agent": "curl/8.7.1", "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    rows = data[1:] if len(data) > 0 and data[0] == ["original"] else data
                    urls = set()
                    for row in rows:
                        if isinstance(row, list) and len(row) > 0:
                            u = row[0]
                            if u and u.startswith("http"):
                                urls.add(u.strip())
                    return urls
        except Exception as e:
            logger.warning(f"[{domain}] Wayback Machine query error: {e}")
        return set()

    def _sync_fetch_urlscan(self, domain):
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=50"
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.7.1", "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    urls = set()
                    for item in data.get("results", []):
                        page = item.get("page", {})
                        u = page.get("url")
                        if u and isinstance(u, str) and u.startswith("http"):
                            urls.add(u.strip())
                    return urls
        except Exception as e:
            logger.warning(f"[{domain}] URLScan query error: {e}")
        return set()

    async def fetch_alienvault_otx(self, domain):
        logger.info(f"[{domain}] Fetching historical URLs from AlienVault OTX...")
        urls = await asyncio.to_thread(self._sync_fetch_alienvault, domain)
        logger.info(f"[{domain}] AlienVault OTX returned {len(urls)} URLs")
        return urls

    async def fetch_urlscan(self, domain):
        logger.info(f"[{domain}] Fetching historical URLs from URLScan.io...")
        urls = await asyncio.to_thread(self._sync_fetch_urlscan, domain)
        logger.info(f"[{domain}] URLScan.io returned {len(urls)} URLs")
        return urls

    async def fetch_wayback(self, domain):
        logger.info(f"[{domain}] Fetching historical URLs from Wayback Machine CDX...")
        urls = await asyncio.to_thread(self._sync_fetch_wayback, domain)
        logger.info(f"[{domain}] Wayback Machine returned {len(urls)} URLs")
        return urls

    def categorize_urls(self, domain, all_urls):
        """Categorize URLs into sensitive files, APIs, parameters, and documents."""
        ignored_exts = (
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
            ".woff", ".woff2", ".ttf", ".eot", ".otf", ".css", ".map"
        )

        sensitive_exts = (
            ".env", ".git", ".bak", ".sql", ".zip", ".tar.gz", ".tar", ".tgz",
            ".gz", ".7z", ".config", ".yml", ".yaml", ".xml", ".log", ".old",
            ".db", ".sqlite", ".pem", ".key", ".crt", ".backup", "wp-config.php",
            "web.config", ".htpasswd"
        )

        doc_exts = (".pdf", ".xls", ".xlsx", ".docx", ".doc", ".csv", ".tsv")

        param_keywords = (
            "redirect", "url", "file", "path", "token", "debug", "admin",
            "cmd", "exec", "dest", "source", "view", "load", "id", "user"
        )

        categorized = {
            "total_urls": len(all_urls),
            "sensitive_files": [],
            "api_endpoints": [],
            "interesting_params": [],
            "documents": [],
            "other_endpoints": []
        }

        seen_sensitive = set()
        seen_api = set()
        seen_params = set()
        seen_docs = set()

        for u in all_urls:
            parsed = urllib.parse.urlparse(u)
            path_lower = parsed.path.lower()
            query_lower = parsed.query.lower()

            # Skip static assets
            if any(path_lower.endswith(ext) for ext in ignored_exts):
                continue

            # 1. Sensitive Files & Backups
            if any(path_lower.endswith(ext) or ext in path_lower for ext in sensitive_exts):
                if u not in seen_sensitive:
                    seen_sensitive.add(u)
                    categorized["sensitive_files"].append({
                        "url": u,
                        "path": parsed.path,
                        "type": "Sensitive Backup / Config",
                        "detected_keyword": next((ext for ext in sensitive_exts if ext in path_lower), "config")
                    })
                continue

            # 2. API Endpoints
            if any(k in path_lower for k in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/swagger", "/openapi", "/rest/"]):
                if u not in seen_api:
                    seen_api.add(u)
                    categorized["api_endpoints"].append({
                        "url": u,
                        "path": parsed.path,
                        "endpoint": parsed.path
                    })
                continue

            # 3. Documents
            if any(path_lower.endswith(ext) for ext in doc_exts):
                if u not in seen_docs:
                    seen_docs.add(u)
                    categorized["documents"].append({
                        "url": u,
                        "path": parsed.path,
                        "filename": os.path.basename(parsed.path)
                    })
                continue

            # 4. Interesting Parameters
            if parsed.query and any(k in query_lower for k in param_keywords):
                if u not in seen_params:
                    seen_params.add(u)
                    categorized["interesting_params"].append({
                        "url": u,
                        "query": parsed.query
                    })
                continue

            # 5. Other Endpoints (cap at 200)
            if len(categorized["other_endpoints"]) < 200:
                categorized["other_endpoints"].append(u)

        return categorized

    async def process_domain_archives(self, doc):
        domain = doc.get("domain")
        logger.info(f"=== Starting Passive Historical URL Discovery for {domain} ===")

        all_urls = set()
        tasks = [
            self.fetch_alienvault_otx(domain),
            self.fetch_urlscan(domain),
            self.fetch_wayback(domain)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, set):
                all_urls.update(res)

        categorized = self.categorize_urls(domain, all_urls)

        logger.info(f"[{domain}] Categorized {len(all_urls)} archive URLs: {len(categorized['sensitive_files'])} sensitive, {len(categorized['api_endpoints'])} APIs, {len(categorized['interesting_params'])} params, {len(categorized['documents'])} docs.")

        # Save to Database
        await self.domains_col.update_one(
            {"_id": doc["_id"]},
            {
                "$set": {
                    "archive_urls": categorized,
                    "archive_hunter_complete": True,
                    "archive_hunter_at": datetime.datetime.utcnow().isoformat()
                }
            }
        )

        # Cross-populate sensitive files into web_applications.$.sensitive_files
        for sf in categorized["sensitive_files"]:
            parsed = urllib.parse.urlparse(sf["url"])
            target = parsed.netloc
            # Check if this target exists in web_applications
            webapp = await self.domains_col.find_one({
                "_id": doc["_id"],
                "web_applications.target": target
            })
            if webapp:
                await self.domains_col.update_one(
                    {"_id": doc["_id"], "web_applications.target": target},
                    {
                        "$addToSet": {
                            "web_applications.$.sensitive_files": {
                                "path": parsed.path.lstrip("/"),
                                "status": 200,
                                "source": "Passive Archive Hunter",
                                "discovered_at": datetime.datetime.utcnow().isoformat()
                            }
                        }
                    }
                )

            # Raise Alert if it's a high-impact file like .env, .git, .sql, .bak
            if any(k in sf["path"].lower() for k in [".env", ".git", ".sql", ".bak", "wp-config"]):
                await self.create_alert(
                    title=f"Historical Archive Leak: {os.path.basename(sf['path'])}",
                    description=f"A historical archive record for {domain} points to an exposed sensitive file at {sf['url']}.",
                    target=target or domain,
                    risk_level="high",
                    details={"url": sf["url"], "path": sf["path"]},
                    exploitation_suggestions=[
                        f"Check if {sf['url']} is still accessible on live server.",
                        "Inspect Web Archive snapshot for previously exposed database passwords or API keys."
                    ]
                )

        # Complete tasks in tasks_col
        await self.tasks_col.update_many(
            {"root_domain": domain, "task_type": "archive_urls", "status": {"$in": ["pending", "processing"]}},
            {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
        )

        logger.info(f"=== Completed Passive Historical URL Discovery for {domain} ===")

    async def process_tasks(self):
        # 1. Process tasks explicitly queued in tasks_col
        task = await self.tasks_col.find_one_and_update(
            {"task_type": "archive_urls", "status": "pending"},
            {"$set": {"status": "processing", "started_at": datetime.datetime.utcnow()}}
        )

        if task:
            root_domain = task["root_domain"]
            doc = await self.domains_col.find_one({"domain": root_domain})
            if doc:
                await self.process_domain_archives(doc)
            else:
                await self.tasks_col.update_one({"_id": task["_id"]}, {"$set": {"status": "failed", "error": "Domain not found"}})
            return

        # 2. Automatically find any domain where archive_hunter_complete is not True
        doc = await self.domains_col.find_one({
            "archive_hunter_complete": {"$ne": True},
            "blacklisted": {"$ne": True}
        })

        if doc:
            await self.process_domain_archives(doc)
            await asyncio.sleep(2)
        else:
            await asyncio.sleep(6)

if __name__ == "__main__":
    agent = ArchiveHunterAgent()
    asyncio.run(agent.main_loop())
