import asyncio
import datetime
import json
import logging
import os
import re
import sys
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpx
from base_agent import BaseAgent, logger

# Query parameter categorizations for parameter mining & fuzzing
INTERESTING_PARAM_CATEGORIES: Dict[str, Set[str]] = {
    "security_sensitive": {
        "debug", "admin", "test", "dev", "stage", "staging", "internal", "root",
        "secret", "key", "token", "auth", "access_token", "api_key", "jwt",
        "hash", "signature", "sig", "passwd", "password", "code", "otp",
        "creds", "credentials", "apikey", "session", "session_id", "priv"
    },
    "ssrf_redirect": {
        "redirect", "url", "uri", "dest", "destination", "return", "return_url",
        "next", "forward", "target", "out", "link", "domain", "host", "endpoint",
        "callback_url", "oauth_callback"
    },
    "file_inclusion": {
        "file", "path", "doc", "document", "folder", "root", "page", "load",
        "include", "template", "dir", "view", "source", "read", "show"
    },
    "command_exec": {
        "cmd", "exec", "command", "run", "cli", "code", "eval", "daemon", "process"
    },
    "database_query": {
        "sql", "query", "search", "select", "where", "filter", "order", "sort",
        "by", "group", "find", "search_term", "q", "keyword", "limit", "offset"
    },
    "identity_idor": {
        "user", "username", "uid", "user_id", "account", "acc", "id", "uuid",
        "role", "group", "tenant", "org", "org_id", "email", "member_id", "profile_id"
    },
    "callback_xss": {
        "callback", "jsonp", "cb", "ref", "action", "prompt", "msg", "format", "render"
    }
}


class ArchiveHunterAgent(BaseAgent):
    def __init__(self):
        super().__init__("archive_hunter", "Passive Historical URL Hunter")
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json,text/html,*/*"
        }

    # ------------------------------------------------------------------
    # Historical URL Fetchers (AlienVault, URLScan, Wayback, Common Crawl)
    # ------------------------------------------------------------------

    def _sync_fetch_alienvault(self, domain: str) -> Set[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=150"
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent, "Accept": "*/*"})
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

    def _sync_fetch_wayback(self, domain: str) -> Set[str]:
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit=150"
        req = urllib.request.Request(cdx_url, headers={"User-Agent": self.user_agent, "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=18) as resp:
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

    def _sync_fetch_urlscan(self, domain: str) -> Set[str]:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent, "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
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

    def _sync_fetch_commoncrawl(self, domain: str) -> Set[str]:
        """Fetch historical URLs from the Common Crawl index collection."""
        urls = set()
        indexes = []

        # 1. Discover latest Common Crawl index collections
        try:
            collinfo_url = "https://index.commoncrawl.org/collinfo.json"
            req = urllib.request.Request(
                collinfo_url,
                headers={"User-Agent": self.user_agent, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for item in data[:1]:  # Query the single most recent crawl index
                        if isinstance(item, dict) and "id" in item:
                            indexes.append(item["id"])
        except Exception as e:
            logger.debug(f"[{domain}] Common Crawl collinfo lookup: {e}")

        # Fallback if collinfo is unavailable
        if not indexes:
            current_year = datetime.datetime.utcnow().year
            indexes = [f"CC-MAIN-{current_year}-34"]

        # 2. Query Common Crawl index for *.domain/*
        for idx in indexes:
            try:
                cc_url = f"https://index.commoncrawl.org/{idx}-index?url=*.{domain}/*&output=json&limit=100"
                req = urllib.request.Request(
                    cc_url,
                    headers={"User-Agent": self.user_agent, "Accept": "*/*"}
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status == 200:
                        raw_text = resp.read().decode("utf-8", errors="ignore")
                        for line in raw_text.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                record = json.loads(line)
                                u = record.get("url")
                                if u and isinstance(u, str) and u.startswith("http"):
                                    urls.add(u.strip())
                            except Exception:
                                continue
            except Exception as e:
                logger.debug(f"[{domain}] Common Crawl query for {idx}: {e}")

        return urls

    async def fetch_alienvault_otx(self, domain: str) -> Set[str]:
        logger.info(f"[{domain}] Fetching historical URLs from AlienVault OTX...")
        urls = await asyncio.to_thread(self._sync_fetch_alienvault, domain)
        logger.info(f"[{domain}] AlienVault OTX returned {len(urls)} URLs")
        return urls

    async def fetch_urlscan(self, domain: str) -> Set[str]:
        logger.info(f"[{domain}] Fetching historical URLs from URLScan.io...")
        urls = await asyncio.to_thread(self._sync_fetch_urlscan, domain)
        logger.info(f"[{domain}] URLScan.io returned {len(urls)} URLs")
        return urls

    async def fetch_wayback(self, domain: str) -> Set[str]:
        logger.info(f"[{domain}] Fetching historical URLs from Wayback Machine CDX...")
        urls = await asyncio.to_thread(self._sync_fetch_wayback, domain)
        logger.info(f"[{domain}] Wayback Machine returned {len(urls)} URLs")
        return urls

    async def fetch_commoncrawl(self, domain: str) -> Set[str]:
        """Asynchronously fetch historical URLs from Common Crawl index."""
        logger.info(f"[{domain}] Fetching historical URLs from Common Crawl...")
        urls = await asyncio.to_thread(self._sync_fetch_commoncrawl, domain)
        logger.info(f"[{domain}] Common Crawl returned {len(urls)} URLs")
        return urls

    # ------------------------------------------------------------------
    # Parameter Mining & Wordlist Extraction (Enhancement #2)
    # ------------------------------------------------------------------

    def extract_mined_parameters(self, domain: str, all_urls: Set[str]) -> Dict[str, Any]:
        """
        Deduplicate and extract all query parameter names from historical URLs
        into a target-specific parameter wordlist for API and parameter fuzzing.
        """
        param_stats: Dict[str, Dict[str, Any]] = {}
        cat_counts: Dict[str, int] = {k: 0 for k in INTERESTING_PARAM_CATEGORIES}
        cat_counts["general"] = 0

        for u in all_urls:
            try:
                parsed = urllib.parse.urlparse(u)
                if not parsed.query:
                    continue
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for raw_k, vals in qs.items():
                    # Clean parameter name (strip array/bracket notation e.g. filter[] -> filter)
                    k_clean = re.sub(r'\[.*?\]', '', raw_k).strip().lower()
                    if not k_clean or len(k_clean) > 64 or not re.match(r'^[a-z0-9_\-\.]+$', k_clean):
                        continue

                    if k_clean not in param_stats:
                        cat = "general"
                        for cat_name, kw_set in INTERESTING_PARAM_CATEGORIES.items():
                            if k_clean in kw_set:
                                cat = cat_name
                                break
                        param_stats[k_clean] = {
                            "name": k_clean,
                            "frequency": 0,
                            "sample_values": set(),
                            "category": cat,
                            "is_interesting": cat != "general"
                        }
                        cat_counts[cat] += 1

                    param_stats[k_clean]["frequency"] += 1
                    for v in vals:
                        if v and len(v) < 80:
                            param_stats[k_clean]["sample_values"].add(v)
            except Exception:
                pass

        for p_name, data in param_stats.items():
            data["sample_values"] = list(data["sample_values"])[:5]

        wordlist = sorted(list(param_stats.keys()))
        detailed_params = sorted(list(param_stats.values()), key=lambda x: x["frequency"], reverse=True)
        interesting_list = [p for p in detailed_params if p["is_interesting"]]

        return {
            "total_unique_parameters": len(wordlist),
            "wordlist": wordlist,
            "interesting_count": len(interesting_list),
            "category_counts": cat_counts,
            "parameters": detailed_params
        }

    # ------------------------------------------------------------------
    # Historical Subdomain Harvesting (Enhancement #3)
    # ------------------------------------------------------------------

    def extract_historical_subdomains(self, domain: str, all_urls: Set[str]) -> Set[str]:
        """
        Extract all unique in-scope hostnames from archived URLs to discover
        legacy, unlinked, or decommissioned subdomains.
        """
        domain_clean = domain.lower().strip()
        subdomains = set()

        for u in all_urls:
            try:
                parsed = urllib.parse.urlparse(u)
                host = (parsed.hostname or "").lower().strip()
                if not host:
                    continue
                # Skip IP addresses
                if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
                    continue
                if self.is_in_scope(host, domain_clean):
                    if re.match(r'^[a-z0-9\-\.]+$', host):
                        subdomains.add(host)
            except Exception:
                pass

        return subdomains

    # ------------------------------------------------------------------
    # URL Categorization & Subdomain Partitioning
    # ------------------------------------------------------------------

    def categorize_urls(self, domain: str, all_urls: Set[str]) -> Dict[str, Any]:
        """Categorize URLs into sensitive files, APIs, parameters, documents, and mined wordlists."""
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
            "total_urls": 0,
            "raw_total_urls": len(all_urls),
            "sensitive_files": [],
            "api_endpoints": [],
            "interesting_params": [],
            "documents": [],
            "other_endpoints": [],
            "mined_parameters": self.extract_mined_parameters(domain, all_urls),
            "discovered_subdomains": sorted(list(self.extract_historical_subdomains(domain, all_urls)))
        }

        seen_sensitive = set()
        seen_api = set()
        seen_params = set()
        seen_docs = set()

        for u in all_urls:
            parsed = urllib.parse.urlparse(u)
            host = (parsed.hostname or "").lower()
            if not self.is_in_scope(host, domain):
                continue

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

        categorized["total_urls"] = (
            len(categorized["sensitive_files"]) +
            len(categorized["api_endpoints"]) +
            len(categorized["interesting_params"]) +
            len(categorized["documents"]) +
            len(categorized["other_endpoints"])
        )

        # Partition categorized archive URLs by subdomain
        by_subdomain = {}
        for category_name, items in [
            ("sensitive_files", categorized["sensitive_files"]),
            ("api_endpoints", categorized["api_endpoints"]),
            ("interesting_params", categorized["interesting_params"]),
            ("documents", categorized["documents"]),
            ("other_endpoints", categorized["other_endpoints"])
        ]:
            for item in items:
                u_str = item.get("url") if isinstance(item, dict) else item
                try:
                    if not u_str.startswith("http://") and not u_str.startswith("https://"):
                        u_str = "http://" + u_str
                    host = (urllib.parse.urlparse(u_str).hostname or domain).lower().strip()
                except Exception:
                    host = domain.lower().strip()

                if host not in by_subdomain:
                    by_subdomain[host] = {
                        "total_urls": 0,
                        "sensitive_files": [],
                        "api_endpoints": [],
                        "interesting_params": [],
                        "documents": [],
                        "other_endpoints": [],
                        "mined_parameters": []
                    }
                by_subdomain[host][category_name].append(item)
                by_subdomain[host]["total_urls"] += 1

        # Associate mined parameters per subdomain
        for host, sub_data in by_subdomain.items():
            sub_urls = set()
            for cat in ["sensitive_files", "api_endpoints", "interesting_params", "documents", "other_endpoints"]:
                for it in sub_data[cat]:
                    u_val = it.get("url") if isinstance(it, dict) else it
                    if u_val:
                        sub_urls.add(u_val)
            sub_mined = self.extract_mined_parameters(host, sub_urls)
            sub_data["mined_parameters"] = sub_mined.get("wordlist", [])

        categorized["by_subdomain"] = by_subdomain
        return categorized

    # ------------------------------------------------------------------
    # Process Domain Archives
    # ------------------------------------------------------------------

    async def process_domain_archives(self, doc: dict):
        domain = doc.get("domain")
        logger.info(f"=== Starting Passive Historical URL Discovery for {domain} ===")

        all_urls: Set[str] = set()

        # Gather historical URLs concurrently across AlienVault, URLScan, Wayback, and Common Crawl
        tasks = [
            self.fetch_alienvault_otx(domain),
            self.fetch_urlscan(domain),
            self.fetch_wayback(domain),
            self.fetch_commoncrawl(domain)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, set):
                all_urls.update(res)

        categorized = self.categorize_urls(domain, all_urls)
        mined_params = categorized.get("mined_parameters", {})
        historical_subs = set(categorized.get("discovered_subdomains", []))

        logger.info(
            f"[{domain}] Categorized {len(all_urls)} archive URLs: "
            f"{len(categorized['sensitive_files'])} sensitive, "
            f"{len(categorized['api_endpoints'])} APIs, "
            f"{len(categorized['interesting_params'])} params, "
            f"{len(categorized['documents'])} docs across {len(categorized.get('by_subdomain', {}))} subdomains. "
            f"Mined {mined_params.get('total_unique_parameters', 0)} unique parameters."
        )

        # --------------------------------------------------------------
        # Enhancement #3: Historical Subdomain Harvesting & Alive Check Feeding
        # --------------------------------------------------------------
        existing_subs_raw = doc.get("infrastructure", {}).get("subdomains", [])
        already_known = set()
        for s in existing_subs_raw:
            if isinstance(s, dict):
                n = s.get("name") or s.get("subdomain") or ""
                if n:
                    already_known.add(n.lower().strip())
            elif isinstance(s, str):
                already_known.add(s.lower().strip())

        new_historical_subs = [
            s for s in historical_subs
            if s not in already_known and s != domain.lower().strip()
        ]

        queued_count = 0
        if not doc.get("single_domain_only"):
            for sub in new_historical_subs:
                # Check if verification task already exists
                exists = await self.tasks_col.find_one({
                    "root_domain": domain,
                    "target": sub,
                    "task_type": "verification"
                })
                if not exists:
                    await self.tasks_col.insert_one({
                        "root_domain": domain,
                        "target": sub,
                        "task_type": "verification",
                        "status": "pending",
                        "source": "archive_hunter",
                        "created_at": datetime.datetime.utcnow()
                    })
                    queued_count += 1

        if historical_subs:
            await self.domains_col.update_one(
                {"_id": doc["_id"]},
                {
                    "$addToSet": {
                        "infrastructure.historical_subdomains": {"$each": list(historical_subs)}
                    }
                }
            )

        logger.info(
            f"[{domain}] Identified {len(historical_subs)} historical subdomains "
            f"({len(new_historical_subs)} new). Queued {queued_count} verification tasks for alive_check."
        )

        # Save to Database with mined parameter wordlist and historical metadata
        await self.domains_col.update_one(
            {"_id": doc["_id"]},
            {
                "$set": {
                    "archive_urls": categorized,
                    "osint.parameter_wordlist": mined_params.get("wordlist", []),
                    "infrastructure.mined_parameters": mined_params.get("wordlist", []),
                    "archive_hunter_complete": True,
                    "archive_hunter_at": datetime.datetime.utcnow().isoformat()
                }
            }
        )

        # Cross-populate sensitive files and archive_urls into matching web_applications
        web_apps = doc.get("web_applications", [])
        by_sub = categorized.get("by_subdomain", {})
        for app in web_apps:
            target = (app.get("target") or "").lower().strip()
            if target and target in by_sub:
                await self.domains_col.update_one(
                    {"_id": doc["_id"], "web_applications.target": app["target"]},
                    {"$set": {"web_applications.$.archive_urls": by_sub[target]}}
                )

        for sf in categorized["sensitive_files"]:
            parsed = urllib.parse.urlparse(sf["url"])
            target = parsed.netloc
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
                    ],
                    alert_type="archive_historical_leaks"
                )

        # Alert if critical internal/legacy subdomains were uncovered
        sensitive_sub_keywords = ["dev", "staging", "stage", "test", "admin", "vpn", "internal", "corp", "qa", "uat", "demo"]
        uncovered_sensitive_subs = [
            s for s in new_historical_subs
            if any(kw in s.split(".")[0].lower() for kw in sensitive_sub_keywords)
        ]
        if uncovered_sensitive_subs:
            await self.create_alert(
                title=f"Historical Subdomain Discovery: {len(uncovered_sensitive_subs)} Legacy/Internal Subdomains",
                description=f"Passive historical archives for {domain} revealed {len(uncovered_sensitive_subs)} previously unindexed subdomains ({', '.join(uncovered_sensitive_subs[:5])}).",
                target=domain,
                risk_level="medium",
                details={
                    "discovered_subdomains": uncovered_sensitive_subs,
                    "total_historical_subdomains": len(historical_subs),
                    "queued_for_alive_check": queued_count
                },
                exploitation_suggestions=[
                    "Verify whether these legacy subdomains resolve to active systems or abandoned cloud services.",
                    "Check for subdomain takeover opportunities on decommissioned cloud services.",
                    "Audit legacy authentication interfaces and outdated software versions."
                ],
                alert_type="historical_subdomain_discovery"
            )

        # Complete tasks in tasks_col
        await self.tasks_col.update_many(
            {"root_domain": domain, "task_type": "archive_urls", "status": {"$in": ["pending", "processing"]}},
            {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
        )

        logger.info(f"=== Completed Passive Historical URL Discovery for {domain} ===")

    async def process_tasks(self):
        # 1. Process tasks explicitly queued in tasks_col
        task = await self.get_next_task("archive_urls")

        if task:
            root_domain = task["root_domain"]
            doc = await self.domains_col.find_one({
                "domain": root_domain,
                "blacklisted": {"$ne": True},
                "on_hold": {"$ne": True}
            })
            if doc:
                await self.process_domain_archives(doc)
            else:
                await self.tasks_col.update_one({"_id": task["_id"]}, {"$set": {"status": "failed", "error": "Domain not found or inactive"}})
            return

        # 2. Automatically find any active domain where archive_hunter_complete is not True
        doc = await self.domains_col.find_one({
            "archive_hunter_complete": {"$ne": True},
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        })

        if doc:
            await self.process_domain_archives(doc)
            await asyncio.sleep(2)
        else:
            await asyncio.sleep(6)


if __name__ == "__main__":
    agent = ArchiveHunterAgent()
    asyncio.run(agent.main_loop())
