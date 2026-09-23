import os
import sys
import asyncio
import datetime
import logging
import json
import re
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from base_agent import BaseAgent, logger
except ImportError:
    from tools.base_agent import BaseAgent, logger

WORDLIST_PATH = "/app/wordlists/subdomains-top5000.txt"

# Permutation mutations to apply to each discovered subdomain label
PERM_PREFIXES = [
    "dev", "stg", "staging", "prod", "production", "api", "api-v2", "api-v3",
    "v2", "v3", "admin", "int", "internal", "uat", "qa", "test", "testing",
    "demo", "beta", "alpha", "sandbox", "preview", "preprod", "pre-prod",
    "new", "old", "legacy", "backup", "bak", "mirror", "origin", "direct",
    "mail", "smtp", "imap", "vpn", "remote", "portal", "app", "apps",
    "dashboard", "console", "panel", "manage", "mgmt", "control", "monitoring",
    "grafana", "kibana", "elastic", "jenkins", "ci", "cd", "gitlab", "jira",
    "confluence", "helpdesk", "support", "status",
]
PERM_SUFFIXES = [
    "-dev", "-stg", "-staging", "-prod", "-v2", "-v3", "-api", "-admin",
    "-test", "-qa", "-beta", "-demo", "-int", "-internal", "-old", "-new",
    "-bak", "-backup", "-2", "-3", "2", "3",
]


class SubdomainDiscoveryAgent(BaseAgent):
    def __init__(self):
        super().__init__("subdomain_discovery", "Subdomain Discovery Tool")

    async def run_subfinder(self, domain):
        logger.info(f"Running Subfinder on {domain}")
        try:
            stdout, stderr = await self.run_command(["subfinder", "-d", domain, "-silent"], timeout=180)
            if stderr:
                logger.warning(f"Subfinder stderr: {stderr}")
            return [line.strip() for line in stdout.splitlines() if line.strip()]
        except Exception as e:
            logger.warning(f"Subfinder failed for {domain}: {e}")
            return []

    async def run_amass(self, domain):
        """Run OWASP Amass in passive mode for subdomain enumeration.
        
        Uses only public data sources (CT logs, DNS datasets, APIs) —
        makes no direct connections to the target's infrastructure.
        """
        logger.info(f"[Amass] Running passive enumeration on {domain}")
        cmd = [
            "amass", "enum",
            "-passive",       # passive only — no active probing
            "-norecursive",   # stay focused on the root domain
            "-d", domain,
            "-timeout", "5"   # minutes; amass timeout flag
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=360)
            found = [line.strip() for line in stdout.splitlines() if line.strip()]
            logger.info(f"[Amass] Found {len(found)} candidates for {domain}")
            return found
        except Exception as e:
            logger.warning(f"[Amass] Passive enumeration failed or timed out for {domain}: {e}")
            return []

    async def has_wildcard_dns(self, domain):
        """Check if a domain has wildcard DNS configured."""
        random_sub = f"detect-wildcard-{datetime.datetime.utcnow().timestamp()}.{domain}"
        try:
            import socket
            # Use a thread-safe way to resolve in async
            loop = asyncio.get_event_loop()
            await loop.getaddrinfo(random_sub, None)
            logger.warning(f"Wildcard DNS detected for {domain}. Skipping active brute-force.")
            return True
        except socket.gaierror:
            return False
        except Exception as e:
            logger.error(f"Error checking wildcard for {domain}: {e}")
            return False

    async def run_ffuf(self, domain):
        logger.info(f"Running ffuf on {domain}")
        # Bounded execution: -timeout 2, -maxtime 60 prevents hanging on slow network/DNS
        cmd = [
            "ffuf", "-w", WORDLIST_PATH, "-u", f"http://FUZZ.{domain}",
            "-mc", "200,204,301,302,307,401,403", "-s", "-ac", "-t", "50",
            "-timeout", "2", "-maxtime", "60"
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=75)
            found = []
            for line in stdout.splitlines():
                sub = line.strip()
                if sub and not sub.startswith("Encountered an error") and " " not in sub:
                    found.append(f"{sub}.{domain}")
            return found
        except Exception as e:
            logger.warning(f"ffuf active discovery skipped or timed out for {domain}: {e}")
            return []

    async def run_recursive_ffuf(self, parent_sub: str, root_domain: str):
        """
        Run a focused mini-brute-force on a confirmed alive subdomain to enumerate
        one level deeper (e.g. FUZZ.api.target.com). Bounded to 30s/25 threads.
        """
        logger.info(f"[Recursive ffuf] Brute-forcing FUZZ.{parent_sub}")
        cmd = [
            "ffuf", "-w", WORDLIST_PATH, "-u", f"http://FUZZ.{parent_sub}",
            "-mc", "200,204,301,302,307,401,403", "-s", "-ac", "-t", "25",
            "-timeout", "2", "-maxtime", "30"
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=40)
            found = []
            for line in stdout.splitlines():
                sub = line.strip()
                if sub and " " not in sub:
                    candidate = f"{sub}.{parent_sub}"
                    if self.is_in_scope(candidate, root_domain):
                        found.append(candidate)
            logger.info(f"[Recursive ffuf] Found {len(found)} candidates under {parent_sub}")
            return found
        except Exception as e:
            logger.warning(f"[Recursive ffuf] Timed out or failed for {parent_sub}: {e}")
            return []

    # ------------------------------------------------------------------
    # NEW: Certificate Transparency Log Harvesting (crt.sh)
    # ------------------------------------------------------------------
    async def fetch_ct_logs(self, domain: str) -> set:
        """
        Query crt.sh Certificate Transparency logs for all historical and current
        certificates issued for *.{domain}. Extracts Subject Alternative Names (SANs)
        and CN values to surface staging, pre-production, and internal subdomains
        that may not appear in active DNS or search-engine indexes.
        """
        import httpx
        found = set()
        urls = [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://crt.sh/?q={domain}&output=json",
        ]
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                for url in urls:
                    try:
                        resp = await client.get(url, headers={"Accept": "application/json"})
                        if resp.status_code != 200:
                            continue
                        certs = resp.json()
                        for cert in certs:
                            name_value = cert.get("name_value", "")
                            # name_value can contain multiple SANs separated by newlines
                            for name in name_value.splitlines():
                                name = name.strip().lower().lstrip("*.")
                                if name and self.is_in_scope(name, domain):
                                    found.add(name)
                    except Exception as ce:
                        logger.debug(f"[CT Logs] Error querying {url}: {ce}")
            logger.info(f"[CT Logs] Found {len(found)} hostnames for {domain}")
        except Exception as e:
            logger.warning(f"[CT Logs] crt.sh query failed for {domain}: {e}")
        return found

    # ------------------------------------------------------------------
    # NEW: Permutation & Alteration Engine
    # ------------------------------------------------------------------
    async def run_permutations(self, root_domain: str, found_subdomains: list) -> set:
        """
        Generate subdomain permutations from already-discovered subdomains by applying
        common environment prefixes and suffixes (dev/stg/api/v2/admin/etc).
        Resolves candidates via async DNS — only returns names that have A or AAAA records.
        No HTTP connections are made; this is purely DNS-based.
        """
        import dns.asyncresolver
        import dns.exception

        # Extract unique single-label prefixes from found subdomains (e.g. "api" from "api.target.com")
        labels = set()
        for sub in found_subdomains:
            parts = sub.replace(f".{root_domain}", "").split(".")
            for part in parts:
                if part and len(part) >= 2:
                    labels.add(part.lower())

        # Generate candidates
        candidates = set()
        for label in labels:
            for prefix in PERM_PREFIXES:
                candidates.add(f"{prefix}.{root_domain}")
                candidates.add(f"{prefix}-{label}.{root_domain}")
                candidates.add(f"{label}-{prefix}.{root_domain}")
            for suffix in PERM_SUFFIXES:
                candidates.add(f"{label}{suffix}.{root_domain}")
        # Also apply prefixes directly on root domain
        for prefix in PERM_PREFIXES:
            candidates.add(f"{prefix}.{root_domain}")

        # Resolve all candidates concurrently in batches
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 2.0
        resolver.lifetime = 2.5

        resolved = set()
        batch_size = 50

        async def resolve_candidate(name: str):
            for rtype in ("A", "AAAA"):
                try:
                    await resolver.resolve(name, rtype)
                    return name
                except Exception:
                    pass
            return None

        candidate_list = list(candidates)
        for i in range(0, len(candidate_list), batch_size):
            batch = candidate_list[i:i + batch_size]
            results = await asyncio.gather(*[resolve_candidate(c) for c in batch])
            for r in results:
                if r and self.is_in_scope(r, root_domain):
                    resolved.add(r)

        logger.info(f"[Permutations] Resolved {len(resolved)} live candidates from {len(candidates)} generated for {root_domain}")
        return resolved

    async def process_tasks(self):
        # 1. Check for new domains that need discovery
        new_domains = await self.domains_col.find({"scanned": False, "blacklisted": {"$ne": True}, "single_domain_only": {"$ne": True}}).to_list(length=10)
        for d in new_domains:
            if d.get("on_hold", False):
                continue
            root_domain = d["domain"]
            active_count = await self.tasks_col.count_documents({
                "root_domain": root_domain,
                "status": {"$in": ["pending", "processing"]}
            })
            if active_count == 0:
                total_tasks = await self.tasks_col.count_documents({"root_domain": root_domain})
                if total_tasks == 0:
                    await self.tasks_col.insert_one({
                        "root_domain": root_domain,
                        "target": root_domain,
                        "task_type": "discovery",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    })
                    logger.info(f"Queued initial discovery scan for new domain: {root_domain}")

        # 2. Process pending discovery tasks
        task = await self.get_next_task("discovery")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        
        # Double check if domain is single_domain_only
        d_doc = await self.domains_col.find_one({"domain": root_domain})
        if d_doc and d_doc.get("single_domain_only"):
            logger.info(f"Subdomain Discovery: Cancelling discovery task for single-target domain {root_domain}.")
            await self.tasks_col.update_one({"_id": task["_id"]}, {"$set": {"status": "cancelled", "error": "Single target only"}})
            return
        
        try:
            is_recursive = (target != root_domain)

            if is_recursive:
                # -------------------------------------------------------
                # Recursive task: focused ffuf on a confirmed alive subdomain
                # -------------------------------------------------------
                wildcard_check = await self.has_wildcard_dns(target)
                recursive_results = []
                if not wildcard_check:
                    recursive_results = await self.run_recursive_ffuf(target, root_domain)
                raw_found = set(recursive_results)
                logger.info(f"[Recursive Discovery] {target}: {len(raw_found)} candidates found")

            else:
                # -------------------------------------------------------
                # Root domain pass: Subfinder + Amass + CT logs + Permutations + ffuf
                # -------------------------------------------------------
                wildcard_check, subfinder_results, amass_results, ct_results = await asyncio.gather(
                    self.has_wildcard_dns(target),
                    self.run_subfinder(target),
                    self.run_amass(target),
                    self.fetch_ct_logs(target),
                )
                passive = subfinder_results + amass_results + list(ct_results)
                logger.info(
                    f"Passive discovery complete for {target}: "
                    f"{len(subfinder_results)} Subfinder, "
                    f"{len(amass_results)} Amass, "
                    f"{len(ct_results)} CT logs"
                )

                # Active: Run bounded ffuf only if no wildcard is detected
                active = []
                if not wildcard_check:
                    active = await self.run_ffuf(target)

                # Permutation engine — uses the combined passive+active results as seed
                perm_results = await self.run_permutations(root_domain, passive + active)

                raw_found = set(passive + active) | perm_results
                raw_found.add(target)
                raw_found.add(root_domain)

            # Strict scope enforcement: only include targets that strictly belong to root_domain
            all_found = set()
            for sub in raw_found:
                cleaned_sub = sub.strip().lower().rstrip(".")
                if self.is_in_scope(cleaned_sub, root_domain):
                    all_found.add(cleaned_sub)
                else:
                    logger.warning(f"Discarding out-of-scope subdomain discovery result: {sub} for {root_domain}")


            # Fetch already scanned subdomains so each subdomain is strictly scanned once
            d_curr = await self.domains_col.find_one({"domain": root_domain}, {"infrastructure.subdomains": 1})
            already_scanned_set = set()
            if d_curr and d_curr.get("infrastructure", {}).get("subdomains"):
                for s in d_curr["infrastructure"]["subdomains"]:
                    if isinstance(s, dict):
                        if s.get("scanned", False) or bool(s.get("last_scanned")):
                            already_scanned_set.add(s.get("name", "").strip().lower())

            for sub in all_found:
                clean_target = sub.strip().lower()
                if clean_target in already_scanned_set:
                    continue

                # Add to verification queue
                exists = await self.tasks_col.find_one({
                    "root_domain": root_domain,
                    "target": sub,
                    "task_type": "verification"
                })
                if not exists:
                    await self.tasks_col.insert_one({
                        "root_domain": root_domain,
                        "target": sub,
                        "task_type": "verification",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow()
                    })

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

            logger.info(f"Completed discovery for {target} (Found {len(all_found)} in-scope targets)")

        except Exception as e:
            logger.error(f"Error in discovery for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = SubdomainDiscoveryAgent()
    asyncio.run(agent.main_loop())
