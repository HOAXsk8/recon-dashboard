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

WORDLIST_PATH = "/app/wordlists/subdomains-top5000.txt" if os.path.exists("/app/wordlists/subdomains-top5000.txt") else "/app/wordlists/subdomains-top500.txt"

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
            stdout, stderr = await self.run_command(["subfinder", "-d", domain, "-silent", "-duc"], timeout=180)
            if stderr:
                logger.warning(f"Subfinder stderr: {stderr}")
            return [line.strip() for line in stdout.splitlines() if line.strip()]
        except Exception as e:
            logger.warning(f"Subfinder failed for {domain}: {e}")
            return []

    async def run_amass(self, domain):
        """Run OWASP Amass in passive mode for subdomain enumeration.
        
        Uses trusted resolvers (-tr) and capped QPS to prevent UDP socket exhaustion in Lima/macOS.
        """
        logger.info(f"[Amass] Running passive enumeration on {domain}")
        cmd = [
            "amass", "enum",
            "-passive",
            "-norecursive",
            "-tr", "1.1.1.1",
            "-tr", "8.8.8.8",
            "-dns-qps", "15",
            "-silent",
            "-d", domain,
            "-timeout", "2"
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=140)
            found = []
            for line in stdout.splitlines():
                sub = line.strip().lower()
                if sub and self.is_in_scope(sub, domain):
                    found.append(sub)
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
        # Bounded execution: -t 6 -rate 25 prevents UDP socket exhaustion on host NAT
        cmd = [
            "ffuf", "-w", WORDLIST_PATH, "-u", f"http://FUZZ.{domain}",
            "-mc", "200,204,301,302,307,401,403", "-s", "-ac", "-t", "6", "-rate", "25",
            "-timeout", "2", "-maxtime", "180"
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=210)
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
        one level deeper (e.g. FUZZ.api.target.com). Bounded to 20s/5 threads.
        """
        logger.info(f"[Recursive ffuf] Brute-forcing FUZZ.{parent_sub}")
        cmd = [
            "ffuf", "-w", WORDLIST_PATH, "-u", f"http://FUZZ.{parent_sub}",
            "-mc", "200,204,301,302,307,401,403", "-s", "-ac", "-t", "5", "-rate", "15",
            "-timeout", "2", "-maxtime", "20"
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
    # Free, Unauthenticated, Unlimited Sources (CertSpotter, RapidDNS, HackerTarget, crt.sh)
    # ------------------------------------------------------------------
    async def fetch_free_sources(self, domain: str) -> set:
        """
        Harvest subdomains strictly from 100% free, unauthenticated, non-rate-limited sources:
        1. crt.sh (Certificate Transparency logs): extracts both common_name and name_value (SANs).
           Includes curl fallback matching the command:
           curl -s https://crt.sh/?q=$domain&output=json | grep common_name | cut -d ":" -f2 | tr -d '",'
        2. CertSpotter (Free CT log issuance API): extracts all dns_names.
        3. RapidDNS (Free historical DNS database): extracts regex matches for *.{domain}.
        4. HackerTarget (Free host search): extracts hostname entries.
        """
        import httpx
        found = set()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, headers=headers) as client:
            # 1. CertSpotter (Free public CT issuances)
            try:
                cs_url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
                resp = await client.get(cs_url)
                if resp.status_code == 200:
                    for item in resp.json():
                        for name in item.get("dns_names", []):
                            clean = name.strip().lower().lstrip("*.")
                            if clean and self.is_in_scope(clean, domain):
                                found.add(clean)
                logger.info(f"[Free Sources - CertSpotter] Total unique subdomains so far: {len(found)}")
            except Exception as e:
                logger.debug(f"[CertSpotter] Error querying {domain}: {e}")

            # 2. RapidDNS (Free historical DNS)
            try:
                rd_url = f"https://rapiddns.io/s/{domain}?same_sub=1"
                resp = await client.get(rd_url)
                if resp.status_code == 200:
                    for match in re.findall(rf"([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})", resp.text):
                        clean = match.strip().lower().lstrip("*.")
                        if clean and self.is_in_scope(clean, domain):
                            found.add(clean)
                logger.info(f"[Free Sources - RapidDNS] Total unique subdomains so far: {len(found)}")
            except Exception as e:
                logger.debug(f"[RapidDNS] Error querying {domain}: {e}")

            # 3. HackerTarget (Free host search)
            try:
                ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
                resp = await client.get(ht_url)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.splitlines():
                        parts = line.split(",")
                        if parts:
                            clean = parts[0].strip().lower().lstrip("*.")
                            if clean and self.is_in_scope(clean, domain):
                                found.add(clean)
                logger.info(f"[Free Sources - HackerTarget] Total unique subdomains so far: {len(found)}")
            except Exception as e:
                logger.debug(f"[HackerTarget] Error querying {domain}: {e}")

            # 4. crt.sh (Certificate Transparency logs)
            crt_success = False
            for q in (domain, f"%.{domain}"):
                try:
                    crt_url = f"https://crt.sh/?q={q}&output=json"
                    resp = await client.get(crt_url)
                    if resp.status_code == 200:
                        certs = resp.json()
                        for cert in certs:
                            # Extract common_name
                            cn = cert.get("common_name", "")
                            if cn:
                                clean_cn = cn.strip().lower().lstrip("*.")
                                if clean_cn and self.is_in_scope(clean_cn, domain):
                                    found.add(clean_cn)
                            # Extract name_value (can contain multiple SANs separated by newlines)
                            nv = cert.get("name_value", "")
                            if nv:
                                for name in nv.splitlines():
                                    clean_name = name.strip().lower().lstrip("*.")
                                    if clean_name and self.is_in_scope(clean_name, domain):
                                        found.add(clean_name)
                        crt_success = True
                except Exception as ce:
                    logger.debug(f"[crt.sh] Error querying {q}: {ce}")

            # If httpx crt.sh query failed or returned 502, run curl fallback
            if not crt_success:
                try:
                    stdout, _ = await self.run_command(
                        ["curl", "-s", "-m", "15", f"https://crt.sh/?q={domain}&output=json"],
                        timeout=20
                    )
                    if stdout and "502" not in stdout:
                        for cn in re.findall(r'"common_name"\s*:\s*"([^"]+)"', stdout):
                            clean = cn.strip().lower().lstrip("*.")
                            if clean and self.is_in_scope(clean, domain):
                                found.add(clean)
                        for nv in re.findall(r'"name_value"\s*:\s*"([^"]+)"', stdout):
                            for name in nv.split(r"\n"):
                                clean = name.strip().lower().lstrip("*.")
                                if clean and self.is_in_scope(clean, domain):
                                    found.add(clean)
                except Exception as fe:
                    logger.debug(f"[crt.sh fallback] Error: {fe}")

        logger.info(f"[Free Sources] Harvested {len(found)} total unique hostnames for {domain}")
        return found

    async def fetch_ct_logs(self, domain: str) -> set:
        """Backwards compatibility alias for fetch_free_sources."""
        return await self.fetch_free_sources(domain)

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

        # Resolve candidates safely without flooding Lima usernet
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 2.0
        resolver.lifetime = 2.5

        resolved = set()
        batch_size = 15
        sem = asyncio.Semaphore(15)

        async def resolve_candidate(name: str):
            async with sem:
                try:
                    await resolver.resolve(name, "A")
                    return name
                except Exception:
                    return None

        candidate_list = list(candidates)
        for i in range(0, len(candidate_list), batch_size):
            batch = candidate_list[i:i + batch_size]
            results = await asyncio.gather(*[resolve_candidate(c) for c in batch])
            for r in results:
                if r and self.is_in_scope(r, root_domain):
                    resolved.add(r)
            if i + batch_size < len(candidate_list):
                await asyncio.sleep(0.04)

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
            if target != root_domain:
                logger.info(f"Skipping discovery for subdomain {target}: Subdomain lookups to public sources only occur for the root domain ({root_domain}).")
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
                )
                return

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
