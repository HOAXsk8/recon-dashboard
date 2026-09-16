import os
import sys
import re
import asyncio
import logging
import datetime
from typing import List, Set, Dict, Tuple, Optional, Iterable, Any
import urllib.parse

# Ensure local imports work cleanly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger

try:
    import dns.asyncresolver
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# -------------------------------------------------------------------------
# Enterprise Environment Taxonomy
# -------------------------------------------------------------------------
# Standard environment replacement groups:
# When any token from this list is detected in a subdomain, it will be
# replaced with other environments from the pool.
ENVIRONMENT_VARIANTS = [
    # Production / Live
    "prod", "production", "prd", "pro", "live", "master", "main", "release", "rel",
    # Pre-Production / Staging
    "stage", "staging", "stg", "pre", "preprod", "pre-prod", "preproduction", "pprd", "preview", "pilot",
    # Non-production compound labels (UK telcos / enterprise)
    "nonprod", "non-prod", "np",
    # Testing & QA
    "test", "testing", "tst", "qa", "qas", "uat", "sit", "iat", "bat", "qc", "reg", "perf", "e2e", "acceptance",
    # Development / Sandbox
    "dev", "devel", "development", "local", "internal", "eng", "build", "ci", "poc", "lab", "labs", "sandbox", "sbx", "demo"
]

# Common compound suffixes and prefixes frequently used in enterprise/cloud
COMPOUND_MODIFIERS = [
    "np", "nonprod", "internal", "int", "ext", "dmz", "corp", "priv", "pub"
]

# Regex pattern matching environment tokens delimited by dots, hyphens, underscores, or string boundaries.
# Captures:
# Group 1: Leading delimiter or boundary (^, ., -, _)
# Group 2: The matched environment token
# Group 3: Optional trailing index digits (e.g. 1 in prod1)
# Group 4: Trailing delimiter or boundary (., -, _, $)
ENV_TOKEN_REGEX = re.compile(
    r'(?P<pre_delim>(?:^|[\.\-_]))'
    r'(?P<env>prod|production|prd|pro|live|master|main|release|rel|stage|staging|stg|pre|preprod|pprd|preview|pilot|nonprod|np|test|testing|tst|qa|qas|uat|sit|iat|bat|qc|reg|perf|e2e|acceptance|dev|devel|development|local|internal|eng|build|ci|poc|lab|labs|sandbox|sbx|demo)'
    r'(?P<idx>\d*)'
    r'(?P<post_delim>(?:[\.\-_]|$))',
    re.IGNORECASE
)


class SubdomainMutator:
    """
    Subdomain permutation engine specialized in environment tokens.
    Identifies environment markers (prod, dev, stage, etc.) and generates
    intelligent cross-environment permutations for DNS resolution.
    """

    def __init__(self, custom_environments: Optional[List[str]] = None):
        self.environments = list(dict.fromkeys(custom_environments or ENVIRONMENT_VARIANTS))

    def detect_environment_tokens(self, hostname: str, root_domain: str = "") -> List[Dict[str, Any]]:
        """
        Inspect the subdomain prefix (excluding the root domain) for environment tokens.
        Returns match metadata: token, span, prefix delimiter, postfix delimiter, digit index.
        """
        if not hostname:
            return []

        clean_host = hostname.lower().strip().rstrip(".")
        clean_root = root_domain.lower().strip().rstrip(".")

        # Extract only the sub-portion if root_domain is given
        if clean_root and clean_host.endswith(f".{clean_root}"):
            sub_part = clean_host[:-len(f".{clean_root}")]
        elif clean_root and clean_host == clean_root:
            return []
        else:
            sub_part = clean_host

        matches = []
        for m in ENV_TOKEN_REGEX.finditer(sub_part):
            env_matched = m.group("env").lower()
            idx = m.group("idx")
            pre_delim = m.group("pre_delim")
            post_delim = m.group("post_delim")
            span = m.span()
            matches.append({
                "raw_match": m.group(0),
                "env": env_matched,
                "idx": idx,
                "pre_delim": pre_delim,
                "post_delim": post_delim,
                "span": span,
                "sub_part": sub_part
            })
        return matches

    def generate_mutations(self, hostname: str, root_domain: str, max_mutations: int = 250) -> Set[str]:
        """
        Generate all permutations for a single subdomain by replacing matched environment
        tokens with the enterprise dictionary. Preserves delimiter conventions and numbering.
        """
        clean_host = hostname.lower().strip().rstrip(".")
        clean_root = root_domain.lower().strip().rstrip(".")

        if not clean_host or not clean_root:
            return set()

        # Target must be strictly within root_domain
        if clean_host == clean_root or not clean_host.endswith(f".{clean_root}"):
            return set()

        sub_part = clean_host[:-len(f".{clean_root}")]
        matches = self.detect_environment_tokens(clean_host, clean_root)
        if not matches:
            return set()

        candidates: Set[str] = set()

        for match in matches:
            matched_env = match["env"]
            idx = match["idx"]
            pre_delim = match["pre_delim"]
            post_delim = match["post_delim"]
            span = match["span"]

            for target_env in self.environments:
                # Don't generate identical token
                if target_env.lower() == matched_env.lower() and not idx:
                    continue

                # 1. Standard 1-to-1 replacement preserving index (e.g. prod1 -> dev1)
                replacement = f"{pre_delim}{target_env}{idx}{post_delim}"
                new_sub_part = sub_part[:span[0]] + replacement + sub_part[span[1]:]
                # Normalize double dots or delimiters if any
                new_sub_part = re.sub(r'\.{2,}', '.', new_sub_part).strip('.')
                candidate = f"{new_sub_part}.{clean_root}"
                candidates.add(candidate)

                # 2. If original had an index (e.g. prod1), also test un-indexed (dev)
                if idx:
                    unindexed_repl = f"{pre_delim}{target_env}{post_delim}"
                    unindexed_sub = sub_part[:span[0]] + unindexed_repl + sub_part[span[1]:]
                    unindexed_sub = re.sub(r'\.{2,}', '.', unindexed_sub).strip('.')
                    candidates.add(f"{unindexed_sub}.{clean_root}")

                # 3. Handle multi-tier non-prod injections (e.g., stage.priority.o2 -> stage.np.priority.o2)
                if target_env in ["dev", "stage", "test", "uat", "qa"]:
                    if post_delim == "." or pre_delim == ".":
                        compound_repl = f"{pre_delim}{target_env}.np{post_delim}"
                        comp_sub = sub_part[:span[0]] + compound_repl + sub_part[span[1]:]
                        comp_sub = re.sub(r'\.{2,}', '.', comp_sub).strip('.')
                        candidates.add(f"{comp_sub}.{clean_root}")

        # Remove the original hostname itself
        candidates.discard(clean_host)

        # Enforce max limit per seed to avoid denial of service
        if len(candidates) > max_mutations:
            candidates = set(list(candidates)[:max_mutations])

        return candidates

    def mutate_batch(self, hostnames: Iterable[str], root_domain: str) -> Set[str]:
        """
        Generate deduplicated candidate mutations for a collection of subdomains.
        """
        all_candidates: Set[str] = set()
        clean_root = root_domain.lower().strip().rstrip(".")
        for host in hostnames:
            mutated = self.generate_mutations(host, clean_root)
            all_candidates.update(mutated)
        return all_candidates


class FastDnsResolver:
    """
    High-performance asynchronous DNS resolver that confirms whether candidate
    permutations actively resolve in DNS before queueing them in the database.
    Includes wildcard DNS detection & suppression.
    """

    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 2.0, concurrency: int = 50):
        self.timeout = timeout
        self.concurrency = concurrency
        self.nameservers = nameservers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        self.wildcard_ips: Dict[str, Optional[Set[str]]] = {}

    async def detect_wildcard_ips(self, domain: str) -> Set[str]:
        """
        Resolve a series of random non-existent subdomains to determine if a wildcard DNS
        record is returning pseudo-IPs.
        """
        if domain in self.wildcard_ips:
            return self.wildcard_ips[domain] or set()

        import uuid
        test_sub = f"detect-wildcard-{uuid.uuid4().hex[:12]}.{domain}"
        ips = await self.resolve_single(test_sub)
        if ips:
            logger.warning(f"Wildcard DNS detected on {domain}! Resolves to: {ips}")
            self.wildcard_ips[domain] = set(ips)
            return set(ips)

        self.wildcard_ips[domain] = set()
        return set()

    async def resolve_single(self, hostname: str) -> List[str]:
        """
        Resolve A records for a single hostname.
        Uses dnspython asyncresolver if installed, else fallback to asyncio getaddrinfo.
        """
        clean_host = hostname.strip().rstrip(".")
        resolved_ips = []

        if HAS_DNSPYTHON:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.nameservers = self.nameservers
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout

                answer = await resolver.resolve(clean_host, "A")
                for rdata in answer:
                    resolved_ips.append(str(rdata))
                return resolved_ips
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
                return []
            except Exception:
                return []
        else:
            # Standard socket fallback
            try:
                loop = asyncio.get_event_loop()
                addr_info = await asyncio.wait_for(
                    loop.getaddrinfo(clean_host, None),
                    timeout=self.timeout
                )
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
                return resolved_ips
            except Exception:
                return []

    async def filter_live_candidates(self, candidates: Iterable[str], root_domain: str) -> Dict[str, List[str]]:
        """
        Resolve all candidate subdomains concurrently.
        Filters out non-resolving hosts and wildcards.
        Returns a dict of {live_hostname: [ip_addresses]}.
        """
        clean_root = root_domain.strip().rstrip(".")
        wildcard_ips = await self.detect_wildcard_ips(clean_root)

        semaphore = asyncio.Semaphore(self.concurrency)
        results: Dict[str, List[str]] = {}

        async def check_host(host: str):
            async with semaphore:
                ips = await self.resolve_single(host)
                if not ips:
                    return
                # Check wildcard suppression
                if wildcard_ips and any(ip in wildcard_ips for ip in ips):
                    # Discard if it strictly matches the wildcard IP
                    return
                results[host] = ips

        tasks = [check_host(c) for c in set(candidates)]
        if tasks:
            await asyncio.gather(*tasks)

        return results


class EnvironmentMutationAgent(BaseAgent):
    """
    Agent wrapper that hooks into the database to mutate known subdomains,
    filter live candidates, and queue them for verification & asset tracking.
    """

    def __init__(self):
        super().__init__("subdomain_mutator", "Subdomain Environment Mutator")
        self.mutator = SubdomainMutator()
        self.resolver = FastDnsResolver()

    async def mutate_and_discover_for_domain(
        self,
        root_domain: str,
        seed_subdomains: Optional[List[str]] = None,
        resolve_dns: bool = True
    ) -> Dict[str, Any]:
        """
        Process a domain:
        1. Fetch known subdomains if seeds not provided.
        2. Generate environment permutations.
        3. Pre-resolve via DNS if resolve_dns=True.
        4. Insert confirmed live discoveries into tasks/domains collections.
        """
        clean_root = root_domain.lower().strip().rstrip(".")
        logger.info(f"Subdomain Mutation: Starting environment permutation discovery for {clean_root}")

        # 1. Gather seeds
        seeds = set(seed_subdomains or [])
        if not seeds:
            dom_doc = await self.domains_col.find_one({"domain": clean_root})
            if dom_doc:
                infra = dom_doc.get("infrastructure", {})
                for sub_obj in infra.get("subdomains", []):
                    name = sub_obj.get("name") if isinstance(sub_obj, dict) else str(sub_obj)
                    if name:
                        seeds.add(name.strip().lower())
                for wa in dom_doc.get("web_applications", []):
                    t = wa.get("target")
                    if t:
                        parsed_t = urllib.parse.urlparse(t).hostname or t
                        seeds.add(parsed_t.strip().lower())

        if not seeds:
            logger.info(f"Subdomain Mutation: No seed subdomains found for {clean_root}")
            return {"root_domain": clean_root, "seeds_count": 0, "generated": 0, "live_found": 0, "live": []}

        # 2. Filter seeds that contain environment markers
        matching_seeds = [s for s in seeds if self.mutator.detect_environment_tokens(s, clean_root)]
        logger.info(f"Subdomain Mutation: {len(matching_seeds)} of {len(seeds)} subdomains contained environment markers.")

        if not matching_seeds:
            return {"root_domain": clean_root, "seeds_count": len(seeds), "matching_seeds": 0, "generated": 0, "live_found": 0, "live": []}

        # 3. Generate candidate permutations
        candidates = self.mutator.mutate_batch(matching_seeds, clean_root)
        # Exclude candidates that are already known in seeds
        new_candidates = candidates - seeds
        logger.info(f"Subdomain Mutation: Generated {len(new_candidates)} new environment permutations for {clean_root}.")

        if not new_candidates:
            return {"root_domain": clean_root, "seeds_count": len(seeds), "generated": 0, "live_found": 0, "live": []}

        # 4. DNS Resolution & Wildcard filtering
        live_subdomains: Dict[str, List[str]] = {}
        if resolve_dns:
            logger.info(f"Subdomain Mutation: Resolving {len(new_candidates)} candidates via Fast DNS Resolver...")
            live_subdomains = await self.resolver.filter_live_candidates(new_candidates, clean_root)
            logger.info(f"Subdomain Mutation: {len(live_subdomains)} of {len(new_candidates)} candidates resolved live!")
        else:
            live_subdomains = {c: [] for c in new_candidates}

        # 5. Queue live discoveries into tasks (task_type="verification") and domains
        queued_count = 0
        now_iso = datetime.datetime.utcnow().isoformat()

        for live_host, ips in live_subdomains.items():
            if not self.is_in_scope(live_host, clean_root):
                continue

            # Add to domains infrastructure.subdomains
            sub_exists = await self.domains_col.find_one({
                "domain": clean_root,
                "infrastructure.subdomains.name": live_host
            })
            if not sub_exists:
                await self.domains_col.update_one(
                    {"domain": clean_root},
                    {"$addToSet": {
                        "infrastructure.subdomains": {
                            "name": live_host,
                            "added_at": now_iso,
                            "source": "environment_mutator",
                            "ips": ips
                        }
                    }}
                )

            # Queue verification task (alive_check)
            task_exists = await self.tasks_col.find_one({
                "root_domain": clean_root,
                "target": live_host,
                "task_type": "verification"
            })
            if not task_exists:
                await self.tasks_col.insert_one({
                    "root_domain": clean_root,
                    "target": live_host,
                    "task_type": "verification",
                    "status": "pending",
                    "source": "environment_mutator",
                    "created_at": datetime.datetime.utcnow()
                })
                queued_count += 1

        return {
            "root_domain": clean_root,
            "seeds_count": len(seeds),
            "matching_seeds": len(matching_seeds),
            "generated_candidates": len(new_candidates),
            "live_found": len(live_subdomains),
            "queued_for_verification": queued_count,
            "live_hosts": list(live_subdomains.keys())
        }

    async def process_tasks(self):
        """Pick up pending environment_mutate tasks from MongoDB tasks queue."""
        task = await self.get_next_task("environment_mutate")
        if not task:
            return

        root_domain = task.get("root_domain")
        try:
            res = await self.mutate_and_discover_for_domain(root_domain)
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {
                    "status": "completed",
                    "completed_at": datetime.datetime.utcnow(),
                    "result": res
                }}
            )
            await self.check_completion(root_domain)
            logger.info(f"Completed environment_mutate task for {root_domain}: {res.get('live_found', 0)} live subdomains found.")
        except Exception as e:
            logger.error(f"Error in environment_mutate task for {root_domain}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Subdomain Environment Permutation Engine")
    parser.add_argument("--domain", required=True, help="Root domain (e.g. o2.co.uk or example.com)")
    parser.add_argument("--subdomain", help="Specific subdomain to mutate (e.g. cms-web.prod.priority.o2.co.uk)")
    parser.add_argument("--all-db", action="store_true", help="Mutate all known subdomains for this domain in MongoDB")
    parser.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution and only output generated permutations")
    parser.add_argument("--concurrency", type=int, default=50, help="DNS concurrency limit (default: 50)")

    args = parser.parse_args()

    async def main():
        agent = EnvironmentMutationAgent()
        agent.resolver.concurrency = args.concurrency

        if args.subdomain:
            mutator = SubdomainMutator()
            tokens = mutator.detect_environment_tokens(args.subdomain, args.domain)
            print(f"\n[*] Inspecting Subdomain: {args.subdomain}")
            print(f"[*] Detected Environment Tokens: {[t['env'] + t['idx'] for t in tokens]}")
            
            candidates = mutator.generate_mutations(args.subdomain, args.domain)
            print(f"[*] Generated {len(candidates)} Environment Permutations:")
            for c in sorted(candidates)[:15]:
                print(f"    - {c}")
            if len(candidates) > 15:
                print(f"    ... and {len(candidates) - 15} more.")

            if not args.no_resolve:
                print(f"\n[*] Resolving candidates via DNS (Wildcard-safe)...")
                live = await agent.resolver.filter_live_candidates(candidates, args.domain)
                print(f"\n[+] Live Permutations Discovered: {len(live)}")
                for h, ips in live.items():
                    print(f"    ✓ {h} -> {', '.join(ips)}")

        elif args.all_db:
            print(f"\n[*] Running Database Environment Mutation for domain: {args.domain}")
            res = await agent.mutate_and_discover_for_domain(
                args.domain,
                resolve_dns=not args.no_resolve
            )
            print(f"\n[+] Mutation Run Summary:")
            print(f"    Seeds Processed:         {res['seeds_count']}")
            print(f"    Environment Seeds:       {res['matching_seeds']}")
            print(f"    Candidates Generated:    {res['generated_candidates']}")
            print(f"    Live Resolving Hosts:    {res['live_found']}")
            print(f"    Queued for Verification: {res['queued_for_verification']}")
            if res['live_hosts']:
                print(f"\n[+] Discovered Live Hosts:")
                for h in res['live_hosts']:
                    print(f"    ✓ {h}")
        else:
            parser.print_help()

    asyncio.run(main())
