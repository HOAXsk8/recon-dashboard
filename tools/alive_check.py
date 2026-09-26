import asyncio
import datetime
import hashlib
import logging
import os
import re
import socket
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger
from dns_analytics import TakeoverDetector, AsnNetworkResolver, DnssecAuditor

VIEWDNS_API_KEY = os.environ.get("VIEWDNS_API_KEY", "")

class AliveCheckAgent(BaseAgent):
    def __init__(self):
        super().__init__("alive_check", "Subdomain Alive Checking Tool")
        self.takeover_detector = TakeoverDetector()
        self.asn_resolver = AsnNetworkResolver()
        self.dnssec_auditor = DnssecAuditor()

    async def get_ip(self, target):
        """Resolve target to IPv4 address with fallback to async DNS resolvers."""
        if not target:
            return None
        target = target.strip().rstrip(".")

        # 1. System resolver
        try:
            loop = asyncio.get_event_loop()
            res = await asyncio.wait_for(loop.getaddrinfo(target, None, family=socket.AF_INET), timeout=3.0)
            if res:
                return res[0][4][0]
        except Exception:
            pass

        # 2. Async DNS resolver fallback (Google & Cloudflare public DNS)
        try:
            import dns.asyncresolver
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 2.5
            resolver.lifetime = 3.0
            ans = await resolver.resolve(target, "A")
            for rdata in ans:
                return str(rdata).strip()
        except Exception:
            pass

        return None

    # ------------------------------------------------------------------
    # 1. IPv6 (AAAA) Record Auditing & Dual-Stack Bypass Detection
    # ------------------------------------------------------------------
    async def get_ipv6(self, target):
        """
        Resolve target to IPv6 address (AAAA record) using async DNS resolvers
        with fallback to system getaddrinfo.
        Returns the first resolved IPv6 address, or None if not found.
        """
        if not target:
            return None
        target = target.strip().rstrip(".")

        # 1. System resolver fallback
        try:
            loop = asyncio.get_event_loop()
            res = await asyncio.wait_for(loop.getaddrinfo(target, None, family=socket.AF_INET6), timeout=2.5)
            if res:
                return res[0][4][0]
        except Exception:
            pass

        # 2. Async DNS resolver (Google + Cloudflare IPv4 nameservers to query AAAA)
        try:
            import dns.asyncresolver
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 2.5
            resolver.lifetime = 3.0
            ans = await resolver.resolve(target, "AAAA")
            for rdata in ans:
                return str(rdata).strip()
        except Exception:
            pass
        return None

    async def probe_ipv6_ports(self, ipv6_addr: str) -> list:
        """
        Probe common web and management ports on an IPv6 address in parallel.
        Returns a list of open port numbers.
        """
        import socket
        # Test if host network stack can route IPv6 traffic before attempting connections
        try:
            test_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            test_sock.settimeout(0.5)
            test_sock.connect((ipv6_addr, 80))
            test_sock.close()
        except OSError:
            return []

        candidate_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 22]

        async def check_port(p):
            try:
                conn = asyncio.open_connection(ipv6_addr, p)
                _, writer = await asyncio.wait_for(conn, timeout=2.5)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return p
            except Exception:
                return None

        results = await asyncio.gather(*[check_port(p) for p in candidate_ports])
        return [p for p in results if p is not None]

    async def probe_ipv6_tls(self, ipv6_addr: str, hostname: str) -> bool:
        """
        Probe common TLS/HTTP ports on an IPv6 address to confirm it is responsive.
        Returns True if any port accepts a connection.
        """
        ports = await self.probe_ipv6_ports(ipv6_addr)
        return len(ports) > 0

    async def compare_dual_stack_banners(self, target: str, ipv4: str, ipv6: str) -> dict:
        """
        Compare HTTP/HTTPS response headers, server banners, and CDN presence between
        IPv4 (which may be CDN-shielded) and IPv6 (which may expose the origin directly).
        Returns a comparison dictionary indicating whether dual-stack bypass was detected.
        """
        import httpx

        async def fetch_endpoint_meta(ip_str: str, is_ipv6: bool) -> dict:
            meta = {
                "reachable": False,
                "status_code": None,
                "server": "",
                "via": "",
                "headers": {},
                "title": "",
                "cdn_detected": False,
                "cdn_provider": None,
                "scheme": None
            }
            ip_formatted = f"[{ip_str}]" if is_ipv6 else ip_str

            for scheme in ("https", "http"):
                url = f"{scheme}://{ip_formatted}"
                try:
                    async with httpx.AsyncClient(
                        timeout=4.5,
                        verify=False,
                        follow_redirects=True,
                        headers={"Host": target, "User-Agent": self.user_agent}
                    ) as client:
                        resp = await client.get(url)
                        meta["reachable"] = True
                        meta["status_code"] = resp.status_code
                        meta["scheme"] = scheme
                        server_val = resp.headers.get("server", "")
                        via_val = resp.headers.get("via", "")
                        meta["server"] = server_val
                        meta["via"] = via_val

                        for h in ["server", "via", "x-powered-by", "cf-ray", "x-amz-cf-id", "x-cache", "x-azure-ref", "akamai-origin-hop"]:
                            if h in resp.headers:
                                meta["headers"][h] = resp.headers[h]

                        m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                        if m:
                            meta["title"] = m.group(1).strip()[:100]

                        # Detect CDN signatures
                        hdr_str = " ".join([server_val, via_val, str(resp.headers)]).lower()
                        if "cloudflare" in hdr_str or "cf-ray" in resp.headers:
                            meta["cdn_detected"] = True
                            meta["cdn_provider"] = "Cloudflare"
                        elif "akamai" in hdr_str or "ghost" in hdr_str:
                            meta["cdn_detected"] = True
                            meta["cdn_provider"] = "Akamai"
                        elif "cloudfront" in hdr_str or "x-amz-cf-id" in resp.headers:
                            meta["cdn_detected"] = True
                            meta["cdn_provider"] = "AWS CloudFront"
                        elif "fastly" in hdr_str:
                            meta["cdn_detected"] = True
                            meta["cdn_provider"] = "Fastly"
                        elif "incapsula" in hdr_str:
                            meta["cdn_detected"] = True
                            meta["cdn_provider"] = "Incapsula"
                        elif "azure" in hdr_str or "x-azure-ref" in resp.headers:
                            meta["cdn_detected"] = True
                            meta["cdn_provider"] = "Azure Front Door"

                        break
                except Exception:
                    continue
            return meta

        v4_meta, v6_meta = await asyncio.gather(
            fetch_endpoint_meta(ipv4, False),
            fetch_endpoint_meta(ipv6, True)
        )

        comparison = {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "v4_reachable": v4_meta["reachable"],
            "v6_reachable": v6_meta["reachable"],
            "v4_server": v4_meta["server"],
            "v6_server": v6_meta["server"],
            "v4_cdn": v4_meta["cdn_provider"],
            "v6_cdn": v6_meta["cdn_provider"],
            "v4_status": v4_meta["status_code"],
            "v6_status": v6_meta["status_code"],
            "v6_title": v6_meta["title"],
            "bypass_detected": False,
            "reason": ""
        }

        if v4_meta["cdn_detected"] and v6_meta["reachable"] and not v6_meta["cdn_detected"]:
            comparison["bypass_detected"] = True
            v6_srv = v6_meta["server"] or "Unshielded Origin Web Server"
            comparison["reason"] = f"IPv4 is shielded behind {v4_meta['cdn_provider']}, whereas IPv6 responds directly without CDN/WAF headers ({v6_srv})."
        elif v4_meta["reachable"] and v6_meta["reachable"] and v4_meta["server"] and v6_meta["server"] and v4_meta["server"].lower() != v6_meta["server"].lower():
            if v4_meta["cdn_detected"]:
                comparison["bypass_detected"] = True
                comparison["reason"] = f"IPv4 server banner '{v4_meta['server']}' differs from IPv6 server banner '{v6_meta['server']}', indicating potential origin exposure over IPv6."

        return comparison

    # ------------------------------------------------------------------
    # 2. Historical DNS / Origin IP Uncloaking
    # ------------------------------------------------------------------
    async def fetch_historical_ips(self, target: str, current_ip: str) -> list:
        """
        Query RapidDNS, HackerTarget, and ViewDNS for historical IP associations.
        For each candidate IP, test whether the origin web server responds directly.
        Returns a list of dicts with: { ip, source, responds_directly, status_code, server, title }
        """
        import httpx
        historical = []
        seen = {current_ip} if current_ip else set()

        # 1. RapidDNS (Free, passive historical DNS)
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers={"User-Agent": self.user_agent}) as client:
                r = await client.get(f"https://rapiddns.io/s/{target}?same_sub=1")
                if r.status_code == 200:
                    found_ips = set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", r.text))
                    for ip in found_ips:
                        if ip not in seen and self._is_valid_public_ip(ip):
                            seen.add(ip)
                            historical.append({"ip": ip, "source": "RapidDNS"})
        except Exception as e:
            logger.debug(f"[HistoricalIPs] RapidDNS failed for {target}: {e}")

        # 2. HackerTarget (Free)
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers={"User-Agent": self.user_agent}) as client:
                resp = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={target}"
                )
                if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
                    for line in resp.text.splitlines():
                        parts = line.strip().split(",")
                        if len(parts) == 2:
                            ip = parts[1].strip()
                            if ip and ip not in seen and self._is_valid_public_ip(ip):
                                seen.add(ip)
                                historical.append({"ip": ip, "source": "HackerTarget"})
        except Exception as e:
            logger.debug(f"[HistoricalIPs] HackerTarget failed for {target}: {e}")

        # 3. ViewDNS (Optional, if VIEWDNS_API_KEY configured)
        if VIEWDNS_API_KEY:
            try:
                async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers={"User-Agent": self.user_agent}) as client:
                    resp = await client.get(
                        f"https://api.viewdns.info/iphistory/?domain={target}&apikey={VIEWDNS_API_KEY}&output=json"
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for entry in data.get("response", {}).get("records", []):
                            ip = entry.get("ip", "").strip()
                            if ip and ip not in seen and self._is_valid_public_ip(ip):
                                seen.add(ip)
                                historical.append({"ip": ip, "source": "ViewDNS"})
            except Exception as e:
                logger.debug(f"[HistoricalIPs] ViewDNS failed for {target}: {e}")

        # Probe candidate historical IPs directly (up to 15 candidates)
        candidates = historical[:15]
        probe_tasks = [self._probe_direct_origin(entry["ip"], target) for entry in candidates]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        for entry, res in zip(candidates, probe_results):
            if isinstance(res, dict):
                entry.update(res)
            else:
                entry["responds_directly"] = False

        exposed = [e for e in candidates if e.get("responds_directly")]
        if exposed:
            logger.warning(f"[HistoricalIPs] {target}: {len(exposed)} historical IPs respond directly (potential origin exposure)")
        else:
            logger.debug(f"[HistoricalIPs] {target}: Found {len(candidates)} historical IPs, none respond directly")

        return candidates

    def _is_valid_public_ip(self, ip: str) -> bool:
        """Return True if ip looks like a routable public IPv4 address."""
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return False
        parts = list(map(int, ip.split(".")))
        if any(p < 0 or p > 255 for p in parts):
            return False
        if parts[0] in (10, 127):
            return False
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return False
        if parts[0] == 192 and parts[1] == 168:
            return False
        if parts[0] in (0, 255):
            return False
        return True

    async def _probe_direct_origin(self, ip: str, hostname: str) -> dict:
        """
        Send a direct HTTP/HTTPS request to the IP with a Host header matching
        the original hostname. Tests whether the origin server is directly accessible,
        filtering out generic CDN direct-access block pages.
        """
        import httpx
        res = {
            "responds_directly": False,
            "status_code": None,
            "server": "",
            "title": "",
            "scheme": None
        }

        for scheme in ("https", "http"):
            url = f"{scheme}://{ip}"
            try:
                async with httpx.AsyncClient(
                    timeout=3.5, verify=False, follow_redirects=False,
                    headers={"Host": hostname, "User-Agent": self.user_agent}
                ) as client:
                    resp = await client.get(url)
                    text_sample = resp.text[:1000].lower()
                    # Filter out CDN direct access error blocks:
                    # Cloudflare Error 1003 "Direct IP access not allowed"
                    # Akamai "Access Denied - Reference #"
                    if "direct ip access not allowed" in text_sample or "error 1003" in text_sample:
                        continue
                    if "access denied" in text_sample and "reference #" in text_sample:
                        continue

                    if resp.status_code < 500:
                        res["responds_directly"] = True
                        res["status_code"] = resp.status_code
                        res["scheme"] = scheme
                        res["server"] = resp.headers.get("server", "")

                        m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                        if m:
                            res["title"] = m.group(1).strip()[:80]
                        return res
            except Exception:
                continue
        return res

    # ------------------------------------------------------------------
    # 3. DNSSEC & Zone Walking (NSEC/NSEC3)
    # ------------------------------------------------------------------
    async def audit_dnssec(self, domain: str, root_domain: str) -> dict:
        """
        Audit DNSSEC configuration, detect NSEC vs NSEC3, and if plain NSEC is used,
        conduct an automated NSEC zone walk to extract authoritative zone names.
        Queues newly discovered zone names into the verification task pipeline.
        """
        dnssec_res = await self.dnssec_auditor.check_dnssec(domain)

        walked_names = []
        if dnssec_res.get("zone_walkable"):
            logger.warning(f"[DNSSEC] Plain NSEC detected for {domain}. Attempting NSEC zone walk...")
            walked_names = await self.dnssec_auditor.attempt_nsec_walk(domain)
            if walked_names:
                queued_count = 0
                for name in walked_names:
                    if name != domain:
                        exists = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": name,
                            "task_type": "verification"
                        })
                        if not exists:
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": name,
                                "task_type": "verification",
                                "status": "pending",
                                "source": "dnssec_nsec_walk",
                                "created_at": datetime.datetime.utcnow()
                            })
                            queued_count += 1
                logger.info(f"[DNSSEC] Queued {queued_count} walked names from {domain} into verification queue.")

                await self.create_alert(
                    title=f"DNSSEC Plain NSEC Zone Walk Vulnerability: {domain}",
                    description=(
                        f"The domain {domain} implements DNSSEC using plain NSEC records without NSEC3 salt/hashing. "
                        f"An automated NSEC zone walk successfully enumerated {len(walked_names)} authoritative "
                        f"zone record names without performing any DNS brute-forcing or dictionary guessing."
                    ),
                    target=domain,
                    risk_level="high",
                    details={
                        "algorithm": dnssec_res.get("algorithm"),
                        "nsec_type": dnssec_res.get("nsec_type"),
                        "total_walked": len(walked_names),
                        "walked_subdomains": walked_names[:50]
                    },
                    exploitation_suggestions=[
                        "Upgrade DNSSEC configuration to use NSEC3 with randomized iteration salts to prevent zone walking.",
                        "Inspect newly enumerated zone names for internal, staging, and administrative portals.",
                        "Verify whether newly exposed subdomains have dangling CNAME records or unauthenticated services."
                    ],
                    alert_type="dnssec_nsec_zone_walk"
                )

        dnssec_res["walked_names_count"] = len(walked_names)
        dnssec_res["walked_names"] = walked_names[:100]
        return dnssec_res

    async def is_wildcard(self, domain):
        """Check if a domain has wildcard DNS."""
        if not domain:
            return None
        random_sub = f"check-{datetime.datetime.utcnow().timestamp()}.{domain}"
        ip = await self.get_ip(random_sub)
        return ip

    async def _check_single_port(self, target, port, timeout=3.0, target_ip=None):
        # Prefer connecting to resolved target_ip directly to bypass IPv6 routing blackholes
        host = target_ip if target_ip else target
        try:
            conn = asyncio.open_connection(host, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
            return True
        except Exception:
            return False

    async def is_alive(self, target, target_ip=None):
        """
        Verify if a target is alive using tiered port checking with HTTP/HTTPS fallback.
        Checks primary web ports (80, 443) first, using direct IPv4 connect when available.
        """
        # Tier 1: Primary web ports (80, 443)
        tier1_ports = [80, 443]
        tasks1 = [asyncio.create_task(self._check_single_port(target, p, timeout=2.5, target_ip=target_ip)) for p in tier1_ports]
        try:
            for coro in asyncio.as_completed(tasks1):
                if await coro:
                    for t in tasks1:
                        if not t.done():
                            t.cancel()
                    return True
        finally:
            for t in tasks1:
                if not t.done():
                    t.cancel()

        # HTTP/HTTPS probe fallback via httpx (handles HTTP redirects, CloudFront, Fastly, WAFs)
        # Using local_address="0.0.0.0" forces IPv4 and prevents IPv6 routing timeouts
        try:
            import httpx
            transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0", verify=False)
            async with httpx.AsyncClient(transport=transport, timeout=3.0, follow_redirects=False) as client:
                for scheme in ("https", "http"):
                    try:
                        r = await client.head(f"{scheme}://{target}", headers={"Host": target, "User-Agent": self.user_agent})
                        if r.status_code is not None and r.status_code > 0:
                            return True
                    except Exception:
                        pass
        except Exception:
            pass

        # Tier 2: Common alternate web ports
        tier2_ports = [8080, 8443, 8000, 8888]
        tasks2 = [asyncio.create_task(self._check_single_port(target, p, timeout=2.5, target_ip=target_ip)) for p in tier2_ports]
        try:
            for coro in asyncio.as_completed(tasks2):
                if await coro:
                    for t in tasks2:
                        if not t.done():
                            t.cancel()
                    return True
        finally:
            for t in tasks2:
                if not t.done():
                    t.cancel()

        # Tier 3: Other auxiliary services
        tier3_ports = [22, 21, 25, 53, 3389, 8081, 8088, 3000, 5000, 9000]
        tasks3 = [asyncio.create_task(self._check_single_port(target, p, timeout=2.0, target_ip=target_ip)) for p in tier3_ports]
        try:
            for coro in asyncio.as_completed(tasks3):
                if await coro:
                    for t in tasks3:
                        if not t.done():
                            t.cancel()
                    return True
        finally:
            for t in tasks3:
                if not t.done():
                    t.cancel()

        return False

    async def process_single_task(self, task):
        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]

        try:
            # 1. Check for wildcard on the parent domain
            parent_domain = ".".join(target.split(".")[1:]) if "." in target else ""
            wildcard_ip = await self.is_wildcard(parent_domain) if parent_domain else None

            # Resolve IPv4 and IPv6 concurrently
            target_ip, target_ipv6 = await asyncio.gather(
                self.get_ip(target),
                self.get_ipv6(target)
            )

            is_potential_fp = False
            if wildcard_ip and target_ip == wildcard_ip:
                is_potential_fp = True
                logger.info(f"Target {target} matches wildcard IP {wildcard_ip}. Requiring open port.")

            # 2. Parallel alive check across common ports
            alive = await self.is_alive(target, target_ip=target_ip)

            # If it's a potential FP and no ports are open, mark as not alive
            if is_potential_fp and not alive:
                logger.info(f"Target {target} is a Wildcard FP (No ports open).")
                alive = False

            # 3. IPv6 dual-stack probe, open ports, and banner comparison
            ipv6_responds = False
            ipv6_ports = []
            dual_stack_comparison = None
            if target_ipv6:
                try:
                    ipv6_ports = await self.probe_ipv6_ports(target_ipv6)
                    ipv6_responds = len(ipv6_ports) > 0
                    logger.info(f"[IPv6] {target} -> {target_ipv6} (open ports={ipv6_ports})")

                    if target_ip and (ipv6_responds or alive):
                        dual_stack_comparison = await self.compare_dual_stack_banners(target, target_ip, target_ipv6)
                        if dual_stack_comparison.get("bypass_detected"):
                            await self.create_alert(
                                title=f"Dual-Stack Origin / CDN Bypass Detected: {target}",
                                description=(
                                    f"{target} has both IPv4 ({target_ip}) and IPv6 ({target_ipv6}) configured. "
                                    f"{dual_stack_comparison['reason']} This allows direct traffic to origin and bypasses WAF/CDN rules."
                                ),
                                target=target,
                                risk_level="high",
                                details={
                                    "target": target,
                                    "ipv4": target_ip,
                                    "ipv6": target_ipv6,
                                    "ipv4_server": dual_stack_comparison.get("v4_server"),
                                    "ipv6_server": dual_stack_comparison.get("v6_server"),
                                    "ipv4_cdn": dual_stack_comparison.get("v4_cdn"),
                                    "ipv6_cdn": dual_stack_comparison.get("v6_cdn"),
                                    "ipv6_open_ports": ipv6_ports
                                },
                                exploitation_suggestions=[
                                    f"Send direct requests to https://[{target_ipv6}]/ with 'Host: {target}' to verify if CDN controls are bypassed.",
                                    "Check if origin-only HTTP headers, internal routes, or administrative endpoints are reachable over IPv6.",
                                    "Align IPv6 routing with WAF/CDN proxy or disable unshielded AAAA records."
                                ],
                                alert_type="dual_stack_origin_exposure"
                            )
                except Exception as ie:
                    logger.debug(f"[IPv6] Probe failed for {target}: {ie}")

            # 4. Autonomous Subdomain Takeover & Dangling DNS check
            takeover_res = None
            is_takeover_suppressed = False
            try:
                takeover_res = await self.takeover_detector.audit_subdomain_takeover(target)
                if takeover_res:
                    # Check if takeover on this target was marked as False Positive, muted, or suppressed
                    fp_title = f"Subdomain Takeover Risk: Dangling CNAME on {target}"
                    fp_hash = hashlib.sha256(f"{target}|{fp_title}".encode()).hexdigest()
                    suppressed_fp = await self.fingerprints_col.find_one({"fingerprint": fp_hash, "status": "suppressed"})
                    if suppressed_fp:
                        is_takeover_suppressed = True
                    else:
                        fp_lead = await self.leads_col.find_one({
                            "target": target,
                            "status": {"$in": ["false_positive", "benign", "muted"]},
                            "$or": [
                                {"alert_type": {"$in": ["dangling_dns_takeover", "subdomain_takeover", "takeover", "cloud_storage_takeover"]}},
                                {"title": {"$regex": "takeover|dangling", "$options": "i"}}
                            ]
                        })
                        if fp_lead:
                            is_takeover_suppressed = True
                        else:
                            dom_chk = await self.domains_col.find_one({
                                "$or": [
                                    {"infrastructure.subdomains": {"$elemMatch": {"name": target, "takeover_false_positive": True}}},
                                    {"domain": target, "takeover_false_positive": True}
                                ]
                            })
                            if dom_chk:
                                is_takeover_suppressed = True

                    if is_takeover_suppressed:
                        logger.info(f"[Takeover Suppressed] Subdomain takeover on {target} is marked as False Positive/suppressed. Skipping alert and clearing indicators.")
                        takeover_res = None
                    else:
                        logger.warning(f"DANGLING DNS / TAKEOVER DETECTED on {target} -> {takeover_res.get('cname')} ({takeover_res.get('provider')})")
                        await self.create_alert(
                            title=f"Subdomain Takeover Risk: Dangling CNAME on {target}",
                            description=(
                                f"The subdomain {target} points via CNAME to {takeover_res.get('cname')} ({takeover_res.get('provider')}). "
                                f"The canonical service appears unallocated or de-provisioned (Evidence: {takeover_res.get('fingerprint')}), "
                                f"allowing an adversary to claim the resource and hijack the domain."
                            ),
                            target=target,
                            risk_level=takeover_res.get("risk", "high"),
                            details=takeover_res,
                            exploitation_suggestions=[
                                f"Attempt to claim/register the {takeover_res.get('provider')} resource ({takeover_res.get('cname')}) in your cloud account to verify ownership.",
                                f"If the service was decommissioned, remove the dangling CNAME DNS record for {target} immediately.",
                                "Audit DNS zones for other dangling aliases pointing to obsolete cloud services."
                            ],
                            alert_type="dangling_dns_takeover"
                        )
            except Exception as te:
                logger.error(f"Error auditing takeover for {target}: {te}")

            # 5. Resolve ASN, Org, and Reverse PTR for discovered IP
            asn_info = {}
            if target_ip:
                try:
                    asn_info = await self.asn_resolver.resolve_ip(target_ip)
                except Exception as ae:
                    logger.debug(f"Error resolving ASN for {target_ip}: {ae}")

            # Also check for ASN mismatch between IPv4 and IPv6 as another indicator of dual-stack bypass
            if target_ip and target_ipv6 and ipv6_responds and not (dual_stack_comparison and dual_stack_comparison.get("bypass_detected")):
                try:
                    ipv6_asn_info = await self.asn_resolver.resolve_ip(target_ipv6)
                    ipv4_asn = asn_info.get("asn")
                    ipv6_asn = ipv6_asn_info.get("asn")
                    if ipv4_asn and ipv6_asn and ipv4_asn != ipv6_asn:
                        await self.create_alert(
                            title=f"Dual-Stack Origin Exposure (ASN Mismatch): {target}",
                            description=(
                                f"{target} uses IPv4 ({target_ip}, ASN {ipv4_asn} — {asn_info.get('org', 'Unknown')}) and "
                                f"IPv6 ({target_ipv6}, ASN {ipv6_asn} — {ipv6_asn_info.get('org', 'Unknown')}). "
                                f"The IPv6 address resolves to a different network and may bypass CDN/WAF filtering entirely."
                            ),
                            target=target,
                            risk_level="high",
                            details={
                                "ipv4": target_ip,
                                "ipv4_asn": ipv4_asn,
                                "ipv4_org": asn_info.get("org"),
                                "ipv6": target_ipv6,
                                "ipv6_asn": ipv6_asn,
                                "ipv6_org": ipv6_asn_info.get("org"),
                                "ipv6_open_ports": ipv6_ports
                            },
                            exploitation_suggestions=[
                                f"Test direct access to https://[{target_ipv6}]/ with Host: {target} header.",
                                "Compare HTTP response headers between IPv4 and IPv6 paths for WAF/CDN differences.",
                                "Check if IPv6 origin exposes internal server version banners or debug endpoints."
                            ],
                            alert_type="dual_stack_origin_exposure"
                        )
                except Exception as da:
                    logger.debug(f"[IPv6 Bypass] ASN comparison failed for {target}: {da}")

            # 6. Historical IP uncloaking — run for root domain and www portal
            historical_ips = []
            if (target == root_domain or target == f"www.{root_domain}") and target_ip:
                try:
                    historical_ips = await self.fetch_historical_ips(target, target_ip)
                    if target == root_domain and historical_ips:
                        await self.domains_col.update_one(
                            {"domain": root_domain},
                            {"$set": {"infrastructure.historical_ips": historical_ips}}
                        )
                    exposed_origins = [h for h in historical_ips if h.get("responds_directly")]
                    if exposed_origins:
                        await self.create_alert(
                            title=f"Historical Origin IP Exposed: {target}",
                            description=(
                                f"{len(exposed_origins)} historical IP address(es) for {target} respond directly to "
                                f"HTTP/HTTPS requests with Host: {target}, suggesting the origin server may be "
                                f"reachable without passing through the CDN or WAF."
                            ),
                            target=target,
                            risk_level="high",
                            details={
                                "current_ip": target_ip,
                                "exposed_origins": exposed_origins,
                                "all_historical_ips": historical_ips,
                            },
                            exploitation_suggestions=[
                                f"Test direct HTTP/HTTPS access to {h['ip']} with Host: {target} header."
                                for h in exposed_origins
                            ],
                            alert_type="origin_ip_exposed",
                            root_domain=root_domain
                        )
                except Exception as he:
                    logger.debug(f"[HistoricalIPs] Error for {target}: {he}")

            # 7. DNSSEC & Zone Walking (NSEC/NSEC3) — audit root/apex domain
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            if target == root_domain or not domain_doc or not domain_doc.get("infrastructure", {}).get("dnssec"):
                try:
                    dnssec_data = await self.audit_dnssec(target if target == root_domain else root_domain, root_domain)
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$set": {"infrastructure.dnssec": dnssec_data}}
                    )
                except Exception as de:
                    logger.debug(f"[DNSSEC] Audit failed for {target}: {de}")

            # 8. Asset Validation:
            # - Dangling takeover detected: Valid asset
            # - Responded on an open port: Valid asset (alive=True)
            # - Resolves to a valid IP and is NOT a wildcard catch-all: Valid asset in DNS (eliminates false negatives)
            is_valid_asset = bool(takeover_res) or alive or (bool(target_ip) and not is_potential_fp)

            # 9. Build Subdomain Metadata & Track Infrastructure Drift History
            existing_sub = None
            if domain_doc and domain_doc.get("infrastructure", {}).get("subdomains"):
                matching_subs = [s for s in domain_doc["infrastructure"]["subdomains"] if s.get("name") == target]
                if matching_subs:
                    existing_sub = matching_subs[0]

            now_iso = datetime.datetime.utcnow().isoformat()
            history_events = []

            if existing_sub:
                old_ip = existing_sub.get("ip")
                if old_ip and target_ip and old_ip != target_ip:
                    history_events.append({
                        "timestamp": now_iso,
                        "event_type": "dns_ip_change",
                        "target": target,
                        "details": f"DNS IP address changed from {old_ip} to {target_ip}",
                        "severity": "info"
                    })
            elif target != root_domain and is_valid_asset:
                history_events.append({
                    "timestamp": now_iso,
                    "event_type": "subdomain_discovered",
                    "target": target,
                    "details": f"Discovered subdomain {target} ({target_ip or 'No IP'})",
                    "severity": "info"
                })

            if takeover_res:
                # Deduplicate: only log timeline event if this takeover was not already detected on this target
                already_detected = False
                if existing_sub and existing_sub.get("dangling_takeover"):
                    if existing_sub.get("cname") == takeover_res.get("cname"):
                        already_detected = True

                if not already_detected:
                    history_events.append({
                        "timestamp": now_iso,
                        "event_type": "dangling_takeover_detected",
                        "target": target,
                        "details": f"Dangling CNAME takeover identified on {target} -> {takeover_res.get('cname')}",
                        "severity": "critical"
                    })

            if history_events:
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$push": {"history": {"$each": history_events, "$slice": -300}}}
                )

            sub_update_fields = {
                "infrastructure.subdomains.$.alive": alive,
                "infrastructure.subdomains.$.last_scanned": now_iso
            }

            if target_ip:
                sub_update_fields["infrastructure.subdomains.$.ip"] = target_ip
            if target_ipv6:
                sub_update_fields["infrastructure.subdomains.$.ipv6"] = target_ipv6
                sub_update_fields["infrastructure.subdomains.$.ipv6_responds"] = ipv6_responds
                sub_update_fields["infrastructure.subdomains.$.ipv6_ports"] = ipv6_ports
                if dual_stack_comparison:
                    sub_update_fields["infrastructure.subdomains.$.dual_stack_bypass"] = dual_stack_comparison.get("bypass_detected", False)
                    sub_update_fields["infrastructure.subdomains.$.dual_stack_details"] = dual_stack_comparison
            if historical_ips:
                sub_update_fields["infrastructure.subdomains.$.historical_ips"] = historical_ips
            if asn_info.get("asn"):
                sub_update_fields["infrastructure.subdomains.$.asn"] = asn_info.get("asn")
                sub_update_fields["infrastructure.subdomains.$.as_org"] = asn_info.get("org")
                sub_update_fields["infrastructure.subdomains.$.cidr"] = asn_info.get("cidr")
            if asn_info.get("ptr"):
                sub_update_fields["infrastructure.subdomains.$.ptr"] = asn_info.get("ptr")

            if is_takeover_suppressed:
                sub_update_fields["infrastructure.subdomains.$.dangling_takeover"] = False
                sub_update_fields["infrastructure.subdomains.$.takeover_provider"] = None
                sub_update_fields["infrastructure.subdomains.$.takeover_risk"] = None
                sub_update_fields["infrastructure.subdomains.$.takeover_false_positive"] = True
            elif takeover_res:
                sub_update_fields["infrastructure.subdomains.$.dangling_takeover"] = True
                sub_update_fields["infrastructure.subdomains.$.cname"] = takeover_res.get("cname")
                sub_update_fields["infrastructure.subdomains.$.takeover_provider"] = takeover_res.get("provider")
                sub_update_fields["infrastructure.subdomains.$.takeover_risk"] = takeover_res.get("risk")

            if is_valid_asset:
                # Add to domains collection if it's a subdomain and not yet present
                if target != root_domain:
                    new_sub_doc = {
                        "name": target,
                        "alive": alive,
                        "added_at": now_iso,
                        "last_scanned": now_iso
                    }
                    if target_ip:
                        new_sub_doc["ip"] = target_ip
                    if target_ipv6:
                        new_sub_doc["ipv6"] = target_ipv6
                        new_sub_doc["ipv6_responds"] = ipv6_responds
                        new_sub_doc["ipv6_ports"] = ipv6_ports
                        if dual_stack_comparison:
                            new_sub_doc["dual_stack_bypass"] = dual_stack_comparison.get("bypass_detected", False)
                            new_sub_doc["dual_stack_details"] = dual_stack_comparison
                    if historical_ips:
                        new_sub_doc["historical_ips"] = historical_ips
                    if asn_info.get("asn"):
                        new_sub_doc["asn"] = asn_info.get("asn")
                        new_sub_doc["as_org"] = asn_info.get("org")
                        new_sub_doc["cidr"] = asn_info.get("cidr")
                    if asn_info.get("ptr"):
                        new_sub_doc["ptr"] = asn_info.get("ptr")
                    if is_takeover_suppressed:
                        new_sub_doc["dangling_takeover"] = False
                        new_sub_doc["takeover_provider"] = None
                        new_sub_doc["takeover_risk"] = None
                        new_sub_doc["takeover_false_positive"] = True
                    elif takeover_res:
                        new_sub_doc["dangling_takeover"] = True
                        new_sub_doc["cname"] = takeover_res.get("cname")
                        new_sub_doc["takeover_provider"] = takeover_res.get("provider")
                        new_sub_doc["takeover_risk"] = takeover_res.get("risk")

                    await self.domains_col.update_one(
                        {
                            "domain": root_domain,
                            "infrastructure.subdomains.name": {"$ne": target}
                        },
                        {
                            "$push": {
                                "infrastructure.subdomains": new_sub_doc
                            }
                        }
                    )

                # Queue Nmap port scan task (top 1000 ports) for all verified IP assets
                if target_ip or alive:
                    exists_scan = await self.tasks_col.find_one({
                        "root_domain": root_domain,
                        "target": target,
                        "task_type": "scan"
                    })
                    if not exists_scan:
                        scan_task = {
                            "root_domain": root_domain,
                            "target": target,
                            "task_type": "scan",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        }
                        if ws_id:
                            scan_task["workspace_id"] = ws_id
                        await self.tasks_col.insert_one(scan_task)
                        logger.info(f"Queued Nmap port scan task for verified asset: {target}")

                # Record full enriched status in infrastructure.subdomains
                if target != root_domain:
                    await self.domains_col.update_one(
                        {"domain": root_domain, "infrastructure.subdomains.name": target},
                        {"$set": sub_update_fields}
                    )
                else:
                    if is_takeover_suppressed:
                        await self.domains_col.update_one(
                            {"domain": root_domain},
                            {"$set": {
                                "dangling_takeover": False,
                                "takeover_provider": None,
                                "takeover_risk": None,
                                "takeover_false_positive": True
                            }}
                        )
                    elif takeover_res:
                        await self.domains_col.update_one(
                            {"domain": root_domain},
                            {"$set": {
                                "dangling_takeover": True,
                                "cname": takeover_res.get("cname"),
                                "takeover_provider": takeover_res.get("provider"),
                                "takeover_risk": takeover_res.get("risk")
                            }}
                        )

                logger.info(f"Target {target} processed (alive={alive}, ipv6={target_ipv6}, valid_asset=True, takeover={bool(takeover_res)}, asn={asn_info.get('asn')}).")
            else:
                logger.info(f"Target {target} is DEAD or Wildcard FP.")
                if target != root_domain:
                    await self.domains_col.update_one(
                        {"domain": root_domain, "infrastructure.subdomains.name": target},
                        {"$set": {
                            "infrastructure.subdomains.$.alive": False,
                            "infrastructure.subdomains.$.scanned": True,
                            "infrastructure.subdomains.$.last_scanned": datetime.datetime.utcnow().isoformat()
                        }}
                    )

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "alive": alive, "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in verification for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

    async def process_tasks(self):
        """Fetch and process up to 10 verification tasks concurrently."""
        tasks = []
        for _ in range(10):
            t = await self.get_next_task("verification")
            if not t:
                break
            tasks.append(t)

        if not tasks:
            return False

        await asyncio.gather(*[self.process_single_task(t) for t in tasks])
        return True

    async def main_loop(self):
        asyncio.create_task(self.update_heartbeat())
        while True:
            await self.pause_event.wait()
            try:
                had_tasks = await self.process_tasks()
                if not had_tasks:
                    await asyncio.sleep(2)
                else:
                    await asyncio.sleep(0.05)
            except Exception as e:
                logger.error(f"Alive-check main loop error: {e}")
                await asyncio.sleep(2)

if __name__ == "__main__":
    agent = AliveCheckAgent()
    asyncio.run(agent.main_loop())
