"""
dns_analytics.py - Advanced DNS Record Analytics, Subdomain Takeover Engine & ASN Resolver
Part of the RDash Reconnaissance Platform.
"""

import asyncio
import re
import socket
import logging
from typing import Dict, List, Optional, Any, Set, Tuple

import dns.resolver
import dns.asyncresolver
import httpx

logger = logging.getLogger("dns_analytics")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


# =====================================================================
# 1. Subdomain Takeover Fingerprints & Detector
# =====================================================================

TAKEOVER_SIGNATURES = [
    {
        "provider": "AWS S3 / CloudFront",
        "cname_patterns": [r"\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com", r"\.cloudfront\.net"],
        "fingerprints": [
            "The specified bucket does not exist",
            "NoSuchBucket",
            "Bad Request: The request could not be satisfied",
            "ERROR: The request could not be satisfied"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "GitHub Pages",
        "cname_patterns": [r"\.github\.io"],
        "fingerprints": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Heroku",
        "cname_patterns": [r"\.herokuapp\.com", r"\.herokussl\.com", r"\.herokudns\.com"],
        "fingerprints": [
            "No such app",
            "There's nothing here, yet.",
            "herokucdn.com/error-pages/no-such-app.html"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Azure Web Apps / Traffic Manager",
        "cname_patterns": [
            r"\.azurewebsites\.net",
            r"\.cloudapp\.net",
            r"\.trafficmanager\.net",
            r"\.blob\.core\.windows\.net"
        ],
        "fingerprints": [
            "404 Web Site not found",
            "The resource you are looking for has been removed, had its name changed, or is temporarily unavailable.",
            "Default Web Site Page - Azure"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Shopify",
        "cname_patterns": [r"\.myshopify\.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable.",
            "Only one Shopify store can be set up per domain name"
        ],
        "nxdomain_check": False
    },
    {
        "provider": "Zendesk",
        "cname_patterns": [r"\.zendesk\.com"],
        "fingerprints": [
            "Help Center Closed",
            "No such app",
            "this help center no longer exists"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Fastly",
        "cname_patterns": [r"\.fastly\.net", r"\.fastlylb\.net"],
        "fingerprints": [
            "Fastly error: unknown domain",
            "The Fastly VCL configuration for this domain is missing"
        ],
        "nxdomain_check": False
    },
    {
        "provider": "Ghost",
        "cname_patterns": [r"\.ghost\.io"],
        "fingerprints": [
            "The thing you were looking for is no longer here",
            "The site you are looking for is not configured"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Pantheon",
        "cname_patterns": [r"\.pantheonsite\.io"],
        "fingerprints": [
            "The gods are wise, but do not know of the site which you seek.",
            "404 error unknown site!"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Readme.io",
        "cname_patterns": [r"\.readme\.io"],
        "fingerprints": [
            "Project doesnt exist... yet!",
            "Project does not exist"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Surge.sh",
        "cname_patterns": [r"\.surge\.sh"],
        "fingerprints": [
            "project not found",
            "repository not found"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Tumblr",
        "cname_patterns": [r"\.tumblr\.com"],
        "fingerprints": [
            "Whatever you were looking for doesn't seem to exist",
            "There's nothing here."
        ],
        "nxdomain_check": True
    },
    {
        "provider": "WordPress.com",
        "cname_patterns": [r"\.wordpress\.com"],
        "fingerprints": [
            "Do you want to register",
            "doesn't exist"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Bitbucket",
        "cname_patterns": [r"\.bitbucket\.io"],
        "fingerprints": [
            "Repository not found",
            "The specified repository does not exist"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Squarespace",
        "cname_patterns": [r"\.squarespace\.com"],
        "fingerprints": [
            "No Such Account",
            "Squarespace - Claim This Domain"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Unbounce",
        "cname_patterns": [r"\.unbouncepages\.com"],
        "fingerprints": [
            "The requested URL was not found on this server.",
            "The page you are looking for is not here."
        ],
        "nxdomain_check": True
    },
    {
        "provider": "HelpScout",
        "cname_patterns": [r"\.helpscoutdocs\.com"],
        "fingerprints": [
            "No settings were found for this company",
            "Help Scout Docs"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Fly.io",
        "cname_patterns": [r"\.fly\.dev"],
        "fingerprints": [
            "404 Not Found",
            "Could not find app"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Ngrok",
        "cname_patterns": [r"\.ngrok\.io", r"\.ngrok-free\.app"],
        "fingerprints": [
            "Tunnel *.ngrok.io not found",
            "ngrok gateway error"
        ],
        "nxdomain_check": True
    },
    {
        "provider": "Statuspage",
        "cname_patterns": [r"\.statuspage\.io"],
        "fingerprints": [
            "You are being redirected to https://statuspage.io",
            "Statuspage not found"
        ],
        "nxdomain_check": True
    }
]

COMMON_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"


class TakeoverDetector:
    """
    Analyzes CNAME aliases, tests for canonical host NXDOMAIN,
    and probes HTTP/HTTPS responses against cloud provider fingerprints.
    """

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": COMMON_USER_AGENT,
            "Accept": "*/*"
        }

    async def get_cname(self, hostname: str) -> Optional[str]:
        """Fetch the CNAME target for a hostname."""
        clean_host = hostname.strip().rstrip(".")
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            answers = await resolver.resolve(clean_host, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".").lower()
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout, Exception):
            pass
        return None

    async def check_canonical_nxdomain(self, canonical_host: str) -> bool:
        """Check if the CNAME canonical target hostname resolves to NXDOMAIN."""
        clean = canonical_host.strip().rstrip(".")
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            await resolver.resolve(clean, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except (dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            # Try resolving AAAA as well
            try:
                await resolver.resolve(clean, "AAAA")
                return False
            except dns.resolver.NXDOMAIN:
                return True
            except Exception:
                return False

    async def audit_subdomain_takeover(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Audit a domain or subdomain for dangling CNAME and takeover vulnerability.
        Returns a takeover vulnerability dict if confirmed, else None.
        """
        clean_host = hostname.strip().rstrip(".")
        cname = await self.get_cname(clean_host)
        if not cname:
            return None

        matched_sig = None
        for sig in TAKEOVER_SIGNATURES:
            for pattern in sig["cname_patterns"]:
                if re.search(pattern, cname, re.I):
                    matched_sig = sig
                    break
            if matched_sig:
                break

        is_canonical_nxdomain = await self.check_canonical_nxdomain(cname)

        # If it's a known provider or resolves to NXDOMAIN, probe HTTP/HTTPS
        vulnerable = False
        detected_provider = matched_sig["provider"] if matched_sig else "Unknown Service Provider"
        matched_fingerprint = None
        evidence_status = None
        evidence_url = None

        # Case A: Canonical host returned NXDOMAIN directly
        if is_canonical_nxdomain:
            vulnerable = True
            matched_fingerprint = f"Canonical CNAME ({cname}) resolves to NXDOMAIN (Non-Existent Domain)."
            evidence_status = "NXDOMAIN"

        # Case B: Probe HTTP and HTTPS endpoints for unclaimed service signatures
        urls = [f"http://{clean_host}", f"https://{clean_host}"]
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False, headers=self.headers) as client:
            for url in urls:
                try:
                    resp = await client.get(url)
                    body = resp.text
                    status_code = resp.status_code

                    # If we have a matched provider, check its specific fingerprints
                    if matched_sig:
                        for fp in matched_sig["fingerprints"]:
                            if fp in body:
                                vulnerable = True
                                matched_fingerprint = fp
                                evidence_status = status_code
                                evidence_url = str(resp.url)
                                break

                    # Also check all fingerprints in case of provider CNAME chaining
                    if not vulnerable:
                        for sig in TAKEOVER_SIGNATURES:
                            for fp in sig["fingerprints"]:
                                if fp in body:
                                    vulnerable = True
                                    detected_provider = sig["provider"]
                                    matched_fingerprint = fp
                                    evidence_status = status_code
                                    evidence_url = str(resp.url)
                                    break
                            if vulnerable:
                                break

                    if vulnerable:
                        break
                except Exception:
                    continue

        if vulnerable:
            return {
                "target": clean_host,
                "cname": cname,
                "provider": detected_provider,
                "fingerprint": matched_fingerprint,
                "is_nxdomain": is_canonical_nxdomain,
                "status_code": evidence_status,
                "evidence_url": evidence_url or f"https://{clean_host}",
                "risk": "critical" if is_canonical_nxdomain or "AWS S3" in detected_provider or "GitHub" in detected_provider else "high",
                "dangling": True
            }

        return None


# =====================================================================
# 2. Comprehensive DNS Record Harvester & Parser
# =====================================================================

class DnsRecordHarvester:
    """
    Harvests and deeply analyzes TXT, MX, SRV, CAA, A, AAAA, SOA, and NS records.
    Extracts third-party SaaS verification tokens, SPF email senders, and SSL authorities.
    """

    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout

    async def harvest(self, domain: str) -> Dict[str, Any]:
        """Harvest all DNS record types for a domain and return structured intelligence."""
        clean = domain.strip().rstrip(".")
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        records = {
            "domain": clean,
            "a": [],
            "aaaa": [],
            "cname": [],
            "mx": [],
            "txt": [],
            "ns": [],
            "soa": None,
            "caa": [],
            "srv": [],
            "spf": None,
            "dmarc": None,
            "identity_tokens": [],
            "authorized_senders": [],
            "mail_provider": "Unknown",
            "ssl_authorities": [],
            "dns_provider": "Unknown"
        }

        # Concurrently query standard DNS record types
        async def query_type(rtype: str):
            try:
                answers = await resolver.resolve(clean, rtype)
                return rtype, [r for rdata in answers for r in [str(rdata)]]
            except Exception:
                return rtype, []

        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"]
        tasks = [query_type(rt) for rt in record_types]
        results = await asyncio.gather(*tasks)

        for rtype, vals in results:
            if rtype == "A":
                records["a"] = vals
            elif rtype == "AAAA":
                records["aaaa"] = vals
            elif rtype == "CNAME":
                records["cname"] = [v.rstrip(".") for v in vals]
            elif rtype == "MX":
                parsed_mx = []
                for val in vals:
                    parts = val.split()
                    if len(parts) >= 2:
                        parsed_mx.append({"priority": int(parts[0]), "host": parts[1].rstrip(".").lower()})
                    else:
                        parsed_mx.append({"priority": 10, "host": val.rstrip(".").lower()})
                parsed_mx.sort(key=lambda x: x["priority"])
                records["mx"] = parsed_mx
            elif rtype == "TXT":
                clean_txts = []
                for t in vals:
                    unquoted = t.strip('"').replace('" "', '')
                    clean_txts.append(unquoted)
                records["txt"] = clean_txts
            elif rtype == "NS":
                records["ns"] = [v.rstrip(".").lower() for v in vals]
            elif rtype == "SOA" and vals:
                records["soa"] = vals[0]
            elif rtype == "CAA":
                records["caa"] = vals

        # 1. Parse MX Provider
        for mx in records["mx"]:
            h = mx["host"]
            if any(k in h for k in ["google", "aspmx", "googlemail"]):
                records["mail_provider"] = "Google Workspace"
                break
            elif any(k in h for k in ["outlook", "protection.outlook.com", "microsoft"]):
                records["mail_provider"] = "Microsoft 365"
                break
            elif "mimecast" in h:
                records["mail_provider"] = "Mimecast Secure Gateway"
                break
            elif "pphosted" in h or "proofpoint" in h:
                records["mail_provider"] = "Proofpoint Email Protection"
                break
            elif "zoho" in h:
                records["mail_provider"] = "Zoho Mail"
                break
            elif "barracuda" in h:
                records["mail_provider"] = "Barracuda Email Security"
                break
            elif "protonmail" in h or "proton" in h:
                records["mail_provider"] = "ProtonMail"
                break
        if records["mail_provider"] == "Unknown" and records["mx"]:
            records["mail_provider"] = records["mx"][0]["host"]

        # 2. Parse DNS Provider from NS
        for ns in records["ns"]:
            if "cloudflare" in ns:
                records["dns_provider"] = "Cloudflare"
                break
            elif "awsdns" in ns or "route53" in ns:
                records["dns_provider"] = "Amazon Route 53"
                break
            elif "azure-dns" in ns:
                records["dns_provider"] = "Azure DNS"
                break
            elif "googledomains" in ns or "cloud-dns" in ns:
                records["dns_provider"] = "Google Cloud DNS"
                break
            elif "domaincontrol" in ns or "godaddy" in ns:
                records["dns_provider"] = "GoDaddy"
                break
            elif "registrar-servers" in ns or "namecheap" in ns:
                records["dns_provider"] = "Namecheap"
                break
            elif "akamai" in ns:
                records["dns_provider"] = "Akamai Edge DNS"
                break

        # 3. Parse TXT Records (Identity Verification Tokens & SPF)
        identity_tokens = []
        authorized_senders = set()

        for txt in records["txt"]:
            # SPF Record
            if txt.startswith("v=spf1"):
                records["spf"] = txt
                for inc in re.findall(r"include:([^\s]+)", txt):
                    authorized_senders.add(inc.strip())
                for ip4 in re.findall(r"ip4:([^\s]+)", txt):
                    authorized_senders.add(f"ip4:{ip4.strip()}")
                for ip6 in re.findall(r"ip6:([^\s]+)", txt):
                    authorized_senders.add(f"ip6:{ip6.strip()}")

            # Domain Verification Tokens
            token_patterns = [
                ("Google Workspace / Cloud", r"google-site-verification=([a-zA-Z0-9_-]+)"),
                ("Microsoft 365 / Azure", r"(?:MS=ms|microsoft-site-verification=)([a-zA-Z0-9_-]+)"),
                ("Atlassian Cloud", r"atlassian-domain-verification=([a-zA-Z0-9_-]+)"),
                ("Apple Business Manager", r"apple-domain-verification=([a-zA-Z0-9_-]+)"),
                ("Meta / Facebook Business", r"facebook-domain-verification=([a-zA-Z0-9_-]+)"),
                ("DocuSign Enterprise", r"docusign=([a-zA-Z0-9_-]+)"),
                ("Stripe Payments", r"stripe-verification=([a-zA-Z0-9_-]+)"),
                ("Adobe Experience / Creative Cloud", r"adobe-idp-site-verification=([a-zA-Z0-9_-]+)"),
                ("GitHub Pages Domain Verification", r"_github-pages-challenge-([a-zA-Z0-9_.-]+)"),
                ("Zoom Enterprise", r"zoom-domain-verification=([a-zA-Z0-9_-]+)"),
                ("Cisco Webex / Umbrella", r"cisco-ci-domain-verification=([a-zA-Z0-9_-]+)"),
                ("HubSpot CRM", r"hubspot-developer-verification=([a-zA-Z0-9_-]+)"),
                ("GlobalSign SSL", r"_globalsign-domain-verification=([a-zA-Z0-9_-]+)"),
                ("Amazon SES", r"amazonses:([a-zA-Z0-9_-]+)"),
                ("SendGrid", r"sendgrid\.net"),
                ("Mailgun", r"mailgun\.org")
            ]

            for service_name, pat in token_patterns:
                match = re.search(pat, txt, re.I)
                if match:
                    val = match.group(1) if match.groups() else ""
                    identity_tokens.append({
                        "service": service_name,
                        "token": val or (txt[:40] + "..."),
                        "raw": txt
                    })

        records["identity_tokens"] = identity_tokens
        records["authorized_senders"] = sorted(list(authorized_senders))

        # 4. Parse CAA Records (Permitted Certificate Authorities)
        ssl_auths = set()
        for caa in records["caa"]:
            parts = caa.split()
            if len(parts) >= 3:
                tag = parts[1].strip('"').lower()
                value = parts[2].strip('"').lower()
                if tag in ["issue", "issuewild"] and ";" not in value:
                    ssl_auths.add(value)
        records["ssl_authorities"] = sorted(list(ssl_auths))

        # 5. Discover SRV Records
        common_srvs = [
            "_autodiscover._tcp",
            "_sip._tls",
            "_sipfederationtls._tcp",
            "_xmpp-server._tcp",
            "_ldap._tcp",
            "_kerberos._tcp",
            "_matrix._tcp"
        ]

        async def check_srv(prefix: str):
            srv_name = f"{prefix}.{clean}"
            try:
                ans = await resolver.resolve(srv_name, "SRV")
                srv_list = []
                for r in ans:
                    srv_list.append({
                        "service": prefix,
                        "target": str(r.target).rstrip("."),
                        "port": r.port,
                        "priority": r.priority,
                        "weight": r.weight
                    })
                return srv_list
            except Exception:
                return []

        srv_tasks = [check_srv(s) for s in common_srvs]
        srv_results = await asyncio.gather(*srv_tasks)
        records["srv"] = [item for sublist in srv_results for item in sublist]

        # 6. DMARC Query (_dmarc.<domain>)
        try:
            dmarc_ans = await resolver.resolve(f"_dmarc.{clean}", "TXT")
            for r in dmarc_ans:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=DMARC1" in txt:
                    records["dmarc"] = txt
                    break
        except Exception:
            pass

        return records


# =====================================================================
# 3. ASN, BGP CIDR & PTR Network Resolver
# =====================================================================

class AsnNetworkResolver:
    """
    Resolves IP addresses to their Autonomous System Number (ASN),
    AS Organization name, registered BGP CIDR prefix, and reverse PTR hostnames
    via Team Cymru DNS (fast, non-rate-limited) with PTR resolution.
    """

    _cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def resolve_ip(self, ip: str) -> Dict[str, Any]:
        """Resolve a single IPv4 address to its ASN, AS Org, CIDR prefix, and PTR."""
        clean_ip = ip.strip()
        if clean_ip in self._cache:
            return self._cache[clean_ip]

        # Skip private/loopback IPs
        if clean_ip.startswith("10.") or clean_ip.startswith("192.168.") or clean_ip.startswith("127.") or clean_ip.startswith("172.16."):
            result = {
                "ip": clean_ip,
                "asn": 0,
                "org": "Private / RFC1918 Network",
                "cidr": "Private",
                "country": "N/A",
                "ptr": None
            }
            self._cache[clean_ip] = result
            return result

        result = {
            "ip": clean_ip,
            "asn": None,
            "org": "Unknown",
            "cidr": None,
            "country": "Unknown",
            "ptr": None
        }

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        # 1. Reverse PTR
        try:
            rev_name = dns.reversename.from_address(clean_ip)
            ptr_ans = await resolver.resolve(rev_name, "PTR")
            if ptr_ans:
                result["ptr"] = str(ptr_ans[0].target).rstrip(".").lower()
        except Exception:
            pass

        # 2. Team Cymru Origin ASN Query: <reversed-ip>.origin.asn.cymru.com
        try:
            octets = clean_ip.split(".")
            if len(octets) == 4:
                rev_ip = ".".join(reversed(octets))
                cymru_origin = f"{rev_ip}.origin.asn.cymru.com"
                ans = await resolver.resolve(cymru_origin, "TXT")
                for rdata in ans:
                    raw = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                    parts = [p.strip() for p in raw.split("|")]
                    if len(parts) >= 3:
                        asn_str = parts[0].split()[0]
                        if asn_str.isdigit():
                            result["asn"] = int(asn_str)
                        result["cidr"] = parts[1]
                        result["country"] = parts[2]
                        break

            # 3. Resolve AS Name from AS number: AS<asn>.asn.cymru.com
            if result["asn"]:
                as_query = f"AS{result['asn']}.asn.cymru.com"
                ans_name = await resolver.resolve(as_query, "TXT")
                for rdata in ans_name:
                    raw_name = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                    parts = [p.strip() for p in raw_name.split("|")]
                    if len(parts) >= 5:
                        result["org"] = parts[4]
                        break
        except Exception as e:
            logger.debug(f"Cymru ASN lookup for {clean_ip} returned: {e}")

        # Fallback to ip-api.com if DNS didn't return an ASN
        if not result["asn"]:
            try:
                async with httpx.AsyncClient(timeout=2.0, headers=self.headers) as client:
                    resp = await client.get(f"http://ip-api.com/json/{clean_ip}?fields=status,countryCode,as,org")
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("status") == "success":
                            result["country"] = data.get("countryCode") or result["country"]
                            result["org"] = data.get("org") or data.get("as") or result["org"]
                            as_val = data.get("as", "")
                            match = re.search(r"AS(\d+)", as_val)
                            if match:
                                result["asn"] = int(match.group(1))
            except Exception:
                pass

        self._cache[clean_ip] = result
        return result

    async def resolve_batch(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Resolve a batch of unique IP addresses concurrently."""
        unique_ips = list(set([ip.strip() for ip in ips if ip and ip != "N/A"]))
        tasks = [self.resolve_ip(ip) for ip in unique_ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        mapped = {}
        for ip, res in zip(unique_ips, results):
            if isinstance(res, dict):
                mapped[ip] = res
            else:
                mapped[ip] = {"ip": ip, "asn": None, "org": "Unknown", "cidr": None, "country": "Unknown", "ptr": None}
        return mapped

    async def sweep_range_ptrs(self, base_ip: str, count: int = 10) -> List[Dict[str, str]]:
        """
        For a given IP, probe adjacent IP addresses to discover unlisted hostnames
        and routers via reverse DNS PTR lookup.
        """
        try:
            octets = [int(x) for x in base_ip.split(".")]
            if len(octets) != 4:
                return []
        except Exception:
            return []

        cur_last = octets[3]
        adjacent_ips = []
        for offset in range(-int(count/2), int(count/2) + 1):
            if offset == 0:
                continue
            cand_last = cur_last + offset
            if 1 <= cand_last <= 254:
                cand_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{cand_last}"
                adjacent_ips.append(cand_ip)

        found = []
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout

        async def check_ptr(cand: str):
            try:
                rev = dns.reversename.from_address(cand)
                ans = await resolver.resolve(rev, "PTR")
                if ans:
                    return {"ip": cand, "hostname": str(ans[0].target).rstrip(".").lower()}
            except Exception:
                pass
            return None

        tasks = [check_ptr(ip) for ip in adjacent_ips]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                found.append(r)
        return found


# =====================================================================
# 4. DNSSEC Auditor & NSEC Zone Walker
# =====================================================================

class DnssecAuditor:
    """
    Audits a domain's DNSSEC configuration and attempts NSEC zone enumeration.

    Checks:
      - Whether DNSKEY records are published (DNSSEC enabled)
      - The signing algorithm (RSA-SHA256, ECDSA-P256, Ed25519, etc.)
      - Whether NSEC or NSEC3 is used for authenticated denial-of-existence
      - If NSEC (not NSEC3) is in use, attempts to walk the chain to enumerate
        all zone names by following the 'Next Domain' pointer in each NSEC record.

    NSEC zone walking is a read-only passive enumeration technique that only
    works against misconfigured zones that use plain NSEC instead of NSEC3.
    It is performed only against the root domain to avoid excessive DNS traffic.
    """

    # IANA DNSSEC algorithm numbers -> human-readable names
    # https://www.iana.org/assignments/dns-sec-alg-numbers/
    ALGORITHM_NAMES = {
        1:  "RSA-MD5 (Insecure)",
        3:  "DSA-SHA1 (Deprecated)",
        5:  "RSA-SHA1 (Deprecated)",
        6:  "DSA-NSEC3-SHA1 (Deprecated)",
        7:  "RSA-SHA1-NSEC3 (Deprecated)",
        8:  "RSA-SHA256",
        10: "RSA-SHA512",
        12: "ECC-GOST",
        13: "ECDSA-P256-SHA256",
        14: "ECDSA-P384-SHA384",
        15: "Ed25519",
        16: "Ed448",
    }

    def __init__(self, timeout: float = 5.0, max_walk_steps: int = 200):
        self.timeout = timeout
        self.max_walk_steps = max_walk_steps

    def _make_resolver(self):
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        return resolver

    async def check_dnssec(self, domain: str) -> Dict[str, Any]:
        """
        Query DNSKEY records to determine DNSSEC status and signing algorithm.
        Also checks for NSEC vs NSEC3 to assess zone walk susceptibility.

        Returns a dict:
        {
            "enabled": bool,
            "algorithm": str | None,
            "algorithm_id": int | None,
            "key_tag": int | None,
            "key_flags": int | None,
            "nsec_type": "NSEC" | "NSEC3" | None,
            "zone_walkable": bool,
            "keys_count": int
        }
        """
        clean = domain.strip().rstrip(".")
        result: Dict[str, Any] = {
            "enabled": False,
            "algorithm": None,
            "algorithm_id": None,
            "key_tag": None,
            "key_flags": None,
            "nsec_type": None,
            "zone_walkable": False,
            "keys_count": 0
        }

        resolver = self._make_resolver()

        # 1. Check for DNSKEY records
        try:
            answers = await resolver.resolve(clean, "DNSKEY")
            result["enabled"] = True
            result["keys_count"] = len(answers)
            for rdata in answers:
                alg_id = int(rdata.algorithm)
                result["algorithm_id"] = alg_id
                result["algorithm"] = self.ALGORITHM_NAMES.get(alg_id, f"Algorithm {alg_id}")
                result["key_flags"] = int(rdata.flags)
                # key_tag calculation (per RFC 4034 appendix B)
                try:
                    wire = rdata.to_wire()
                    ac = 0
                    for i, byte in enumerate(wire):
                        ac += byte if i % 2 == 0 else byte << 8
                    ac += (ac >> 16) & 0xFFFF
                    result["key_tag"] = ac & 0xFFFF
                except Exception:
                    pass
                break  # use the first KSK/ZSK
        except Exception:
            # No DNSKEY — DNSSEC not deployed
            return result

        # 2. Check whether NSEC or NSEC3 is used
        try:
            await resolver.resolve(clean, "NSEC3PARAM")
            result["nsec_type"] = "NSEC3"
            result["zone_walkable"] = False
            logger.info(f"[DNSSEC] {clean}: DNSSEC enabled, NSEC3 (zone walk not possible)")
        except Exception:
            # NSEC3PARAM missing — check for plain NSEC
            try:
                nsec_ans = await resolver.resolve(clean, "NSEC")
                if nsec_ans:
                    result["nsec_type"] = "NSEC"
                    result["zone_walkable"] = True
                    logger.warning(f"[DNSSEC] {clean}: Plain NSEC detected — zone walk may be possible!")
            except Exception:
                pass

        return result

    async def attempt_nsec_walk(self, domain: str) -> List[str]:
        """
        Attempt to enumerate all DNS zone names for a domain that uses plain NSEC records
        by following the 'Next Domain' pointer chain from NSEC record to NSEC record.

        This is a fully passive, read-only enumeration technique that works ONLY when
        the zone uses NSEC (not NSEC3). Returns an empty list for NSEC3-protected zones.

        Returns a list of discovered zone names (sorted), or an empty list on failure.
        """
        clean = domain.strip().rstrip(".")
        resolver = self._make_resolver()
        discovered = set()
        to_query = {clean}
        steps = 0

        logger.info(f"[DNSSEC Walk] Starting NSEC walk for {clean} (max {self.max_walk_steps} steps)")

        while to_query and steps < self.max_walk_steps:
            current = to_query.pop()
            steps += 1
            try:
                answers = await resolver.resolve(current, "NSEC")
                for rdata in answers:
                    # The NSEC 'next' field is the next name in canonical zone order
                    next_name = str(rdata.next).rstrip(".").lower()
                    if next_name and next_name not in discovered:
                        discovered.add(next_name)
                        # If the next name is still within the zone, keep walking
                        if next_name.endswith(f".{clean}") or next_name == clean:
                            to_query.add(next_name)
            except Exception:
                pass

        zone_names = sorted(discovered)
        if zone_names:
            logger.warning(
                f"[DNSSEC Walk] {clean}: Enumerated {len(zone_names)} zone names "
                f"in {steps} steps via NSEC walk — zone enumeration is possible!"
            )
        else:
            logger.info(f"[DNSSEC Walk] {clean}: No NSEC names discovered (NSEC3 or walk unsuccessful)")

        return zone_names

