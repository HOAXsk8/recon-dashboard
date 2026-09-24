import asyncio
import datetime
import json
import os
import sys
import re
import socket
import ipaddress
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger

try:
    import httpx
except ImportError:
    httpx = None

# ---------------------------------------------------------------------------
# Enhancement #3: Edge POP and Airport Code Geographic Mapping
# ---------------------------------------------------------------------------
IATA_POP_MAP = {
    # United Kingdom & Ireland
    "LHR": {"city": "London", "country": "United Kingdom", "region": "Europe"},
    "LGW": {"city": "London", "country": "United Kingdom", "region": "Europe"},
    "LCY": {"city": "London", "country": "United Kingdom", "region": "Europe"},
    "STN": {"city": "London", "country": "United Kingdom", "region": "Europe"},
    "MAN": {"city": "Manchester", "country": "United Kingdom", "region": "Europe"},
    "EDI": {"city": "Edinburgh", "country": "United Kingdom", "region": "Europe"},
    "DUB": {"city": "Dublin", "country": "Ireland", "region": "Europe"},

    # North America
    "IAD": {"city": "Ashburn / Washington DC", "country": "United States", "region": "North America"},
    "DCA": {"city": "Washington DC", "country": "United States", "region": "North America"},
    "BWI": {"city": "Baltimore", "country": "United States", "region": "North America"},
    "JFK": {"city": "New York", "country": "United States", "region": "North America"},
    "EWR": {"city": "Newark", "country": "United States", "region": "North America"},
    "LGA": {"city": "New York", "country": "United States", "region": "North America"},
    "ORD": {"city": "Chicago", "country": "United States", "region": "North America"},
    "DFW": {"city": "Dallas", "country": "United States", "region": "North America"},
    "IAH": {"city": "Houston", "country": "United States", "region": "North America"},
    "ATL": {"city": "Atlanta", "country": "United States", "region": "North America"},
    "MIA": {"city": "Miami", "country": "United States", "region": "North America"},
    "SFO": {"city": "San Francisco", "country": "United States", "region": "North America"},
    "SJC": {"city": "San Jose", "country": "United States", "region": "North America"},
    "OAK": {"city": "Oakland", "country": "United States", "region": "North America"},
    "LAX": {"city": "Los Angeles", "country": "United States", "region": "North America"},
    "SEA": {"city": "Seattle", "country": "United States", "region": "North America"},
    "DEN": {"city": "Denver", "country": "United States", "region": "North America"},
    "PHX": {"city": "Phoenix", "country": "United States", "region": "North America"},
    "BOS": {"city": "Boston", "country": "United States", "region": "North America"},
    "MSP": {"city": "Minneapolis", "country": "United States", "region": "North America"},
    "YYZ": {"city": "Toronto", "country": "Canada", "region": "North America"},
    "YVR": {"city": "Vancouver", "country": "Canada", "region": "North America"},
    "YUL": {"city": "Montreal", "country": "Canada", "region": "North America"},
    "MEX": {"city": "Mexico City", "country": "Mexico", "region": "North America"},

    # Western & Central Europe
    "FRA": {"city": "Frankfurt", "country": "Germany", "region": "Europe"},
    "MUC": {"city": "Munich", "country": "Germany", "region": "Europe"},
    "BER": {"city": "Berlin", "country": "Germany", "region": "Europe"},
    "AMS": {"city": "Amsterdam", "country": "Netherlands", "region": "Europe"},
    "CDG": {"city": "Paris", "country": "France", "region": "Europe"},
    "ORY": {"city": "Paris", "country": "France", "region": "Europe"},
    "MRS": {"city": "Marseille", "country": "France", "region": "Europe"},
    "BRU": {"city": "Brussels", "country": "Belgium", "region": "Europe"},
    "ZRH": {"city": "Zurich", "country": "Switzerland", "region": "Europe"},
    "GVA": {"city": "Geneva", "country": "Switzerland", "region": "Europe"},
    "VIE": {"city": "Vienna", "country": "Austria", "region": "Europe"},
    "MAD": {"city": "Madrid", "country": "Spain", "region": "Europe"},
    "BCN": {"city": "Barcelona", "country": "Spain", "region": "Europe"},
    "LIS": {"city": "Lisbon", "country": "Portugal", "region": "Europe"},
    "MXP": {"city": "Milan", "country": "Italy", "region": "Europe"},
    "FCO": {"city": "Rome", "country": "Italy", "region": "Europe"},
    "ARN": {"city": "Stockholm", "country": "Sweden", "region": "Europe"},
    "CPH": {"city": "Copenhagen", "country": "Denmark", "region": "Europe"},
    "OSL": {"city": "Oslo", "country": "Norway", "region": "Europe"},
    "HEL": {"city": "Helsinki", "country": "Finland", "region": "Europe"},
    "WAW": {"city": "Warsaw", "country": "Poland", "region": "Europe"},
    "PRG": {"city": "Prague", "country": "Czech Republic", "region": "Europe"},

    # Asia & Middle East
    "NRT": {"city": "Tokyo", "country": "Japan", "region": "Asia-Pacific"},
    "HND": {"city": "Tokyo", "country": "Japan", "region": "Asia-Pacific"},
    "KIX": {"city": "Osaka", "country": "Japan", "region": "Asia-Pacific"},
    "ICN": {"city": "Seoul", "country": "South Korea", "region": "Asia-Pacific"},
    "SIN": {"city": "Singapore", "country": "Singapore", "region": "Asia-Pacific"},
    "HKG": {"city": "Hong Kong", "country": "Hong Kong", "region": "Asia-Pacific"},
    "TPE": {"city": "Taipei", "country": "Taiwan", "region": "Asia-Pacific"},
    "BOM": {"city": "Mumbai", "country": "India", "region": "Asia"},
    "DEL": {"city": "Delhi", "country": "India", "region": "Asia"},
    "BLR": {"city": "Bangalore", "country": "India", "region": "Asia"},
    "MAA": {"city": "Chennai", "country": "India", "region": "Asia"},
    "DXB": {"city": "Dubai", "country": "United Arab Emirates", "region": "Middle East"},
    "DOH": {"city": "Doha", "country": "Qatar", "region": "Middle East"},
    "BAH": {"city": "Manama", "country": "Bahrain", "region": "Middle East"},
    "TLV": {"city": "Tel Aviv", "country": "Israel", "region": "Middle East"},
    "BKK": {"city": "Bangkok", "country": "Thailand", "region": "Asia-Pacific"},
    "KUL": {"city": "Kuala Lumpur", "country": "Malaysia", "region": "Asia-Pacific"},
    "CGK": {"city": "Jakarta", "country": "Indonesia", "region": "Asia-Pacific"},

    # Australia & Oceania
    "SYD": {"city": "Sydney", "country": "Australia", "region": "Oceania"},
    "MEL": {"city": "Melbourne", "country": "Australia", "region": "Oceania"},
    "BNE": {"city": "Brisbane", "country": "Australia", "region": "Oceania"},
    "PER": {"city": "Perth", "country": "Australia", "region": "Oceania"},
    "AKL": {"city": "Auckland", "country": "New Zealand", "region": "Oceania"},

    # Latin America & Africa
    "GRU": {"city": "São Paulo", "country": "Brazil", "region": "South America"},
    "GIG": {"city": "Rio de Janeiro", "country": "Brazil", "region": "South America"},
    "EZE": {"city": "Buenos Aires", "country": "Argentina", "region": "South America"},
    "SCL": {"city": "Santiago", "country": "Chile", "region": "South America"},
    "BOG": {"city": "Bogota", "country": "Colombia", "region": "South America"},
    "JNB": {"city": "Johannesburg", "country": "South Africa", "region": "Africa"},
    "CPT": {"city": "Cape Town", "country": "South Africa", "region": "Africa"},
    "LOS": {"city": "Lagos", "country": "Nigeria", "region": "Africa"},
    "NBO": {"city": "Nairobi", "country": "Kenya", "region": "Africa"},
}

# ---------------------------------------------------------------------------
# Enhancement #1: Known CDN IP Ranges (Used to identify direct origin vs edge)
# ---------------------------------------------------------------------------
CLOUDFLARE_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]
CLOUDFLARE_NETWORKS = [ipaddress.ip_network(c) for c in CLOUDFLARE_CIDRS]

CLOUDFRONT_SAMPLE_NETWORKS = [
    ipaddress.ip_network("13.32.0.0/15"),
    ipaddress.ip_network("13.35.0.0/16"),
    ipaddress.ip_network("13.224.0.0/14"),
    ipaddress.ip_network("13.249.0.0/16"),
    ipaddress.ip_network("18.64.0.0/14"),
    ipaddress.ip_network("52.84.0.0/15"),
    ipaddress.ip_network("54.182.0.0/16"),
    ipaddress.ip_network("54.192.0.0/16"),
    ipaddress.ip_network("54.230.0.0/16"),
    ipaddress.ip_network("54.239.128.0/18"),
    ipaddress.ip_network("64.252.64.0/18"),
    ipaddress.ip_network("65.8.0.0/16"),
    ipaddress.ip_network("65.9.0.0/16"),
    ipaddress.ip_network("70.132.0.0/18"),
    ipaddress.ip_network("99.84.0.0/16"),
    ipaddress.ip_network("99.86.0.0/16"),
    ipaddress.ip_network("143.204.0.0/16"),
    ipaddress.ip_network("205.251.192.0/19"),
    ipaddress.ip_network("204.246.160.0/19"),
]

def is_known_cdn_ip(ip_str: str) -> bool:
    """Checks whether an IPv4 address belongs to known Cloudflare or CloudFront ranges."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_private or ip.is_loopback:
            return False
        for net in CLOUDFLARE_NETWORKS:
            if ip in net:
                return True
        for net in CLOUDFRONT_SAMPLE_NETWORKS:
            if ip in net:
                return True
    except Exception:
        pass
    return False


class WafDetectorAgent(BaseAgent):
    def __init__(self):
        super().__init__("waf_detector", "WAF Detector")

    async def run_wafw00f(self, url):
        """Run wafw00f against a URL and return parsed JSON results."""
        logger.info(f"Running wafw00f on {url}")
        safe_name = url.replace("://", "_").replace("/", "_").replace(".", "_")
        tmp_output = f"/tmp/wafw00f_{safe_name}.json"
        cmd = ["wafw00f", "-a", "-o", tmp_output, "-f", "json", url]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=120)
            if stderr:
                logger.debug(f"[wafw00f stderr] {stderr}")
            if os.path.exists(tmp_output):
                with open(tmp_output, "r") as f:
                    data = json.load(f)
                os.remove(tmp_output)
                return data
        except Exception as e:
            logger.error(f"wafw00f error for {url}: {e}")
        return None

    def parse_wafw00f_result(self, data):
        """Parse wafw00f JSON output into a normalised result dict."""
        result = {
            "detected": False,
            "firewall": None,
            "manufacturer": None,
            "mode": None,
            "confidence": None,
            "generic": False,
            "all_detections": [],
            "scanned_at": datetime.datetime.utcnow().isoformat()
        }
        if not data or not isinstance(data, list):
            return result

        detected_entries = []
        has_generic = False

        for entry in data:
            if not isinstance(entry, dict):
                continue

            raw_detected = entry.get("detected")
            if isinstance(raw_detected, list):
                for sub in raw_detected:
                    if isinstance(sub, dict) and sub.get("firewall") and str(sub.get("firewall")).lower() != "none":
                        if str(sub.get("firewall")).lower() == "generic":
                            has_generic = True
                        else:
                            detected_entries.append(sub)
                if entry.get("generic"):
                    has_generic = True
                continue

            if raw_detected is True:
                fw = entry.get("firewall")
                if fw and str(fw).lower() != "none":
                    if str(fw).lower() == "generic":
                        has_generic = True
                    else:
                        detected_entries.append(entry)

        result["generic"] = has_generic

        if detected_entries:
            result["detected"] = True
            first = detected_entries[0]
            result["firewall"] = first.get("firewall")
            result["manufacturer"] = first.get("manufacturer")
            result["confidence"] = "high" if len(detected_entries) == 1 else "medium"
            result["all_detections"] = [
                {"firewall": d.get("firewall"), "manufacturer": d.get("manufacturer")}
                for d in detected_entries
            ]
        elif has_generic:
            result["detected"] = True
            result["firewall"] = "Generic WAF"
            result["manufacturer"] = "Unknown"
            result["confidence"] = "low"
            result["all_detections"] = [{"firewall": "Generic WAF", "manufacturer": "Unknown"}]

        return result

    # ---------------------------------------------------------------------------
    # Enhancement #3: Cloud Edge POP & Geographic Mapping
    # ---------------------------------------------------------------------------
    def extract_edge_pop_geo(self, raw_headers: dict) -> dict:
        """
        Parses response headers (cf-ray, x-amz-cf-pop, x-served-by, x-azure-ref, server-timing)
        to identify Cloud Edge POP codes and geographic locations.
        """
        if not raw_headers:
            return {"provider": None, "pop_code": None, "city": None, "country": None, "region": None}

        norm = {k.lower(): str(v).strip() for k, v in raw_headers.items()}
        pop_code = None
        provider = None
        raw_token = None

        # 1. Cloudflare
        if "cf-ray" in norm:
            provider = "Cloudflare"
            raw_token = norm["cf-ray"]
            m = re.search(r"-([A-Z]{3})$", raw_token)
            if m:
                pop_code = m.group(1)

        # 2. AWS CloudFront
        elif "x-amz-cf-pop" in norm:
            provider = "AWS CloudFront"
            raw_token = norm["x-amz-cf-pop"]
            m = re.match(r"^([A-Z]{3})", raw_token)
            if m:
                pop_code = m.group(1)

        # 3. Fastly
        elif "x-served-by" in norm:
            provider = "Fastly"
            raw_token = norm["x-served-by"]
            m = re.search(r"-([A-Z]{3})$", raw_token)
            if m:
                pop_code = m.group(1)

        # 4. Akamai
        elif any(k.startswith("x-akamai") for k in norm) or "akamaighost" in norm.get("server", "").lower():
            provider = "Akamai"
            raw_token = norm.get("x-akamai-transformed") or norm.get("server")

        # 5. Azure Front Door / CDN
        elif "x-azure-ref" in norm:
            provider = "Microsoft Azure Front Door"
            raw_token = norm["x-azure-ref"]

        geo = IATA_POP_MAP.get(pop_code, {})
        return {
            "provider": provider,
            "pop_code": pop_code,
            "city": geo.get("city", "Unknown City" if pop_code else None),
            "country": geo.get("country", "Unknown Country" if pop_code else None),
            "region": geo.get("region", "Unknown Region" if pop_code else None),
            "header_evidence": raw_token
        }

    # ---------------------------------------------------------------------------
    # Enhancement #2: WAF Blocking Behavior Profile
    # ---------------------------------------------------------------------------
    async def profile_waf_blocking_behavior(self, target: str, url: str) -> dict:
        """
        Tests standard attack vectors (SQLi, XSS, Path Traversal, Cmd Injection, SSTI,
        scanner user-agent) against the endpoint to establish which classes of attacks
        are actively blocked by the WAF and identify defensive gaps.
        """
        logger.info(f"Profiling WAF blocking behavior on {url}")

        # Baseline probe
        baseline_status = 200
        try:
            cmd = ["curl", "-sI", "-k", "-m", "8", url]
            stdout, _ = await self.run_command(cmd, timeout=10)
            if stdout:
                lines = stdout.splitlines()
                first = lines[0] if lines else ""
                m = re.search(r"HTTP/\S+\s+(\d{3})", first)
                if m:
                    baseline_status = int(m.group(1))
        except Exception as e:
            logger.debug(f"Baseline probe error for {url}: {e}")

        test_cases = [
            {
                "id": "sqli",
                "name": "SQL Injection",
                "query": "?id=1%27+OR+%271%27%3D%271",
                "headers": []
            },
            {
                "id": "xss",
                "name": "Cross-Site Scripting (XSS)",
                "query": "?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                "headers": []
            },
            {
                "id": "path_traversal",
                "name": "Directory / Path Traversal",
                "query": "?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                "headers": []
            },
            {
                "id": "cmd_injection",
                "name": "Command Injection (RCE)",
                "query": "?cmd=%3Bcat+%2Fetc%2Fpasswd%3B",
                "headers": []
            },
            {
                "id": "ssti",
                "name": "Server-Side Template Injection",
                "query": "?name=%7B%7B7*7%7D%7D",
                "headers": []
            },
            {
                "id": "scanner_user_agent",
                "name": "Malicious Scanner User-Agent",
                "query": "/",
                "headers": ["-A", "sqlmap/1.6#stable (https://sqlmap.org)"]
            },
            {
                "id": "special_chars",
                "name": "Protocol Fuzzing / Special Chars",
                "query": "?fuzz=%00%0a%0d%27%22%3c%3e",
                "headers": []
            }
        ]

        results = []
        blocked_count = 0
        allowed_count = 0
        blocked_categories = []
        allowed_categories = []

        base_clean = url.rstrip("/")
        for tc in test_cases:
            probe_url = f"{base_clean}/{tc['query'].lstrip('/')}" if not tc['query'].startswith("?") else f"{base_clean}{tc['query']}"
            cmd = ["curl", "-sI", "-k", "-m", "6"]
            if tc["headers"]:
                cmd.extend(tc["headers"])
            cmd.append(probe_url)

            status_code = None
            server_header = ""
            waf_block_sign = False

            try:
                stdout, _ = await self.run_command(cmd, timeout=8)
                if stdout:
                    for line in stdout.splitlines():
                        if not status_code:
                            m = re.search(r"HTTP/\S+\s+(\d{3})", line)
                            if m:
                                status_code = int(m.group(1))
                        if line.lower().startswith("server:"):
                            server_header = line.split(":", 1)[1].strip()
                        if any(sig in line.lower() for sig in ["cloudflare", "akamaighost", "imperva", "waf", "access denied"]):
                            waf_block_sign = True
            except Exception as e:
                logger.debug(f"WAF profile test {tc['id']} error: {e}")

            # Assess whether request was blocked
            # Typical WAF block statuses: 403, 406, 429, 999, 501
            is_blocked = False
            if status_code in (403, 406, 429, 999) and baseline_status != status_code:
                is_blocked = True
            elif status_code == 403 or (status_code and status_code >= 400 and waf_block_sign):
                is_blocked = True

            if is_blocked:
                blocked_count += 1
                blocked_categories.append(tc["name"])
            else:
                allowed_count += 1
                allowed_categories.append(tc["name"])

            results.append({
                "category_id": tc["id"],
                "name": tc["name"],
                "status_code": status_code,
                "blocked": is_blocked,
                "server": server_header
            })

        total = len(test_cases)
        block_rate = round((blocked_count / total) * 100, 1) if total > 0 else 0

        profile = {
            "tested_probes_count": total,
            "blocked_count": blocked_count,
            "allowed_count": allowed_count,
            "block_rate_percent": block_rate,
            "baseline_status": baseline_status,
            "blocked_categories": blocked_categories,
            "allowed_categories": allowed_categories,
            "detailed_results": results
        }

        # If high-risk attacks like SQLi or Path Traversal are completely allowed, flag alert
        critical_unblocked = [c for c in ["SQL Injection", "Directory / Path Traversal", "Command Injection (RCE)"] if c in allowed_categories]
        if critical_unblocked:
            await self.create_waf_gap_alert(target, critical_unblocked, profile, url)

        return profile

    async def create_waf_gap_alert(self, target: str, critical_unblocked: list, profile: dict, url: str):
        """Create a lead/alert when critical attack vectors are not blocked by the WAF."""
        title = f"WAF Protection Gap: Unblocked Attack Classes on {target}"
        description = f"WAF active but failed to block simulated attack vectors: {', '.join(critical_unblocked)}"
        
        details = (
            f"### WAF Rule Gap Analysis for {url}\n\n"
            f"- **Overall Block Rate**: `{profile['block_rate_percent']}%` ({profile['blocked_count']}/{profile['tested_probes_count']} probes blocked)\n"
            f"- **Baseline HTTP Status**: `{profile['baseline_status']}`\n\n"
            f"#### Attack Classes Allowed by WAF:\n"
            + "\n".join([f"- **{cat}**: Allowed by edge filters" for cat in profile["allowed_categories"]])
            + f"\n\n#### Attack Classes Blocked:\n"
            + "\n".join([f"- **{cat}**: Successfully blocked" for cat in profile["blocked_categories"]])
        )

        exploitation = (
            f"### Remediation & WAF Tuning\n\n"
            f"1. **Enable Strict Managed Rules**: Enable CRS (Core Rule Set) for {', '.join(critical_unblocked)}.\n"
            f"2. **Verify Detection Mode**: Ensure the WAF rule mode is set to 'Block/Drop' rather than 'Log/Simulate'.\n"
            f"3. **Custom Firewall Rules**: Deploy path/query filtering for `{target}`."
        )

        await self.create_alert(
            title=title,
            description=description,
            target=target,
            risk_level="medium",
            details=details,
            exploitation_suggestions=exploitation,
            extra_key="waf_gaps:" + ",".join(sorted(critical_unblocked)),
            alert_type="waf_protection_gap"
        )

    # ---------------------------------------------------------------------------
    # Enhancement #1: Direct Origin Access Testing (WAF Bypassing)
    # ---------------------------------------------------------------------------
    async def test_direct_origin_access(self, target: str, root_domain: str, waf_name: str) -> dict:
        """
        When a WAF (Cloudflare, Akamai, etc.) is detected on a target, test direct HTTP/HTTPS
        connections to all discovered IP addresses in the domain doc using the target Host: header.
        Determines whether the origin web server can be accessed directly without WAF filtering.
        """
        logger.info(f"Testing direct origin access for {target} behind {waf_name}")

        # Harvest candidate IPs from the root domain document
        candidate_ips = set()
        try:
            doc = await self.domains_col.find_one({"domain": root_domain})
            if doc:
                # 1. Subdomain IPs
                for sub in doc.get("infrastructure", {}).get("subdomains", []):
                    ip = sub.get("ip")
                    if ip and not ip.startswith("127."):
                        candidate_ips.add(ip)
                    # Historical IPs
                    for h_ip in sub.get("historical_ips", []):
                        if h_ip and not h_ip.startswith("127."):
                            candidate_ips.add(h_ip)

                # 2. Root-level historical IPs
                for r_ip in doc.get("infrastructure", {}).get("historical_ips", []):
                    if r_ip and not r_ip.startswith("127."):
                        candidate_ips.add(r_ip)
        except Exception as e:
            logger.debug(f"Error harvesting candidate origin IPs for {target}: {e}")

        # Filter out known CDN edge IPs (Cloudflare, CloudFront, etc.)
        filtered_candidates = [ip for ip in candidate_ips if not is_known_cdn_ip(ip)]
        
        origin_findings = []
        tested_count = 0

        for ip in filtered_candidates[:12]: # Cap at 12 candidate IPs to avoid scan bloat
            tested_count += 1
            for scheme, port in [("https", 443), ("http", 80)]:
                cmd = [
                    "curl", "-sI", "-k", "-m", "6",
                    "-H", f"Host: {target}",
                    f"{scheme}://{ip}:{port}/"
                ]
                try:
                    stdout, _ = await self.run_command(cmd, timeout=8)
                    if not stdout:
                        continue

                    status_code = None
                    server_header = None
                    has_waf_headers = False

                    for line in stdout.splitlines():
                        if not status_code:
                            m = re.search(r"HTTP/\S+\s+(\d{3})", line)
                            if m:
                                status_code = int(m.group(1))
                        if line.lower().startswith("server:"):
                            server_header = line.split(":", 1)[1].strip()
                        if any(sig in line.lower() for sig in ["cf-ray", "cf-cache-status", "x-amz-cf-id", "x-akamai-", "imperva"]):
                            has_waf_headers = True

                    # Direct origin response detected if:
                    # 1. Responded with a standard HTTP status (200, 301, 302, 401, 403, 404, 500)
                    # 2. Does NOT have Cloudflare / CDN proxy headers
                    # 3. Server header is not 'cloudflare' or 'AkamaiGHost'
                    if status_code and not has_waf_headers:
                        server_clean = (server_header or "").lower()
                        if "cloudflare" not in server_clean and "akamaighost" not in server_clean:
                            origin_finding = {
                                "origin_ip": ip,
                                "port": port,
                                "scheme": scheme,
                                "status_code": status_code,
                                "server": server_header or "Unknown Web Server",
                                "curl_command": f"curl -k -H 'Host: {target}' {scheme}://{ip}:{port}/",
                                "evidence": f"Responded HTTP {status_code} without {waf_name} edge headers"
                            }
                            origin_findings.append(origin_finding)
                            logger.warning(f"CONFIRMED DIRECT ORIGIN BYPASS on {target}: {ip}:{port}")
                            
                            # Alert on direct origin discovery
                            await self.create_waf_origin_bypass_alert(target, root_domain, origin_finding, waf_name)
                            break # Found working direct origin on this IP
                except Exception as probe_err:
                    logger.debug(f"Direct origin probe error on {ip}:{port} for {target}: {probe_err}")

        return {
            "tested_candidate_ips": len(filtered_candidates),
            "origin_bypasses_found": len(origin_findings),
            "origin_bypasses": origin_findings,
            "bypassed": len(origin_findings) > 0
        }

    async def create_waf_origin_bypass_alert(self, target: str, root_domain: str, origin_info: dict, waf_name: str):
        """Create a CRITICAL alert when an origin server is directly reachable without WAF filtering."""
        origin_ip = origin_info["origin_ip"]
        port = origin_info["port"]
        scheme = origin_info["scheme"]
        status = origin_info["status_code"]
        server = origin_info["server"]
        curl_cmd = origin_info["curl_command"]

        title = f"WAF Bypass via Direct Origin IP: {target} -> {origin_ip}"
        description = (
            f"WAF protection ({waf_name}) completely bypassed! Origin web server exposed at {origin_ip}:{port} "
            f"({server}, HTTP {status})."
        )

        details = (
            f"### Direct Origin Access Report (WAF Bypassing)\n\n"
            f"- **Target Domain**: `{target}`\n"
            f"- **WAF in Front of Target**: `{waf_name}`\n"
            f"- **Discovered Origin IP**: `{origin_ip}:{port}` ({scheme.upper()})\n"
            f"- **Origin Web Server**: `{server}`\n"
            f"- **HTTP Status Code**: `{status}`\n"
            f"- **Evidence**: {origin_info['evidence']}\n\n"
            f"#### Direct Reproduction Command:\n"
            f"```bash\n{curl_cmd}\n```\n\n"
            f"Direct connection to the origin server bypasses all Cloudflare / WAF security rules, rate-limiting, and DDoS shields."
        )

        exploitation = (
            f"### Remediation & Firewall Locking\n\n"
            f"1. **Firewall Origin Server**: Restrict incoming connections on port {port} on `{origin_ip}` to ONLY permit traffic from authorized WAF reverse proxy IP ranges.\n"
            f"2. **Enable Authenticated Origin Pull (AOP)**: Require TLS client certificates between the WAF edge and `{origin_ip}`.\n"
            f"3. **Rotate Origin IP**: If this IP was historically indexed or leaked via DNS/mail records, migrate the origin host to a fresh, unindexed IP address."
        )

        await self.create_alert(
            title=title,
            description=description,
            target=target,
            risk_level="critical",
            details=details,
            exploitation_suggestions=exploitation,
            extra_key=f"origin_bypass:{origin_ip}:{target}",
            alert_type="waf_origin_bypass"
        )

    async def process_tasks(self):
        task = await self.get_next_task("waf_detect")
        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]

        try:
            raw = None
            resolved_url = None
            sample_headers = {}

            for scheme in ["https", "http"]:
                url = f"{scheme}://{target}"
                raw = await self.run_wafw00f(url)
                if raw is not None:
                    resolved_url = url
                    break

            if not resolved_url:
                resolved_url = f"https://{target}"

            waf_result = self.parse_wafw00f_result(raw)

            # Probe baseline headers to extract Edge POP and geographic markers (Enhancement #3)
            try:
                cmd = ["curl", "-sI", "-k", "-m", "8", resolved_url]
                stdout, _ = await self.run_command(cmd, timeout=10)
                if stdout:
                    for line in stdout.splitlines():
                        if ":" in line:
                            k, v = line.split(":", 1)
                            sample_headers[k.strip().lower()] = v.strip()
            except Exception as e:
                logger.debug(f"Error fetching sample headers for {resolved_url}: {e}")

            # Extract Cloud Edge POP & Geographic Mapping (Enhancement #3)
            edge_pop_info = self.extract_edge_pop_geo(sample_headers)
            waf_result["edge_pop"] = edge_pop_info

            # Reverse DNS lookup
            waf_result["ips"] = []
            waf_result["reverse_dns"] = {}
            waf_result["fqdns"] = []

            try:
                loop = asyncio.get_event_loop()
                addr_info = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
                resolved_ips = []
                for item in addr_info:
                    ip = item[4][0]
                    if ip and not ip.startswith("127.") and ip not in resolved_ips:
                        resolved_ips.append(ip)
                waf_result["ips"] = resolved_ips

                for ip in resolved_ips:
                    try:
                        fqdns = await self.reverse_dns_lookup(ip)
                        if fqdns:
                            waf_result["reverse_dns"][ip] = fqdns
                            for f in fqdns:
                                if f not in waf_result["fqdns"]:
                                    waf_result["fqdns"].append(f)
                    except Exception as rdns_err:
                        logger.debug(f"Reverse DNS error for WAF IP {ip}: {rdns_err}")
            except Exception as dns_err:
                logger.debug(f"Error resolving IPs for WAF target {target}: {dns_err}")

            # If WAF detected (or generic proxy detected):
            # Run Blocking Behavior Profiling (Enhancement #2) & Direct Origin Access Testing (Enhancement #1)
            waf_name = waf_result.get("firewall") or "WAF"
            if waf_result.get("detected"):
                # Enhancement #2: WAF Blocking Behavior Profile
                blocking_profile = await self.profile_waf_blocking_behavior(target, resolved_url)
                waf_result["blocking_behavior"] = blocking_profile

                # Enhancement #1: Direct Origin Access Testing (WAF Bypassing)
                origin_bypass_res = await self.test_direct_origin_access(target, root_domain, waf_name)
                waf_result["origin_bypass"] = origin_bypass_res
            else:
                waf_result["blocking_behavior"] = None
                waf_result["origin_bypass"] = None

            # Update MongoDB domains collection
            if target.strip().lower() == root_domain.strip().lower():
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {"infrastructure.waf": waf_result}}
                )
            else:
                await self.domains_col.update_one(
                    {"domain": root_domain, "infrastructure.subdomains.name": target},
                    {"$set": {"infrastructure.subdomains.$.waf": waf_result}}
                )
                await self.domains_col.update_one(
                    {"domain": root_domain, "web_applications.target": target},
                    {"$set": {"web_applications.$.waf": waf_result}}
                )

            logger.info(
                f"WAF scan complete for {target}: detected={waf_result['detected']}, "
                f"firewall={waf_result['firewall']}, pop={edge_pop_info.get('pop_code')}"
            )

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"WAF detection error for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )


if __name__ == "__main__":
    agent = WafDetectorAgent()
    asyncio.run(agent.main_loop())
