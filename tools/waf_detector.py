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
    @staticmethod
    def parse_curl_chain(stdout: str) -> list:
        """Parses output of curl -sI -L containing one or more HTTP response blocks."""
        blocks = re.split(r'(?:\r?\n){2,}', (stdout or "").strip())
        chain = []
        for b in blocks:
            lines = [line.strip() for line in b.splitlines() if line.strip()]
            if not lines:
                continue
            first = lines[0]
            m = re.search(r"HTTP/\S+\s+(\d{3})", first)
            if not m:
                continue
            status_code = int(m.group(1))
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            chain.append({
                "status_line": first,
                "status_code": status_code,
                "headers": headers,
                "server": headers.get("server", ""),
                "location": headers.get("location", ""),
                "via": headers.get("via", "")
            })
        return chain

    async def profile_waf_blocking_behavior(self, target: str, url: str) -> dict:
        """
        Tests standard attack vectors (SQLi, XSS, Path Traversal, Cmd Injection, SSTI,
        scanner user-agent, fuzzing) against the endpoint to establish which classes of attacks
        are actively blocked by the WAF and identify defensive gaps with full evidentiary detail.
        """
        logger.info(f"Profiling WAF blocking behavior on {url}")

        test_cases = [
            {
                "id": "sqli",
                "name": "SQL Injection",
                "vector_type": "Query Parameter",
                "payload": "?id=1' OR '1'='1",
                "query": "?id=1%27+OR+%271%27%3D%271",
                "headers": [],
                "description": "Standard SQL boolean tautology injection in URL parameter."
            },
            {
                "id": "xss",
                "name": "Cross-Site Scripting (XSS)",
                "vector_type": "Query Parameter",
                "payload": "?q=<script>alert(1)</script>",
                "query": "?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                "headers": [],
                "description": "Unsanitized inline script tag payload in search/query parameter."
            },
            {
                "id": "path_traversal",
                "name": "Directory / Path Traversal",
                "vector_type": "Path Parameter",
                "payload": "?file=../../../../etc/passwd",
                "query": "?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                "headers": [],
                "description": "Dot-dot-slash sequence aimed at accessing underlying UNIX files."
            },
            {
                "id": "cmd_injection",
                "name": "Command Injection (RCE)",
                "vector_type": "Command Argument",
                "payload": "?cmd=;cat /etc/passwd;",
                "query": "?cmd=%3Bcat+%2Fetc%2Fpasswd%3B",
                "headers": [],
                "description": "Semicolon shell command separator invoking system shell execution."
            },
            {
                "id": "ssti",
                "name": "Server-Side Template Injection",
                "vector_type": "Template Expression",
                "payload": "?name={{7*7}}",
                "query": "?name=%7B%7B7*7%7D%7D",
                "headers": [],
                "description": "Jinja/Twig/Smarty double-curly template expression evaluation."
            },
            {
                "id": "scanner_user_agent",
                "name": "Malicious Scanner User-Agent",
                "vector_type": "HTTP Request Header",
                "payload": "User-Agent: sqlmap/1.6#stable (https://sqlmap.org)",
                "query": "/",
                "headers": ["-A", "sqlmap/1.6#stable (https://sqlmap.org)"],
                "description": "Well-known automated penetration testing tool user-agent signature."
            },
            {
                "id": "special_chars",
                "name": "Protocol Fuzzing / Special Chars",
                "vector_type": "Query Parameter",
                "payload": "?fuzz=\\x00\\n\\r'\"<>",
                "query": "?fuzz=%00%0a%0d%27%22%3c%3e",
                "headers": [],
                "description": "Null-bytes, CRLF delimiters, quotes, and angle brackets for protocol fuzzing."
            }
        ]

        # Baseline probe
        base_clean = url.rstrip("/")
        baseline_status = 200
        baseline_server = ""
        baseline_url = url

        candidate_urls = [url]
        if url.startswith("https://"):
            candidate_urls.append("http://" + url[len("https://"):])
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc.startswith("www."):
            candidate_urls.append(f"https://www.{parsed.netloc}")

        for test_url in candidate_urls:
            try:
                cmd = ["curl", "-sI", "-k", "-m", "6", "-L", "-A", self.user_agent, test_url]
                stdout, _ = await self.run_command(cmd, timeout=8)
                chain = self.parse_curl_chain(stdout)
                if chain:
                    final_hop = chain[-1]
                    baseline_status = final_hop["status_code"]
                    baseline_server = final_hop.get("server", "")
                    # If target redirected to a canonical URL on the same domain, adopt it for accurate probing
                    for hop in chain[:-1]:
                        loc = hop.get("location", "")
                        if loc:
                            if loc.startswith("/"):
                                p = urllib.parse.urlparse(test_url)
                                baseline_url = f"{p.scheme}://{p.netloc}{loc}".rstrip("/")
                            elif any(part in loc for part in [target, "www." + target]):
                                baseline_url = loc.rstrip("/")
                    if not any(hop.get("location") for hop in chain[:-1]):
                        baseline_url = test_url
                    break
            except Exception as e:
                logger.debug(f"Baseline probe error for {test_url}: {e}")

        # Use canonical URL base if redirected (e.g. o2.co.uk -> www.o2.co.uk)
        target_base = baseline_url.rstrip("/") if baseline_url else base_clean

        results = []
        blocked_count = 0
        allowed_count = 0
        unresponsive_count = 0
        blocked_categories = []
        allowed_categories = []
        unresponsive_categories = []

        for tc in test_cases:
            probe_url = f"{target_base}/{tc['query'].lstrip('/')}" if not tc['query'].startswith("?") else f"{target_base}{tc['query']}"
            cmd = ["curl", "-sI", "-k", "-m", "10", "-L"]
            if tc["headers"]:
                cmd.extend(tc["headers"])
                if not any(h in ["-A", "--user-agent"] for h in tc["headers"]):
                    cmd.extend(["-A", self.user_agent])
            else:
                cmd.extend(["-A", self.user_agent])
            cmd.append(probe_url)

            status_code = None
            server_header = ""
            via_header = ""
            is_blocked = False
            is_allowed = False
            outcome = "UNRESPONSIVE"
            raw_evidence = ""

            try:
                stdout, _ = await self.run_command(cmd, timeout=12)
                raw_evidence = (stdout or "").strip()
                chain = self.parse_curl_chain(stdout)
                if chain:
                    final_hop = chain[-1]
                    status_code = final_hop["status_code"]
                    server_header = final_hop.get("server") or ""
                    via_header = final_hop.get("headers", {}).get("via") or ""
                    azure_ref = final_hop.get("headers", {}).get("x-azure-ref") or ""
                    cf_ray = final_hop.get("headers", {}).get("cf-ray") or ""

                    if not server_header:
                        if azure_ref:
                            server_header = "Microsoft Azure Front Door / Gateway"
                        elif cf_ray:
                            server_header = "Cloudflare Edge"
                        elif via_header:
                            server_header = f"Edge Proxy ({via_header})"

                    # Check if ANY hop in the redirect chain returned a WAF block code
                    block_hops = [h for h in chain if h["status_code"] in (403, 406, 429, 999)]
                    waf_sign = any(
                        any(sig in (h.get("headers", {}).get("via", "") + h.get("headers", {}).get("server", "") + h.get("status_line", "")).lower()
                            for sig in ["cloudflare", "akamaighost", "imperva", "waf", "access denied", "azure-ref"])
                        for h in chain
                    )

                    if block_hops:
                        is_blocked = True
                        status_code = block_hops[-1]["status_code"]
                        outcome = f"BLOCKED (HTTP {status_code})"
                    elif status_code == 403 or (status_code and status_code >= 400 and waf_sign):
                        is_blocked = True
                        outcome = f"BLOCKED (HTTP {status_code})"
                    elif status_code and (status_code == baseline_status or (200 <= status_code < 400)):
                        is_allowed = True
                        outcome = f"BYPASSED (HTTP {status_code})"
                    else:
                        outcome = f"HTTP {status_code}"
                else:
                    outcome = "NO_RESPONSE"
            except Exception as e:
                logger.debug(f"WAF profile test {tc['id']} error: {e}")
                outcome = "TIMEOUT"
                raw_evidence = str(e)

            if is_blocked:
                blocked_count += 1
                blocked_categories.append(tc["name"])
            elif is_allowed:
                allowed_count += 1
                allowed_categories.append(tc["name"])
            else:
                unresponsive_count += 1
                unresponsive_categories.append(tc["name"])

            results.append({
                "category_id": tc["id"],
                "name": tc["name"],
                "vector_type": tc["vector_type"],
                "payload": tc["payload"],
                "description": tc["description"],
                "probe_url": probe_url,
                "status_code": status_code,
                "blocked": is_blocked,
                "allowed": is_allowed,
                "outcome": outcome,
                "server": server_header,
                "evidence": raw_evidence[:600]
            })

        total = len(test_cases)
        block_rate = round((blocked_count / total) * 100, 1) if total > 0 else 0

        profile = {
            "tested_probes_count": total,
            "blocked_count": blocked_count,
            "allowed_count": allowed_count,
            "unresponsive_count": unresponsive_count,
            "block_rate_percent": block_rate,
            "baseline_status": baseline_status,
            "baseline_url": baseline_url,
            "baseline_server": baseline_server,
            "blocked_categories": blocked_categories,
            "allowed_categories": allowed_categories,
            "unresponsive_categories": unresponsive_categories,
            "detailed_results": results
        }

        # Only flag alert if critical attacks genuinely bypassed the WAF
        critical_unblocked = [c for c in ["SQL Injection", "Directory / Path Traversal", "Command Injection (RCE)"] if c in allowed_categories]
        if critical_unblocked:
            await self.create_waf_gap_alert(target, critical_unblocked, profile, url)

        return profile

    async def create_waf_gap_alert(self, target: str, critical_unblocked: list, profile: dict, url: str):
        """Create a lead/alert when critical attack vectors are not blocked by the WAF with complete test evidence."""
        title = f"WAF Protection Gap: Unblocked Attack Classes on {target}"
        description = f"WAF active but failed to block simulated attack vectors: {', '.join(critical_unblocked)}"
        
        # Build Markdown Table of all probes
        table_rows = []
        for r in profile.get("detailed_results", []):
            status_str = f"`HTTP {r['status_code']}`" if r.get("status_code") else "`No Response`"
            server_str = r.get("server") or "Unknown"
            if r.get("blocked"):
                badge = f"🛡️ **BLOCKED** ({r.get('outcome')})"
            elif r.get("allowed"):
                badge = f"⚠️ **BYPASSED** ({r.get('outcome')})"
            else:
                badge = f"⏳ **UNRESPONSIVE**"
            payload_clean = r.get("payload", "").replace("|", "\\|")
            table_rows.append(f"| **{r['name']}** | `{r.get('vector_type', 'Param')}` | `{payload_clean}` | {status_str} | {server_str} | {badge} |")

        table_md = (
            "| Attack Vector | Vector Type | Tested Payload / Vector | Status Code | Edge / Server | Result |\n"
            "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
            + "\n".join(table_rows)
        )

        # Build Deep-Dive section for bypassed vectors
        bypassed_items = [r for r in profile.get("detailed_results", []) if r.get("allowed")]
        bypassed_md_list = []
        for idx, item in enumerate(bypassed_items, 1):
            evidence_block = f"```http\n{item['evidence']}\n```" if item.get("evidence") else "_No raw HTTP headers recorded_"
            bypassed_md_list.append(
                f"#### {idx}. ⚠️ {item['name']} (Bypassed WAF)\n"
                f"- **Vector Type**: `{item.get('vector_type', 'Parameter')}`\n"
                f"- **Injected Payload**: `{item.get('payload')}`\n"
                f"- **Full Target URL**: `{item.get('probe_url')}`\n"
                f"- **Response Code**: `HTTP {item.get('status_code')}` (Baseline: `HTTP {profile.get('baseline_status')}`)\n"
                f"- **Edge / Server Identity**: `{item.get('server') or 'Standard Origin Server'}`\n"
                f"- **Mechanism**: {item.get('description')}\n"
                f"- **Observed Response Headers / Evidence**:\n{evidence_block}\n"
            )
        bypassed_section = "\n".join(bypassed_md_list) if bypassed_md_list else "_None of the tested attack vectors bypassed the WAF._"

        # Build Deep-Dive section for blocked vectors
        blocked_items = [r for r in profile.get("detailed_results", []) if r.get("blocked")]
        blocked_md_list = []
        for item in blocked_items:
            blocked_md_list.append(
                f"- 🛡️ **{item['name']}**: Neutralized with `{item.get('outcome')}` by `{item.get('server') or 'WAF Edge'}` (Payload: `{item.get('payload')}`)"
            )
        blocked_section = "\n".join(blocked_md_list) if blocked_md_list else "_No attack vectors were blocked by the edge filter._"

        details = (
            f"### 🛡️ WAF Rule Gap & Bypass Audit for `{url}`\n\n"
            f"The Web Application Firewall (WAF) was actively audited using industry-standard simulated attack payloads against `{target}`. "
            f"The inspection engine permitted **{len(critical_unblocked)}** high-severity attack vector(s) to pass through to the origin application server without interception.\n\n"
            f"- **Target Evaluated**: `{url}`\n"
            f"- **Canonical Base URL**: `{profile.get('baseline_url', url)}`\n"
            f"- **Baseline HTTP Status**: `HTTP {profile.get('baseline_status')}`\n"
            f"- **Overall Block Rate**: `{profile['block_rate_percent']}%` ({profile['blocked_count']}/{profile['tested_probes_count']} probes blocked)\n"
            f"- **Unblocked / Bypassed Vectors**: `{profile['allowed_count']}`\n"
            f"- **Unresponsive / Timed Out**: `{profile.get('unresponsive_count', 0)}`\n\n"
            f"### 📋 Full Probe Test Matrix\n\n"
            f"{table_md}\n\n"
            f"### ⚠️ Bypassed Attack Vectors (Evidence of WAF Gap)\n\n"
            f"{bypassed_section}\n\n"
            f"### 🛡️ Successfully Blocked Vectors\n\n"
            f"{blocked_section}\n"
        )

        exploitation = (
            f"### Remediation & WAF Hardening Recommendations\n\n"
            f"1. **Enable Strict Managed Rules**: Activate Core Rule Set (CRS) or vendor-managed signatures (e.g., Azure Front Door Managed Rules, Cloudflare WAF, AWS WAF CRS) for: **{', '.join(critical_unblocked)}**.\n"
            f"2. **Verify WAF Action Mode**: Ensure rule sets are set to active **'Block'** or **'Drop'** mode rather than passive 'Count', 'Log', or 'Simulate' mode.\n"
            f"3. **Payload Normalization & Pre-decoding**: Ensure input strings are URL-decoded and canonicalized prior to regex/signature matching to prevent evasion via percent-encoding.\n"
            f"4. **Origin Lockdown**: Ensure backend origin IPs do not accept direct connections that bypass the WAF reverse proxy."
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
                    "-A", self.user_agent,
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
                                "curl_command": f"curl -k -A '{self.user_agent}' -H 'Host: {target}' {scheme}://{ip}:{port}/",
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
                cmd = ["curl", "-sI", "-k", "-m", "8", "-A", self.user_agent, resolved_url]
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
