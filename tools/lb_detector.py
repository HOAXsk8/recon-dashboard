import asyncio
import datetime
import socket
import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpx
from base_agent import BaseAgent, logger

# ---------------------------------------------------------------------------
# Enhancement #3: Cloud Edge POP & Geographic Mapping (IATA Airport/Metro Map)
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
# Load Balancer & Reverse Proxy Manufacturer/Software Signatures Database
# ---------------------------------------------------------------------------
LB_SIGNATURES = [
    {
        "name": "F5 BIG-IP Local Traffic Manager (LTM)",
        "vendor": "F5 Networks",
        "category": "Hardware / Virtual Appliance",
        "cookies": [
            r"^BIGipServer",
            r"^TS[0-9a-fA-F]{6,8}",
            r"^F5_ST",
            r"^F5_HT_shrinked",
            r"^f5_cspm",
            r"^MRHSession",
        ],
        "headers": {
            "server": r"(?i)big-?ip",
            "x-wa-info": r".+",
            "x-cnection": r"(?i)close",
        },
        "body_patterns": [
            r"The requested URL was not found on this server",
            r"<!--\s*F5\s*-->",
        ],
        "ptr_patterns": [
            r"(?i)\bf5\b",
            r"(?i)big-?ip",
        ],
    },
    {
        "name": "AWS Application Load Balancer (ALB / ELB)",
        "vendor": "Amazon Web Services",
        "category": "Cloud Load Balancer",
        "cookies": [
            r"^AWSALB$",
            r"^AWSALBCORS$",
            r"^AWSELB$",
            r"^AWSALBTG$",
            r"^AWSALBTGCORS$",
        ],
        "headers": {
            "server": r"(?i)awselb",
            "x-amz-rid": r".+",
        },
        "body_patterns": [
            r"<title>502 Bad Gateway</title>[\s\S]*?awselb",
            r"<title>504 Gateway Time-out</title>[\s\S]*?awselb",
        ],
        "ptr_patterns": [
            r"(?i)\.elb\.amazonaws\.com$",
            r"(?i)\.elb\.amazonaws\.com\.$",
        ],
    },
    {
        "name": "AWS CloudFront Distribution & Edge",
        "vendor": "Amazon Web Services",
        "category": "Cloud Edge / Anycast Load Balancer",
        "headers": {
            "x-amz-cf-pop": r".+",
            "x-amz-cf-id": r".+",
            "server": r"(?i)CloudFront",
            "via": r"(?i)cloudfront",
        },
        "ptr_patterns": [
            r"(?i)\.cloudfront\.net$",
            r"(?i)\.cloudfront\.net\.$",
        ],
    },
    {
        "name": "Citrix ADC / NetScaler",
        "vendor": "Citrix Systems",
        "category": "Hardware / Virtual Appliance",
        "cookies": [
            r"^NSC_",
            r"^citrix_ns_id",
            r"^ns_af",
            r"^ns_session_id",
        ],
        "headers": {
            "cneonction": r"(?i)close",
            "nncoection": r"(?i)close",
            "x-citrix-application": r".+",
            "ns-cache-control": r".+",
            "server": r"(?i)netscaler",
        },
        "ptr_patterns": [
            r"(?i)netscaler",
            r"(?i)\bns\b.*\.citrix\.",
        ],
    },
    {
        "name": "HAProxy Load Balancer",
        "vendor": "HAProxy Technologies",
        "category": "Software Load Balancer",
        "cookies": [
            r"^SERVERID$",
            r"^SRV$",
            r"^HA_ID$",
            r"^HAPROXY",
        ],
        "headers": {
            "server": r"(?i)haproxy",
            "x-haproxy-": r".+",
        },
        "body_patterns": [
            r"503 Service Unavailable[\s\S]*?No server is available to handle this request",
            r"<html><body><h1>503 Service Unavailable</h1>\s*No server is available to handle this request\.</body></html>",
        ],
        "ptr_patterns": [
            r"(?i)haproxy",
        ],
    },
    {
        "name": "Microsoft Azure Application Gateway / ARR",
        "vendor": "Microsoft Azure",
        "category": "Cloud Load Balancer",
        "cookies": [
            r"^ARRAffinity$",
            r"^ARRAffinitySameSite$",
            r"^ApplicationGatewayAffinity$",
            r"^ApplicationGatewayAffinityCORS$",
        ],
        "headers": {
            "x-powered-by": r"(?i)\bARR\b",
            "x-ms-request-id": r".+",
            "x-azure-ref": r".+",
        },
        "ptr_patterns": [
            r"(?i)\.azurefd\.net$",
            r"(?i)\.trafficmanager\.net$",
            r"(?i)\.azureedge\.net$",
            r"(?i)\.cloudapp\.azure\.com$",
        ],
    },
    {
        "name": "Envoy Proxy / Istio Service Mesh",
        "vendor": "CNCF / Envoy Project",
        "category": "Software Load Balancer / Proxy",
        "headers": {
            "server": r"(?i)^envoy$",
            "x-envoy-upstream-service-time": r"\d+",
            "x-envoy-decorator-operation": r".+",
            "x-envoy-attempt-count": r"\d+",
        },
        "body_patterns": [
            r"upstream connect error or disconnect/reset before headers\. reset reason: connection failure",
            r"upstream request timeout",
            r"no healthy upstream",
        ],
    },
    {
        "name": "Traefik Modern HTTP Reverse Proxy",
        "vendor": "Traefik Labs",
        "category": "Software Load Balancer / Proxy",
        "headers": {
            "server": r"(?i)^traefik$",
        },
    },
    {
        "name": "Nginx / OpenResty Reverse Proxy",
        "vendor": "Nginx / F5",
        "category": "Software Load Balancer / Reverse Proxy",
        "headers": {
            "server": r"(?i)^(nginx|openresty)",
        },
    },
    {
        "name": "Google Cloud Load Balancing (GCLB)",
        "vendor": "Google Cloud",
        "category": "Cloud Load Balancer",
        "headers": {
            "via": r"(?i)1\.1 google",
            "server": r"(?i)^(gws|gse|googlefrontend)$",
            "x-cloud-trace-context": r".+",
        },
        "body_patterns": [
            r"<title>Error 502 \(Server Error\)!!1</title>",
            r"The server encountered a temporary error and could not complete your request",
        ],
        "ptr_patterns": [
            r"(?i)\.1e100\.net$",
            r"(?i)\.bc\.googleusercontent\.com$",
        ],
    },
    {
        "name": "Kemp LoadMaster",
        "vendor": "Progress / Kemp",
        "category": "Hardware / Virtual Load Balancer",
        "cookies": [
            r"^reassign_seq$",
            r"^u_sess$",
        ],
        "headers": {
            "x-kemp-": r".+",
            "server": r"(?i)kemp",
        },
    },
    {
        "name": "Fortinet FortiADC",
        "vendor": "Fortinet",
        "category": "Hardware / Virtual ADC",
        "cookies": [
            r"^FORTIADC",
        ],
        "headers": {
            "server": r"(?i)fortiadc",
        },
    },
    {
        "name": "Barracuda Load Balancer ADC",
        "vendor": "Barracuda Networks",
        "category": "Hardware / Virtual ADC",
        "cookies": [
            r"^barra_counter_session",
            r"^BNI__BARRACUDA_",
            r"^BNI_persistence",
            r"^BNES_",
        ],
        "headers": {
            "server": r"(?i)barracuda",
        },
    },
    {
        "name": "Radware Alteon ADC",
        "vendor": "Radware",
        "category": "Hardware Load Balancer",
        "cookies": [
            r"^rdwr_",
            r"^alteonP",
        ],
        "headers": {
            "x-radware-": r".+",
            "server": r"(?i)alteon",
        },
    },
    {
        "name": "Akamai Edge & Global Traffic Management (GTM)",
        "vendor": "Akamai Technologies",
        "category": "Global Server Load Balancing (GSLB) / Edge",
        "headers": {
            "server": r"(?i)akamaighost",
            "x-akamai-transformed": r".+",
            "x-akamai-staging": r".+",
        },
        "ptr_patterns": [
            r"(?i)\.akamaitechnologies\.com$",
            r"(?i)\.akadns\.net$",
            r"(?i)\.akamai\.net$",
        ],
    },
    {
        "name": "Cloudflare Global Load Balancing & Proxy",
        "vendor": "Cloudflare",
        "category": "Global Anycast Load Balancer / Edge",
        "headers": {
            "server": r"(?i)^cloudflare$",
            "cf-ray": r".+",
        },
        "cookies": [
            r"^__cf_bm$",
            r"^cf_clearance$",
            r"^__cfduid$",
        ],
        "ptr_patterns": [
            r"(?i)\.cloudflare\.com$",
        ],
    },
    {
        "name": "Fastly Edge Load Balancing",
        "vendor": "Fastly",
        "category": "Edge Cloud / Load Balancer",
        "headers": {
            "x-served-by": r"(?i)cache-",
            "x-fastly-request-id": r".+",
            "fastly-debug-digest": r".+",
        },
        "ptr_patterns": [
            r"(?i)\.fastly\.net$",
        ],
    },
    {
        "name": "Varnish Cache Reverse Proxy",
        "vendor": "Varnish Software",
        "category": "HTTP Accelerator / Reverse Proxy",
        "headers": {
            "via": r"(?i)varnish",
            "x-varnish": r"\d+",
        },
    },
    {
        "name": "Apache Traffic Server",
        "vendor": "Apache Software Foundation",
        "category": "Software Reverse Proxy / Cache",
        "headers": {
            "server": r"(?i)ATS",
            "via": r"(?i)traffic_server",
        },
    },
    {
        "name": "Caddy Modern Web Server & Reverse Proxy",
        "vendor": "Caddy",
        "category": "Software Reverse Proxy",
        "headers": {
            "server": r"(?i)^caddy$",
        },
    },
    {
        "name": "Kong API Gateway & Load Balancer",
        "vendor": "Kong Inc.",
        "category": "API Gateway / Reverse Proxy",
        "headers": {
            "server": r"(?i)^kong/",
            "via": r"(?i)kong",
        },
    },
]


def decode_f5_cookie(cookie_name: str, cookie_val: str) -> dict:
    """
    Decodes F5 BIG-IP persistence cookie to reveal internal backend IPv4 and port.
    Standard format: BIGipServer<pool>=<ip_int>.<port_int>.0000
    """
    try:
        parts = cookie_val.split(".")
        if len(parts) >= 2:
            ip_int = int(parts[0])
            port_int = int(parts[1])
            # Little endian decode for IPv4
            a = ip_int & 0xFF
            b = (ip_int >> 8) & 0xFF
            c = (ip_int >> 16) & 0xFF
            d = (ip_int >> 24) & 0xFF
            ip_str = f"{a}.{b}.{c}.{d}"
            # Port byte swap
            p_high = (port_int >> 8) & 0xFF
            p_low = port_int & 0xFF
            port = (p_low << 8) | p_high
            return {
                "cookie": cookie_name,
                "internal_ip": ip_str,
                "internal_port": port,
                "raw_value": cookie_val,
                "pool": cookie_name.replace("BIGipServer", "")
            }
    except Exception:
        pass
    return None


def match_load_balancer_fingerprints(headers_list, cookies_dict, body_snippets, fqdns):
    """
    Matches observed HTTP headers, Set-Cookie lines, error/body responses, and reverse DNS PTRs
    against LB_SIGNATURES to identify the exact manufacturer and software name.
    """
    matched_results = []
    f5_backends = []

    # Check for F5 cookie decoding
    for c_name, c_vals in cookies_dict.items():
        if c_name.startswith("BIGipServer"):
            for cv in c_vals:
                decoded = decode_f5_cookie(c_name, cv)
                if decoded and decoded not in f5_backends:
                    f5_backends.append(decoded)

    for sig in LB_SIGNATURES:
        evidence = []
        confidence_score = 0

        # 1. Check cookies
        sig_cookies = sig.get("cookies", [])
        for c_pat in sig_cookies:
            regex = re.compile(c_pat, re.I)
            for c_name, c_vals in cookies_dict.items():
                if regex.search(c_name):
                    val_sample = c_vals[0] if c_vals else ""
                    evidence.append(f"Cookie: {c_name}")
                    confidence_score += 4

        # 2. Check headers
        sig_headers = sig.get("headers", {})
        for h_key, h_val_pat in sig_headers.items():
            h_regex = re.compile(h_val_pat, re.I)
            for h_dict in headers_list:
                for actual_key, actual_val in h_dict.items():
                    if actual_key.lower() == h_key.lower() or (h_key.endswith("-") and actual_key.lower().startswith(h_key.lower())):
                        if h_regex.search(str(actual_val)):
                            ev_str = f"Header: {actual_key}: {actual_val}"
                            if ev_str not in evidence:
                                evidence.append(ev_str)
                                confidence_score += 3

        # 3. Check bodies / error templates
        sig_bodies = sig.get("body_patterns", [])
        for b_pat in sig_bodies:
            b_regex = re.compile(b_pat, re.I)
            for body in body_snippets:
                if body and b_regex.search(body):
                    ev_str = f"Response template match: {b_pat[:35]}..."
                    if ev_str not in evidence:
                        evidence.append(ev_str)
                        confidence_score += 2

        # 4. Check Reverse DNS PTRs
        sig_ptrs = sig.get("ptr_patterns", [])
        for p_pat in sig_ptrs:
            p_regex = re.compile(p_pat, re.I)
            for fqdn in fqdns:
                if fqdn and p_regex.search(fqdn):
                    ev_str = f"Reverse DNS (PTR): {fqdn}"
                    if ev_str not in evidence:
                        evidence.append(ev_str)
                        confidence_score += 2

        if evidence:
            confidence = "High" if confidence_score >= 3 else "Medium"
            matched_results.append({
                "name": sig["name"],
                "vendor": sig["vendor"],
                "category": sig["category"],
                "confidence": confidence,
                "score": confidence_score,
                "evidence": evidence
            })

    # Sort matched by score descending
    matched_results.sort(key=lambda x: x["score"], reverse=True)
    return matched_results, f5_backends


class LbDetectorAgent(BaseAgent):
    """
    Detects load balancers, reverse proxies, and Cloud Edge distribution using:
      1. Vendor & Software fingerprinting: matching signatures against cookies, headers, body templates, and PTRs.
      2. DNS round-robin: resolve domain repeatedly to collect unique IP addresses.
      3. HTTP header variance: compare Date precision, Server banners, and X-Served-By headers.
      4. Cloud Edge POP & Geographic mapping: parse cf-ray, x-amz-cf-pop, and x-served-by.
      5. Direct backend node probing: test direct connectivity to discovered backend nodes.
    """

    def __init__(self):
        super().__init__("lb_detector", "Load Balancer Detector")
        self.dns_samples = 10      # DNS queries to send
        self.http_samples = 8      # HTTP requests to send
        self.http_timeout = 10     # seconds per request

    # ------------------------------------------------------------------
    # Enhancement #3: Extract Edge POP & Geographic Location from Headers
    # ------------------------------------------------------------------
    def extract_edge_pop_geo(self, raw_headers: dict) -> dict:
        """Parses headers to identify Edge POP code and geographical location."""
        if not raw_headers:
            return {"provider": None, "pop_code": None, "city": None, "country": None, "region": None}

        norm = {k.lower(): str(v).strip() for k, v in raw_headers.items()}
        pop_code = None
        provider = None
        raw_evidence = None

        if "cf-ray" in norm:
            provider = "Cloudflare"
            raw_evidence = norm["cf-ray"]
            m = re.search(r"-([A-Z]{3})$", raw_evidence)
            if m:
                pop_code = m.group(1)
        elif "x-amz-cf-pop" in norm:
            provider = "AWS CloudFront"
            raw_evidence = norm["x-amz-cf-pop"]
            m = re.match(r"^([A-Z]{3})", raw_evidence)
            if m:
                pop_code = m.group(1)
        elif "x-served-by" in norm:
            provider = "Fastly"
            raw_evidence = norm["x-served-by"]
            m = re.search(r"-([A-Z]{3})$", raw_evidence)
            if m:
                pop_code = m.group(1)
        elif "x-azure-ref" in norm:
            provider = "Microsoft Azure Front Door"
            raw_evidence = norm["x-azure-ref"]
        elif any(k.startswith("x-akamai") for k in norm) or "akamaighost" in norm.get("server", "").lower():
            provider = "Akamai"
            raw_evidence = norm.get("x-akamai-transformed") or norm.get("server")

        geo = IATA_POP_MAP.get(pop_code, {})
        return {
            "provider": provider,
            "pop_code": pop_code,
            "city": geo.get("city", "Unknown City" if pop_code else None),
            "country": geo.get("country", "Unknown Country" if pop_code else None),
            "region": geo.get("region", "Unknown Region" if pop_code else None),
            "header_evidence": raw_evidence
        }

    # ------------------------------------------------------------------
    # DNS round-robin detection
    # ------------------------------------------------------------------
    async def check_dns_roundrobin(self, domain):
        """Resolve the domain repeatedly and collect distinct IPs."""
        loop = asyncio.get_event_loop()
        seen_ips = set()
        for _ in range(self.dns_samples):
            try:
                results = await loop.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
                for r in results:
                    ip = r[4][0]
                    if ip and not ip.startswith("127."):
                        seen_ips.add(ip)
            except Exception as e:
                logger.debug(f"DNS resolution error for {domain}: {e}")
            await asyncio.sleep(0.2)
        return list(seen_ips)

    # ------------------------------------------------------------------
    # HTTP header variance & Edge POP detection
    # ------------------------------------------------------------------
    async def check_http_variance(self, domain):
        """
        Send multiple HTTP requests and look for inconsistent headers
        (different Date precision, Server banners, or X-Served-By values),
        record Edge POP locations, collect Set-Cookie headers, and probe error pages.
        """
        dates = []
        servers = []
        served_by = []
        all_headers_list = []
        edge_pops = []
        cookies_dict = {}
        body_snippets = []

        async with httpx.AsyncClient(
            timeout=self.http_timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": self.user_agent}
        ) as client:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{domain}/"
                for i in range(self.http_samples):
                    try:
                        resp = await client.get(url)
                        h = resp.headers
                        h_dict = dict(h)
                        all_headers_list.append(h_dict)

                        # Capture parsed cookies
                        for c_k, c_v in resp.cookies.items():
                            if c_k not in cookies_dict:
                                cookies_dict[c_k] = []
                            if c_v not in cookies_dict[c_k]:
                                cookies_dict[c_k].append(c_v)

                        # Also capture raw Set-Cookie lines to catch affinity attributes
                        for sc in h.get_list("set-cookie"):
                            m = re.match(r"^([^=;,\s]+)=([^;]*)", sc)
                            if m:
                                raw_ck, raw_cv = m.group(1).strip(), m.group(2).strip()
                                if raw_ck not in cookies_dict:
                                    cookies_dict[raw_ck] = []
                                if raw_cv not in cookies_dict[raw_ck]:
                                    cookies_dict[raw_ck].append(raw_cv)

                        if resp.text and len(body_snippets) < 2:
                            body_snippets.append(resp.text[:4096])

                        if h.get("date"):
                            dates.append(h["date"])
                        if h.get("server"):
                            servers.append(h["server"])
                        for key in ("x-served-by", "x-backend-server", "via", "x-cache"):
                            if h.get(key):
                                served_by.append(h[key])

                        # Extract edge pop per request
                        pop_info = self.extract_edge_pop_geo(h_dict)
                        if pop_info.get("pop_code"):
                            edge_pops.append(pop_info)
                    except Exception as e:
                        logger.debug(f"HTTP probe {i} for {url} failed: {e}")
                    await asyncio.sleep(0.2)
                if dates or servers:
                    # Also probe an intentional non-existent URL to capture LB error page templates (e.g. HAProxy 503, Envoy reset, AWS ALB 502/504)
                    try:
                        err_url = f"{scheme}://{domain}/_recon_lb_probe_{os.urandom(4).hex()}"
                        err_resp = await client.get(err_url)
                        all_headers_list.append(dict(err_resp.headers))
                        if err_resp.text:
                            body_snippets.append(err_resp.text[:4096])
                    except Exception as probe_err:
                        logger.debug(f"Error page probe failed for {url}: {probe_err}")
                    break  # Got data from this scheme

        # Analyse for variance
        unique_servers = set(servers)
        unique_served_by = set(served_by)
        date_variance = len(set(d[:25] for d in dates)) > 1 if dates else False

        # Analyse Edge POP geographic distribution (Enhancement #3)
        unique_pop_codes = sorted(list(set(p["pop_code"] for p in edge_pops if p.get("pop_code"))))
        unique_cities = sorted(list(set(p["city"] for p in edge_pops if p.get("city"))))
        unique_countries = sorted(list(set(p["country"] for p in edge_pops if p.get("country"))))
        geo_steering_detected = len(unique_pop_codes) > 1

        primary_pop = edge_pops[0] if edge_pops else None

        return {
            "unique_servers": list(unique_servers),
            "served_by": list(unique_served_by),
            "date_variance": date_variance,
            "server_variance": len(unique_servers) > 1,
            "primary_edge_pop": primary_pop,
            "unique_pop_codes": unique_pop_codes,
            "unique_cities": unique_cities,
            "unique_countries": unique_countries,
            "geo_steering_detected": geo_steering_detected,
            "sample_headers": all_headers_list[0] if all_headers_list else {},
            "all_headers_list": all_headers_list,
            "cookies_dict": cookies_dict,
            "body_snippets": body_snippets
        }

    # ------------------------------------------------------------------
    # Enhancement #1: Direct Backend Node Probing
    # ------------------------------------------------------------------
    async def test_direct_backend_nodes(self, domain: str, backend_ips: list) -> list:
        """
        Tests whether individual backend node IPs discovered via DNS round-robin
        respond directly when queried with the target Host: header.
        """
        node_results = []
        if not backend_ips or len(backend_ips) <= 1:
            return node_results

        for ip in backend_ips[:8]:
            for scheme, port in [("https", 443), ("http", 80)]:
                cmd = ["curl", "-sI", "-k", "-m", "5", "-A", self.user_agent, "-H", f"Host: {domain}", f"{scheme}://{ip}:{port}/"]
                try:
                    stdout, _ = await self.run_command(cmd, timeout=7)
                    if not stdout:
                        continue

                    status_code = None
                    server_val = None
                    for line in stdout.splitlines():
                        if not status_code:
                            m = re.search(r"HTTP/\S+\s+(\d{3})", line)
                            if m:
                                status_code = int(m.group(1))
                        if line.lower().startswith("server:"):
                            server_val = line.split(":", 1)[1].strip()

                    if status_code:
                        node_results.append({
                            "ip": ip,
                            "port": port,
                            "scheme": scheme,
                            "status": status_code,
                            "server": server_val or "Unknown Server",
                            "direct_accessible": True
                        })
                        break
                except Exception as e:
                    logger.debug(f"Direct node probe error for {ip}:{port}: {e}")

        return node_results

    # ------------------------------------------------------------------
    # Aggregate result
    # ------------------------------------------------------------------
    async def detect_load_balancer(self, domain):
        ips = await self.check_dns_roundrobin(domain)
        http_info = await self.check_http_variance(domain)

        # Fallback resolution if not already resolved
        if not ips:
            try:
                loop = asyncio.get_event_loop()
                results = await loop.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
                for r in results:
                    ip = r[4][0]
                    if ip and not ip.startswith("127.") and ip not in ips:
                        ips.append(ip)
            except Exception as e:
                logger.debug(f"Fallback DNS resolution error for {domain}: {e}")

        # Perform reverse DNS lookup using `dig -x`
        reverse_dns = {}
        all_fqdns = []
        if ips:
            for ip in ips:
                try:
                    fqdns = await self.reverse_dns_lookup(ip)
                    if fqdns:
                        reverse_dns[ip] = fqdns
                        for f in fqdns:
                            if f not in all_fqdns:
                                all_fqdns.append(f)
                except Exception as rdns_err:
                    logger.debug(f"Reverse DNS error for LB IP {ip}: {rdns_err}")

        # Match vendor/manufacturer signatures
        matched_vendors, f5_backends = match_load_balancer_fingerprints(
            headers_list=http_info.get("all_headers_list", []),
            cookies_dict=http_info.get("cookies_dict", {}),
            body_snippets=http_info.get("body_snippets", []),
            fqdns=all_fqdns
        )

        dns_lb = len(ips) > 1
        http_lb = http_info["server_variance"] or http_info["date_variance"] or len(http_info["served_by"]) > 0
        geo_lb = http_info["geo_steering_detected"]
        vendor_lb = len(matched_vendors) > 0

        detected = dns_lb or http_lb or geo_lb or vendor_lb

        methods = []
        vendor_name = None
        vendor_category = None
        confidence = None
        signatures_matched = []
        all_vendors = []

        if vendor_lb:
            top_vendor = matched_vendors[0]
            vendor_name = top_vendor["name"]
            vendor_category = top_vendor["category"]
            confidence = top_vendor["confidence"]
            all_vendors = [m["name"] for m in matched_vendors]
            signatures_matched = [ev for m in matched_vendors for ev in m["evidence"]]
            methods.append(f"{vendor_name}")

        if dns_lb:
            methods.append(f"DNS round-robin ({len(ips)} IPs)")
        if http_lb and not vendor_lb:
            if http_info["server_variance"]:
                methods.append("HTTP Server header variance")
            if http_info["date_variance"]:
                methods.append("HTTP Date header variance")
            if http_info["served_by"]:
                methods.append("HTTP proxy/cache header")
        if geo_lb:
            methods.append(f"Geo-distributed edge routing ({', '.join(http_info['unique_pop_codes'])})")

        # Classify specific Load Balancing Type(s) / Mechanism
        lb_types = []
        if dns_lb:
            lb_types.append(f"DNS Round Robin ({len(ips)} IPs)")
        if any("Cookie:" in ev for ev in signatures_matched):
            lb_types.append("Cookie Session Affinity (Sticky Session)")
        if geo_lb:
            lb_types.append(f"Geo-Distributed Edge Anycast ({len(http_info['unique_pop_codes'])} POPs)")
        if http_lb or any("Header:" in ev for ev in signatures_matched):
            if not any("Cookie" in t for t in lb_types):
                lb_types.append("Layer 7 HTTP Reverse Proxy")
        if not lb_types and detected:
            lb_types.append("Layer 4 Transport Load Balancer")

        primary_lb_type = " • ".join(lb_types) if lb_types else ("DNS Round Robin" if len(ips) > 1 else "Reverse Proxy")

        # Enhancement #1: Test direct connectivity to backend node IPs
        backend_nodes = []
        if detected and len(ips) > 1:
            backend_nodes = await self.test_direct_backend_nodes(domain, ips)

        detail_parts = []
        if vendor_name:
            detail_parts.append(f"Manufacturer/Software: {vendor_name} ({confidence} Confidence)")
        if primary_lb_type:
            detail_parts.append(f"Balancing Type: {primary_lb_type}")
        if signatures_matched:
            detail_parts.append(f"Signatures: {'; '.join(signatures_matched[:4])}")
        if f5_backends:
            f5_str = ", ".join(f"{b['internal_ip']}:{b['internal_port']} (pool: {b['pool']})" for b in f5_backends)
            detail_parts.append(f"F5 Decoded Backends: {f5_str}")
        if http_info["served_by"]:
            detail_parts.append(f"Via/X-Served-By: {', '.join(http_info['served_by'])}")
        if http_info["unique_servers"] and http_info["server_variance"]:
            detail_parts.append(f"Server headers: {', '.join(http_info['unique_servers'])}")
        if http_info["unique_pop_codes"]:
            detail_parts.append(f"Edge POPs: {', '.join(http_info['unique_pop_codes'])} ({', '.join(http_info['unique_cities'])})")
        if all_fqdns:
            detail_parts.append(f"Reverse DNS (FQDN): {', '.join(all_fqdns)}")

        return {
            "detected": detected,
            "vendor": vendor_name,
            "vendors": all_vendors,
            "vendor_category": vendor_category,
            "confidence": confidence,
            "lb_type": primary_lb_type,
            "lb_types": lb_types,
            "signatures_matched": signatures_matched,
            "f5_decoded_backends": f5_backends,
            "method": " • ".join(methods) if methods else None,
            "ips": ips,
            "reverse_dns": reverse_dns,
            "fqdns": all_fqdns,
            "edge_pop": http_info.get("primary_edge_pop"),
            "geo_distribution": {
                "geo_steering_detected": geo_lb,
                "unique_pops": http_info["unique_pop_codes"],
                "unique_cities": http_info["unique_cities"],
                "unique_countries": http_info["unique_countries"]
            },
            "backend_nodes_tested": backend_nodes,
            "details": "; ".join(detail_parts) if detail_parts else None,
            "scanned_at": datetime.datetime.utcnow().isoformat()
        }

    # ------------------------------------------------------------------
    # Task processing
    # ------------------------------------------------------------------
    async def process_tasks(self):
        task = await self.get_next_task("lb_detect")
        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]

        try:
            lb_result = await self.detect_load_balancer(target)

            if target.strip().lower() == root_domain.strip().lower():
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {"infrastructure.load_balancer": lb_result}}
                )
            else:
                await self.domains_col.update_one(
                    {"domain": root_domain, "infrastructure.subdomains.name": target},
                    {"$set": {"infrastructure.subdomains.$.load_balancer": lb_result}}
                )
                await self.domains_col.update_one(
                    {"domain": root_domain, "web_applications.target": target},
                    {"$set": {"web_applications.$.load_balancer": lb_result}}
                )
            logger.info(
                f"LB scan complete for {target}: detected={lb_result['detected']}, "
                f"ips={lb_result['ips']}, method={lb_result['method']}"
            )

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"LB detection error for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )


if __name__ == "__main__":
    agent = LbDetectorAgent()
    asyncio.run(agent.main_loop())
