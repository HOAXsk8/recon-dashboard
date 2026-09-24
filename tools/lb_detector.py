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


class LbDetectorAgent(BaseAgent):
    """
    Detects load balancers, reverse proxies, and Cloud Edge distribution using:
      1. DNS round-robin: resolve domain repeatedly to collect unique IP addresses.
      2. HTTP header variance: compare Date precision, Server banners, and X-Served-By headers.
      3. Cloud Edge POP & Geographic mapping: parse cf-ray, x-amz-cf-pop, and x-served-by.
      4. Direct backend node probing: test direct connectivity to discovered backend nodes.
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
        (different Date precision, Server banners, or X-Served-By values)
        and record Edge POP locations across requests.
        """
        dates = []
        servers = []
        served_by = []
        all_headers_list = []
        edge_pops = []

        async with httpx.AsyncClient(
            timeout=self.http_timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"}
        ) as client:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{domain}/"
                for i in range(self.http_samples):
                    try:
                        resp = await client.get(url)
                        h = resp.headers
                        all_headers_list.append(dict(h))

                        if h.get("date"):
                            dates.append(h["date"])
                        if h.get("server"):
                            servers.append(h["server"])
                        for key in ("x-served-by", "x-backend-server", "via", "x-cache"):
                            if h.get(key):
                                served_by.append(h[key])

                        # Extract edge pop per request
                        pop_info = self.extract_edge_pop_geo(dict(h))
                        if pop_info.get("pop_code"):
                            edge_pops.append(pop_info)
                    except Exception as e:
                        logger.debug(f"HTTP probe {i} for {url} failed: {e}")
                    await asyncio.sleep(0.2)
                if dates or servers:
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
            "sample_headers": all_headers_list[0] if all_headers_list else {}
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
                cmd = ["curl", "-sI", "-k", "-m", "5", "-H", f"Host: {domain}", f"{scheme}://{ip}:{port}/"]
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

        dns_lb = len(ips) > 1
        http_lb = http_info["server_variance"] or http_info["date_variance"] or len(http_info["served_by"]) > 0
        geo_lb = http_info["geo_steering_detected"]

        methods = []
        if dns_lb:
            methods.append(f"DNS round-robin ({len(ips)} IPs)")
        if http_lb:
            if http_info["server_variance"]:
                methods.append("HTTP Server header variance")
            if http_info["date_variance"]:
                methods.append("HTTP Date header variance")
            if http_info["served_by"]:
                methods.append("HTTP proxy/cache header")
        if geo_lb:
            methods.append(f"Geo-distributed edge routing ({', '.join(http_info['unique_pop_codes'])})")

        detected = dns_lb or http_lb or geo_lb

        # Fallback resolution if not already resolved
        if detected and not ips:
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
        if detected and ips:
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

        # Enhancement #1: Test direct connectivity to backend node IPs
        backend_nodes = []
        if detected and len(ips) > 1:
            backend_nodes = await self.test_direct_backend_nodes(domain, ips)

        detail_parts = []
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
            "method": ", ".join(methods) if methods else None,
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
