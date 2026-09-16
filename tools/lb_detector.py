import asyncio
import datetime
import socket
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpx
from base_agent import BaseAgent, logger


class LbDetectorAgent(BaseAgent):
    """
    Detects load balancers using two techniques — mirroring what `lbd` does:
      1. DNS round-robin: resolve the domain multiple times and collect unique IPs.
      2. HTTP header variance: make multiple HTTP requests and compare Date/Server
         headers for inconsistencies indicating different backend nodes.
    """

    def __init__(self):
        super().__init__("lb_detector", "Load Balancer Detector")
        self.dns_samples = 10      # DNS queries to send
        self.http_samples = 8      # HTTP requests to send
        self.http_timeout = 10     # seconds per request

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
            await asyncio.sleep(0.3)
        return list(seen_ips)

    # ------------------------------------------------------------------
    # HTTP header variance detection
    # ------------------------------------------------------------------
    async def check_http_variance(self, domain):
        """
        Send multiple HTTP requests and look for inconsistent headers
        (different Date precision, Server banners, or X-Served-By values)
        that indicate traffic is hitting different backend nodes.
        """
        dates = []
        servers = []
        served_by = []

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
                        if h.get("date"):
                            dates.append(h["date"])
                        if h.get("server"):
                            servers.append(h["server"])
                        for key in ("x-served-by", "x-backend-server", "via", "x-cache"):
                            if h.get(key):
                                served_by.append(h[key])
                    except Exception as e:
                        logger.debug(f"HTTP probe {i} for {url} failed: {e}")
                    await asyncio.sleep(0.2)
                if dates or servers:
                    break  # Got data from this scheme, no need to try the other

        # Analyse for variance
        unique_servers = set(servers)
        unique_served_by = set(served_by)
        # Date variance: compare seconds — LB nodes can have slight clock drift
        date_variance = len(set(d[:25] for d in dates)) > 1 if dates else False

        return {
            "unique_servers": list(unique_servers),
            "served_by": list(unique_served_by),
            "date_variance": date_variance,
            "server_variance": len(unique_servers) > 1,
        }

    # ------------------------------------------------------------------
    # Aggregate result
    # ------------------------------------------------------------------
    async def detect_load_balancer(self, domain):
        ips = await self.check_dns_roundrobin(domain)
        http_info = await self.check_http_variance(domain)

        dns_lb = len(ips) > 1
        http_lb = http_info["server_variance"] or http_info["date_variance"] or len(http_info["served_by"]) > 0

        methods = []
        if dns_lb:
            methods.append("DNS round-robin")
        if http_lb:
            if http_info["server_variance"]:
                methods.append("HTTP Server header variance")
            if http_info["date_variance"]:
                methods.append("HTTP Date header variance")
            if http_info["served_by"]:
                methods.append("HTTP proxy/cache header")

        detected = dns_lb or http_lb

        # If HTTP-detected LB but DNS round-robin returned 0 or 1 IP, ensure we resolve the IP
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

        # Perform reverse DNS lookup using `dig -x` for all observed device IPs
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

        detail_parts = []
        if http_info["served_by"]:
            detail_parts.append(f"Via/X-Served-By: {', '.join(http_info['served_by'])}")
        if http_info["unique_servers"] and http_info["server_variance"]:
            detail_parts.append(f"Server headers: {', '.join(http_info['unique_servers'])}")
        if all_fqdns:
            detail_parts.append(f"Reverse DNS (FQDN): {', '.join(all_fqdns)}")

        return {
            "detected": detected,
            "method": ", ".join(methods) if methods else None,
            "ips": ips,
            "reverse_dns": reverse_dns,
            "fqdns": all_fqdns,
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
