import asyncio
import datetime
import logging
import ssl
import socket
import struct
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from base_agent import BaseAgent, logger

# Cloud provider ASN ranges — used to activate extended DevOps port scanning
CLOUD_ASN_ORGS = [
    "amazon", "aws", "google", "gcp", "microsoft", "azure",
    "digitalocean", "linode", "akamai", "fastly", "cloudflare",
    "hetzner", "ovh", "vultr"
]

# Additional ports to scan when target is in cloud/DevOps infrastructure
CLOUD_EXTRA_PORTS = [
    2375, 2376, 4243,    # Docker daemon (unencrypted / TLS / alt)
    6443,                # Kubernetes API server
    5000, 5001,          # Docker Registry
    9090, 9091, 9093,    # Prometheus / Alertmanager
    8500,                # Consul HTTP API
    8300, 8301,          # Consul RPC / LAN serf
    4001, 2379, 2380,    # etcd client / peer
    9200, 9300,          # Elasticsearch HTTP / transport
    27017,               # MongoDB
    6379,                # Redis
    11211,               # Memcached
    4040,                # Spark UI
    8888,                # Jupyter Notebook
]

# Protocol-aware banner probes
BANNER_PROBES = {
    21:    b"",                           # FTP: just read banner
    22:    b"",                           # SSH: just read banner
    25:    b"",                           # SMTP: just read banner
    80:    b"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    443:   b"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    6379:  b"INFO server\r\n",            # Redis
    11211: b"stats\r\n",                  # Memcached
    9200:  b"GET / HTTP/1.0\r\n\r\n",    # Elasticsearch
    9090:  b"GET /metrics HTTP/1.0\r\n\r\n",  # Prometheus
    3306:  b"",                           # MySQL: just read greeting
    5432:  b"",                           # PostgreSQL: just read banner
}

# Services that should NOT be responding without authentication
UNAUTHENTICATED_SERVICES = {
    6379: "Redis",
    11211: "Memcached",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


class PortScannerAgent(BaseAgent):
    def __init__(self):
        super().__init__("port_scanner", "Port Scanner Tool")

    def _is_cloud_host(self, asn_org: str) -> bool:
        """Return True if the ASN organisation string matches a known cloud provider."""
        if not asn_org:
            return False
        asn_org_lower = asn_org.lower()
        return any(kw in asn_org_lower for kw in CLOUD_ASN_ORGS)

    async def run_nmap(self, target: str, extra_ports: Optional[List[int]] = None):
        logger.info(f"Running optimized Nmap on {target}")
        # Optimized for speed: TCP only, top 1000 ports, service versioning
        cmd = [
            "nmap", "-sS", "--top-ports", "1000", "-sV",
            "--max-retries", "1",
            "--max-rtt-timeout", "500ms",
            "-T4", target, "-oX", "-"
        ]

        # Append cloud-specific DevOps ports if target is in cloud infrastructure
        if extra_ports:
            port_str = ",".join(str(p) for p in extra_ports)
            cmd = [
                "nmap", "-sS", "--top-ports", "1000", f"-p1-1024,{port_str}", "-sV",
                "--max-retries", "1",
                "--max-rtt-timeout", "500ms",
                "-T4", target, "-oX", "-"
            ]
            logger.info(f"[Nmap] Cloud target detected — appending {len(extra_ports)} additional DevOps ports for {target}")

        # Set a 10-minute timeout for the scan
        stdout, stderr = await self.run_command(cmd, timeout=600)
        if stderr:
            logger.warning(f"Nmap stderr: {stderr}")
        return stdout

    def parse_nmap_xml(self, xml_data):
        services = []
        ip = "N/A"
        try:
            root = ET.fromstring(xml_data)
            for host in root.findall('host'):
                addr = host.find('address')
                if addr is not None:
                    ip = addr.get('addr')
                
                for port in host.findall('.//port'):
                    p_id = port.get('portid')
                    proto = port.get('protocol')
                    state_el = port.find('state')
                    if state_el is not None:
                        state = state_el.get('state')
                        if state == 'open':
                            service = port.find('service')
                            service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                            soft = service.get('product', '') if service is not None else ''
                            version = service.get('version', '') if service is not None else ''
                            services.append({
                                "port": int(p_id),
                                "protocol": proto,
                                "service": service_name,
                                "software": soft,
                                "version": version
                            })
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
        return ip, services

    # ------------------------------------------------------------------
    # NEW: TLS Certificate Harvesting
    # ------------------------------------------------------------------
    async def grab_tls_certificate(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Connect via TLS and parse the X.509 peer certificate to extract:
        - Subject CN, issuer, SANs (Subject Alternative Names)
        - Validity period (notBefore, notAfter)
        - Serial number and signature algorithm
        - Expiry status (flags certs expiring within 30 days)

        Returns a dict with cert metadata, or None on failure.
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.x509.oid import ExtensionOID, NameOID
            import datetime as dt

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()

            def _get_cert_der():
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        return ssock.getpeercert(binary_form=True)

            der_bytes = await asyncio.wait_for(
                loop.run_in_executor(None, _get_cert_der), timeout=8.0
            )
            if not der_bytes:
                return None

            cert = x509.load_der_x509_certificate(der_bytes)

            # Subject CN
            try:
                subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                subject_cn = ""

            # Issuer
            try:
                issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            except Exception:
                issuer_org = ""
            try:
                issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                issuer_cn = ""

            # SANs (Subject Alternative Names)
            sans = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = [name.value for name in san_ext.value]
            except Exception:
                pass

            not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
            not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
            now = dt.datetime.now(dt.timezone.utc)
            days_until_expiry = (not_after - now).days
            expiring_soon = 0 <= days_until_expiry <= 30
            expired = days_until_expiry < 0

            try:
                sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
            except Exception:
                sig_alg = "unknown"

            return {
                "subject_cn": subject_cn,
                "issuer_org": issuer_org,
                "issuer_cn": issuer_cn,
                "sans": sans,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_until_expiry": days_until_expiry,
                "expiring_soon": expiring_soon,
                "expired": expired,
                "serial_number": str(cert.serial_number),
                "signature_algorithm": sig_alg,
                "port": port,
            }
        except asyncio.TimeoutError:
            logger.debug(f"[TLS Cert] Timeout connecting to {host}:{port}")
        except Exception as e:
            logger.debug(f"[TLS Cert] Could not grab certificate from {host}:{port}: {e}")
        return None

    # ------------------------------------------------------------------
    # NEW: Raw Service Banner Grabbing
    # ------------------------------------------------------------------
    async def grab_service_banner(self, host: str, port: int, service_name: str = "") -> Optional[str]:
        """
        Send a protocol-aware probe to an open port and read the response banner.
        Returns the first 512 bytes of the response as a decoded string, or None.
        """
        probe = BANNER_PROBES.get(port, b"")
        if isinstance(probe, bytes) and b"{host}" in probe:
            probe = probe.replace(b"{host}", host.encode())

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=4.0
            )
            if probe:
                writer.write(probe)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=3.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            banner = data.decode("utf-8", errors="replace").strip()
            return banner[:300] if banner else None
        except Exception as e:
            logger.debug(f"[Banner] Could not grab banner from {host}:{port}: {e}")
        return None

    async def create_port_alert(self, root_domain, target, old_ports, new_ports):
        """Create a lead/alert for changed ports using the centralized alerting system."""
        old_set = {f"{p['port']}/{p['protocol']}" for p in old_ports}
        new_set = {f"{p['port']}/{p['protocol']}" for p in new_ports}
        
        added = new_set - old_set
        removed = old_set - new_set
        
        if not added and not removed:
            return

        title = f"Port Change Detected: {target}"
        changes = []
        if added:
            changes.append(f"OPENED: {', '.join(added)}")
        if removed:
            changes.append(f"CLOSED: {', '.join(removed)}")
        
        description = " | ".join(changes)
        risk = "high" if any(p.split('/')[0] in ['22', '3389', '21', '23', '445'] for p in added) else "medium"
        
        details = f"A change in the open ports was detected for {target}.\n\nPrevious ports: {', '.join(old_set) or 'None'}\nNew ports: {', '.join(new_set) or 'None'}"
        exploitation = f"### Port Analysis\n\n1. **Verify Services**: For new ports, identify the service running.\n2. **Firewall Check**: Ensure that newly opened ports are intended to be public.\n3. **Decommissioning**: If ports were closed, verify if it was a planned decommission or a service failure."

        now_iso = datetime.datetime.utcnow().isoformat()
        history_events = []
        if added:
            history_events.append({
                "timestamp": now_iso,
                "event_type": "port_opened",
                "target": target,
                "details": f"Ports opened: {', '.join(added)}",
                "severity": "high" if any(p.split('/')[0] in ['22', '3389', '21', '23', '445'] for p in added) else "medium"
            })
        if removed:
            history_events.append({
                "timestamp": now_iso,
                "event_type": "port_closed",
                "target": target,
                "details": f"Ports closed: {', '.join(removed)}",
                "severity": "low"
            })
        if history_events:
            try:
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$push": {"history": {"$each": history_events, "$slice": -300}}}
                )
            except Exception as he:
                logger.warning(f"Failed to record port change history: {he}")

        return await self.create_alert(title, description, target, risk, details, exploitation, alert_type="port_scanner_changes")

    async def update_scan_results_in_db(self, root_domain, target, ip, services):
        # Fetch previous results for comparison
        domain_doc = await self.domains_col.find_one({"domain": root_domain})
        old_systems = domain_doc.get("systems", [])
        
        # Find latest scan for this specific target
        latest_prev_scan = None
        for sys in reversed(old_systems):
            if sys.get("target") == target:
                latest_prev_scan = sys
                break
        
        changed_ports = set()
        if latest_prev_scan:
            old_services = latest_prev_scan.get("services", [])
            if services or old_services:
                await self.create_port_alert(root_domain, target, old_services, services)
            
            # Identify which ports are new or have changed service info
            old_map = {p['port']: p for p in old_services}
            for s in services:
                if s['port'] not in old_map or old_map[s['port']] != s:
                    changed_ports.add(s['port'])
        else:
            # All ports are "new" if no previous scan exists
            changed_ports = {s['port'] for s in services}

        system_entry = {
            "ip": ip,
            "target": target,
            "services": services,
            "last_scanned": datetime.datetime.utcnow().isoformat()
        }
        await self.domains_col.update_one(
            {"domain": root_domain},
            {"$push": {"systems": system_entry}}
        )
        return changed_ports

    async def process_tasks(self):
        task = await self.get_next_task("scan")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]

        try:
            # Fetch ASN info for cloud-aware port extension
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            sub_asn_org = ""
            if domain_doc:
                subs = (domain_doc.get("infrastructure") or {}).get("subdomains", [])
                for s in subs:
                    if isinstance(s, dict) and s.get("name") == target:
                        sub_asn_org = s.get("as_org", "")
                        break
                # Also check root domain ASN
                if not sub_asn_org:
                    sub_asn_org = (domain_doc.get("asn_data") or {}).get("org", "")

            # Determine if cloud-extended port scan is warranted
            extra_ports = CLOUD_EXTRA_PORTS if self._is_cloud_host(sub_asn_org) else None

            xml_data = await self.run_nmap(target, extra_ports=extra_ports)
            ip, services = self.parse_nmap_xml(xml_data)
            
            # Always record the scan in systems so the host is marked as scanned (even if 0 open ports)
            changed_ports = await self.update_scan_results_in_db(root_domain, target, ip, services or [])

            # Mark subdomain as scanned in infrastructure.subdomains
            if target != root_domain:
                await self.domains_col.update_one(
                    {"domain": root_domain, "infrastructure.subdomains.name": target},
                    {"$set": {
                        "infrastructure.subdomains.$.scanned": True,
                        "infrastructure.subdomains.$.ip": ip,
                        "infrastructure.subdomains.$.last_scanned": datetime.datetime.utcnow().isoformat()
                    }}
                )
            
            if services:
                # ---------------------------------------------------------
                # NEW: TLS Certificate Harvesting + Banner Grabbing
                # ---------------------------------------------------------
                tls_ports = [
                    s['port'] for s in services
                    if s['service'] in ('https', 'ssl', 'tls') or s['port'] in (443, 8443, 9443, 10443, 4443, 8444)
                ]
                banner_targets = [s for s in services if s['port'] in BANNER_PROBES or s['service'] in ('ftp', 'ssh', 'smtp', 'redis', 'http', 'https')]

                # Grab TLS certs in parallel
                cert_tasks = [self.grab_tls_certificate(target, p) for p in tls_ports]
                cert_results = await asyncio.gather(*cert_tasks, return_exceptions=True)

                cert_map: Dict[int, Dict] = {}
                in_scope_sans = []
                for port, cert in zip(tls_ports, cert_results):
                    if isinstance(cert, dict):
                        cert_map[port] = cert
                        logger.info(f"[TLS Cert] {target}:{port} CN={cert.get('subject_cn')} SANs={len(cert.get('sans', []))} expires_in={cert.get('days_until_expiry')}d")

                        # Alert on expiring certs
                        if cert.get("expiring_soon") and not cert.get("expired"):
                            await self.create_alert(
                                title=f"TLS Certificate Expiring Soon: {target}:{port}",
                                description=(
                                    f"The TLS certificate on {target}:{port} expires in "
                                    f"{cert['days_until_expiry']} days "
                                    f"({cert['not_after'][:10]}). CN: {cert.get('subject_cn', 'N/A')} "
                                    f"Issuer: {cert.get('issuer_org', 'N/A')}"
                                ),
                                target=target,
                                risk_level="medium",
                                details=cert,
                                exploitation_suggestions=[
                                    f"Renew the certificate for {cert.get('subject_cn', target)} before {cert['not_after'][:10]}.",
                                    "Ensure automated certificate renewal (Let's Encrypt / ACM) is configured correctly."
                                ],
                                alert_type="tls_cert_expiry"
                            )
                        elif cert.get("expired"):
                            await self.create_alert(
                                title=f"TLS Certificate Expired: {target}:{port}",
                                description=(
                                    f"The TLS certificate on {target}:{port} expired {abs(cert['days_until_expiry'])} days ago "
                                    f"({cert['not_after'][:10]}). CN: {cert.get('subject_cn', 'N/A')}"
                                ),
                                target=target,
                                risk_level="high",
                                details=cert,
                                exploitation_suggestions=[
                                    "Replace the expired certificate immediately to restore secure communication.",
                                    "Audit certificate management processes to prevent future expirations."
                                ],
                                alert_type="tls_cert_expired"
                            )

                        # Collect in-scope SANs for subdomain discovery feedback
                        for san in cert.get("sans", []):
                            san_clean = san.lstrip("*.").lower()
                            if self.is_in_scope(san_clean, root_domain) and san_clean != target:
                                in_scope_sans.append(san_clean)

                # Feed SAN-discovered hostnames into the verification queue
                for san_host in set(in_scope_sans):
                    exists = await self.tasks_col.find_one({
                        "root_domain": root_domain,
                        "target": san_host,
                        "task_type": "verification"
                    })
                    if not exists:
                        await self.tasks_col.insert_one({
                            "root_domain": root_domain,
                            "target": san_host,
                            "task_type": "verification",
                            "status": "pending",
                            "source": "tls_cert_san",
                            "created_at": datetime.datetime.utcnow()
                        })
                        logger.info(f"[TLS Cert SAN] Queued verification for {san_host} (discovered in cert SAN for {target}:{tls_ports})")

                # Grab service banners in parallel
                banner_tasks = [self.grab_service_banner(target, s['port'], s['service']) for s in banner_targets]
                banner_results = await asyncio.gather(*banner_tasks, return_exceptions=True)

                banner_map: Dict[int, str] = {}
                for svc, banner in zip(banner_targets, banner_results):
                    if isinstance(banner, str) and banner:
                        banner_map[svc['port']] = banner
                        logger.info(f"[Banner] {target}:{svc['port']} -> {banner[:80]!r}")

                        # Alert on unauthenticated internal services
                        if svc['port'] in UNAUTHENTICATED_SERVICES:
                            service_label = UNAUTHENTICATED_SERVICES[svc['port']]
                            await self.create_alert(
                                title=f"Unauthenticated {service_label} Exposed: {target}:{svc['port']}",
                                description=(
                                    f"{service_label} on {target}:{svc['port']} responded to an unauthenticated "
                                    f"query without credentials. This service may be accessible without authentication, "
                                    f"exposing internal data or allowing unauthorised write access."
                                ),
                                target=target,
                                risk_level="critical",
                                details={
                                    "port": svc['port'],
                                    "service": service_label,
                                    "banner": banner[:200],
                                },
                                exploitation_suggestions=[
                                    f"Verify whether {service_label} on {target}:{svc['port']} requires authentication.",
                                    f"If not authenticated, restrict access via firewall rules to trusted IP ranges immediately.",
                                    f"Enable {service_label} authentication and review exposed data."
                                ],
                                alert_type="unauthenticated_service_exposed"
                            )

                # Enrich service entries with TLS cert data and banners
                for svc in services:
                    if svc['port'] in cert_map:
                        svc['tls_cert'] = cert_map[svc['port']]
                    if svc['port'] in banner_map:
                        svc['banner'] = banner_map[svc['port']]

                # Update enriched services back into the systems entry
                await self.domains_col.update_one(
                    {"domain": root_domain, "systems.target": target},
                    {"$set": {"systems.$.services": services}}
                )

                # Trigger directory hunt for web services
                for svc in services:
                    if svc['port'] in [80, 443, 8080, 8443, 3000, 5000, 8000] or svc['service'] in ['http', 'https']:
                        proto = 'https' if svc['port'] in [443, 8443] or svc['service'] == 'https' else 'http'
                        
                        exists = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": target,
                            "port": svc['port'],
                            "task_type": "directory_hunt"
                        })
                        
                        # Re-run if it doesn't exist OR if the port changed
                        if not exists or svc['port'] in changed_ports:
                            if exists:
                                await self.tasks_col.delete_one({"_id": exists["_id"]})
                                
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "protocol": proto,
                                "port": svc['port'],
                                "task_type": "directory_hunt",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Queued directory hunt for {target}:{svc['port']} (Change detected: {svc['port'] in changed_ports})")

                        # Also trigger tech fingerprinting
                        exists_tech = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": target,
                            "port": svc['port'],
                            "task_type": "tech_fingerprint"
                        })
                        if not exists_tech:
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "protocol": proto,
                                "port": svc['port'],
                                "task_type": "tech_fingerprint",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Queued tech fingerprint for {target}:{svc['port']}")

                # Trigger WAF and Load Balancer detection once per target for web subdomains
                if target != root_domain:
                    exists_waf = await self.tasks_col.find_one({
                        "root_domain": root_domain,
                        "target": target,
                        "task_type": "waf_detect"
                    })
                    if not exists_waf:
                        await self.tasks_col.insert_one({
                            "root_domain": root_domain,
                            "target": target,
                            "task_type": "waf_detect",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        })
                        logger.info(f"Queued WAF detection for subdomain {target}")

                    exists_lb = await self.tasks_col.find_one({
                        "root_domain": root_domain,
                        "target": target,
                        "task_type": "lb_detect"
                    })
                    if not exists_lb:
                        await self.tasks_col.insert_one({
                            "root_domain": root_domain,
                            "target": target,
                            "task_type": "lb_detect",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        })
                        logger.info(f"Queued Load Balancer detection for subdomain {target}")
            
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            logger.info(f"Completed port scan for {target}")

            # Check if this was the last task for the root domain
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in port scan for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = PortScannerAgent()
    asyncio.run(agent.main_loop())
