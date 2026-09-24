import asyncio
import datetime
import logging
import os
import re
import socket
import ssl
import struct
import xml.etree.ElementTree as ET
import sys
from typing import Dict, List, Optional, Any, Tuple
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger

# Known cloud infrastructure provider keywords in ASN or reverse DNS
CLOUD_ASN_ORGS = [
    "amazon", "aws", "google", "gcp", "microsoft", "azure",
    "digitalocean", "linode", "akamai", "fastly", "cloudflare",
    "hetzner", "ovh", "vultr", "oracle", "alibaba"
]

CLOUD_HOSTNAME_KEYWORDS = [
    "compute.amazonaws.com", "elb.amazonaws.com", "s3.amazonaws.com",
    "googleusercontent.com", "cloudapp.azure.com", "azurewebsites.net",
    "digitaloceanspaces.com", "linodeobjects.com", "hetzner.com", "ovh.net"
]

# Additional targeted DevOps / Microservice / Cloud ports
CLOUD_EXTRA_PORTS = [
    2375, 2376, 4243,          # Docker daemon (plaintext / TLS / alternative)
    6443, 8001,                # Kubernetes API server / local proxy
    5000, 5001,                # Docker Registry (v2 API)
    9090, 9091, 9093,          # Prometheus / Pushgateway / Alertmanager
    8500, 8300, 8301,          # HashiCorp Consul (HTTP / RPC / Serf LAN)
    2379, 2380,                # CoreOS etcd (client API / peer)
    9200, 9300,                # Elasticsearch (HTTP REST / Transport)
    27017,                     # MongoDB database
    6379,                      # Redis in-memory store
    11211,                     # Memcached
    4040,                      # Apache Spark Web UI
    8888,                      # Jupyter Notebook / web server
    15672, 5672,               # RabbitMQ (Management HTTP API / AMQP)
]

CLOUD_PORT_NAMES = {
    2375: "docker-api",
    2376: "docker-api-tls",
    4243: "docker-api-alt",
    6443: "k8s-api",
    8001: "k8s-api-proxy",
    5000: "docker-registry",
    5001: "docker-registry-alt",
    9090: "prometheus-metrics",
    9091: "prometheus-pushgateway",
    9093: "alertmanager",
    8500: "consul-http",
    8300: "consul-rpc",
    8301: "consul-serf-lan",
    2379: "etcd-client",
    2380: "etcd-peer",
    9200: "elasticsearch-http",
    9300: "elasticsearch-transport",
    27017: "mongodb",
    6379: "redis",
    11211: "memcached",
    4040: "spark-ui",
    8888: "jupyter-notebook",
    15672: "rabbitmq-mgmt",
    5672: "amqp",
}

# Protocol-aware banner probes
BANNER_PROBES = {
    21:    b"",                                                               # FTP: read greeting
    22:    b"",                                                               # SSH: read greeting
    23:    b"",                                                               # Telnet: read greeting
    25:    b"",                                                               # SMTP: read greeting
    587:   b"",                                                               # SMTP submission
    80:    b"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    443:   b"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    554:   b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",                          # RTSP
    2375:  b"GET /version HTTP/1.0\r\nHost: {host}\r\n\r\n",                 # Docker Engine API
    2376:  b"GET /version HTTP/1.0\r\nHost: {host}\r\n\r\n",                 # Docker Engine TLS
    6443:  b"GET /version HTTP/1.0\r\nHost: {host}\r\n\r\n",                 # Kubernetes API
    6379:  b"INFO server\r\n",                                                # Redis
    11211: b"stats\r\n",                                                      # Memcached
    9200:  b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",                        # Elasticsearch
    8500:  b"GET /v1/status/leader HTTP/1.0\r\nHost: {host}\r\n\r\n",        # Consul
    9090:  b"GET /metrics HTTP/1.0\r\nHost: {host}\r\n\r\n",                 # Prometheus
    2379:  b"GET /version HTTP/1.0\r\nHost: {host}\r\n\r\n",                 # etcd
    5000:  b"GET /v2/ HTTP/1.0\r\nHost: {host}\r\n\r\n",                     # Docker Registry
    15672: b"GET /api/overview HTTP/1.0\r\nHost: {host}\r\n\r\n",            # RabbitMQ Management
    5672:  b"AMQP\x00\x00\x09\x01",                                           # AMQP Handshake
    3306:  b"",                                                               # MySQL: read greeting
    5432:  b"",                                                               # PostgreSQL
    5900:  b"",                                                               # VNC: read RFB greeting
}

# Services that should NEVER be publicly exposed without authentication
UNAUTHENTICATED_SERVICES = {
    6379:  "Redis",
    11211: "Memcached",
    9200:  "Elasticsearch",
    27017: "MongoDB",
    2375:  "Docker Daemon API",
    6443:  "Kubernetes API",
    8500:  "HashiCorp Consul",
    9090:  "Prometheus Metrics",
    2379:  "etcd Key-Value Store",
}

INTERNAL_DOMAIN_PATTERNS = [
    r"\.internal\b", r"\.local\b", r"\.corp\b", r"\.lan\b", r"\.priv\b",
    r"\.intranet\b", r"\.infra\b", r"\.dev\.corp\b",
    r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
    r"^192\.168\.\d{1,3}\.\d{1,3}$",
    r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$"
]


class PortScannerAgent(BaseAgent):
    def __init__(self):
        super().__init__("port_scanner", "Port Scanner Tool")

    def _is_cloud_host(self, asn_org: str, hostname: str = "", ip: str = "") -> bool:
        """Return True if the ASN organisation or hostname indicates a known cloud provider."""
        combined = f"{asn_org} {hostname} {ip}".lower()
        if any(kw in combined for kw in CLOUD_ASN_ORGS):
            return True
        if any(kw in combined for kw in CLOUD_HOSTNAME_KEYWORDS):
            return True
        return False

    async def run_nmap(self, target: str):
        """Run standard optimized Nmap scan across top 1000 TCP ports with service versioning."""
        logger.info(f"Running optimized Nmap on {target}")
        cmd = [
            "nmap", "-sS", "--top-ports", "1000", "-sV",
            "--max-retries", "1",
            "--max-rtt-timeout", "500ms",
            "-T4", target, "-oX", "-"
        ]

        stdout, stderr = await self.run_command(cmd, timeout=600)
        if stderr:
            logger.warning(f"Nmap stderr: {stderr}")
        return stdout

    async def scan_cloud_ports(self, host: str, extra_ports: List[int]) -> List[Dict[str, Any]]:
        """
        Quickly test extra cloud/DevOps ports using lightweight parallel async TCP handshakes.
        For any responsive ports, return service metadata so they can be merged with Nmap.
        """
        async def check_port(port: int):
            try:
                conn = asyncio.open_connection(host, port)
                _, writer = await asyncio.wait_for(conn, timeout=2.0)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except Exception:
                return None

        tasks = [check_port(p) for p in extra_ports]
        results = await asyncio.gather(*tasks)
        live_ports = [p for p in results if p is not None]

        services = []
        for port in live_ports:
            service_name = CLOUD_PORT_NAMES.get(port, "unknown")
            is_tls = port in (2376, 6443)
            services.append({
                "port": port,
                "protocol": "tcp",
                "service": service_name,
                "software": "",
                "version": "",
                "is_tls": is_tls,
                "is_cloud_extra": True
            })
        return services

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
                            tunnel = service.get('tunnel', '') if service is not None else ''
                            is_tls = (tunnel == 'ssl') or (service_name in ('https', 'ssl', 'tls')) or (int(p_id) in (443, 8443, 9443, 10443, 4443, 8444))

                            services.append({
                                "port": int(p_id),
                                "protocol": proto,
                                "service": service_name,
                                "software": soft,
                                "version": version,
                                "is_tls": is_tls
                            })
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
        return ip, services

    # ------------------------------------------------------------------
    # 1. TLS Certificate Harvesting per Port
    # ------------------------------------------------------------------
    async def grab_tls_certificate(self, host: str, port: int, root_domain: str = "") -> Optional[Dict[str, Any]]:
        """
        Connect via TLS and parse the X.509 peer certificate using the cryptography library.
        Extracts:
        - Subject CN, issuer organisation and CN
        - Subject Alternative Names (SANs)
        - Validity period (notBefore, notAfter, days_until_expiry)
        - Expiry status (expired, expiring_soon)
        - Self-signed certificate detection (Issuer == Subject)
        - Detection of internal domains/IPs leaked in SANs
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID, NameOID
            import datetime as dt

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()

            def _get_cert_der():
                with socket.create_connection((host, port), timeout=4) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        return ssock.getpeercert(binary_form=True)

            der_bytes = await asyncio.wait_for(
                loop.run_in_executor(None, _get_cert_der), timeout=6.0
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
            self_signed = (cert.issuer == cert.subject)

            # Detect leaked internal domains or private IPs in SANs
            leaked_internal = []
            for san in sans:
                for pat in INTERNAL_DOMAIN_PATTERNS:
                    if re.search(pat, san, re.IGNORECASE):
                        leaked_internal.append(san)
                        break

            try:
                sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
            except Exception:
                sig_alg = "unknown"

            cert_data = {
                "subject_cn": subject_cn,
                "issuer_org": issuer_org,
                "issuer_cn": issuer_cn,
                "sans": sans,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_until_expiry": days_until_expiry,
                "expiring_soon": expiring_soon,
                "expired": expired,
                "self_signed": self_signed,
                "leaked_internal_sans": leaked_internal,
                "serial_number": str(cert.serial_number),
                "signature_algorithm": sig_alg,
                "port": port,
            }

            # Security Alerts
            if expired:
                await self.create_alert(
                    title=f"TLS Certificate Expired: {host}:{port}",
                    description=(
                        f"The TLS certificate on {host}:{port} expired {abs(days_until_expiry)} days ago "
                        f"({not_after.strftime('%Y-%m-%d')}). Subject CN: {subject_cn or 'N/A'}, Issuer: {issuer_org or issuer_cn or 'N/A'}."
                    ),
                    target=host,
                    risk_level="high",
                    details=cert_data,
                    exploitation_suggestions=[
                        "Replace the expired certificate immediately to restore trusted encryption.",
                        "Audit automated renewal pipelines (e.g. Certbot, AWS ACM) on the host."
                    ],
                    alert_type="tls_cert_expired"
                )
            elif expiring_soon:
                await self.create_alert(
                    title=f"TLS Certificate Expiring Soon: {host}:{port}",
                    description=(
                        f"The TLS certificate on {host}:{port} expires in {days_until_expiry} days "
                        f"({not_after.strftime('%Y-%m-%d')}). Subject CN: {subject_cn or 'N/A'}, Issuer: {issuer_org or issuer_cn or 'N/A'}."
                    ),
                    target=host,
                    risk_level="medium",
                    details=cert_data,
                    exploitation_suggestions=[
                        f"Renew certificate for {subject_cn or host} before {not_after.strftime('%Y-%m-%d')}.",
                        "Verify automated renewal job timers and renewal hooks."
                    ],
                    alert_type="tls_cert_expiry"
                )

            if leaked_internal:
                await self.create_alert(
                    title=f"Internal Domain / IP Leaked in TLS Certificate SAN: {host}:{port}",
                    description=(
                        f"The TLS certificate on {host}:{port} exposes internal infrastructure identifiers in its "
                        f"Subject Alternative Names (SANs): {', '.join(leaked_internal[:6])}. "
                        f"This leaks internal network topology, server roles, and naming conventions to public observers."
                    ),
                    target=host,
                    risk_level="medium",
                    details={
                        "port": port,
                        "leaked_internal": leaked_internal,
                        "all_sans": sans,
                        "subject_cn": subject_cn,
                        "issuer": issuer_org or issuer_cn
                    },
                    exploitation_suggestions=[
                        "Separate public-facing certificates from internal hostnames during certificate issuance.",
                        "Issue private CA certificates for internal endpoints instead of listing them on public certs.",
                        "Query internal DNS records for discovered names to identify intranet routing points."
                    ],
                    alert_type="tls_internal_domain_leak"
                )

            if self_signed and not expired:
                await self.create_alert(
                    title=f"Self-Signed TLS Certificate: {host}:{port}",
                    description=(
                        f"The TLS certificate on {host}:{port} is self-signed (Issuer == Subject: {subject_cn}). "
                        f"Clients cannot verify the CA chain, which may indicate an unmanaged development or test deployment."
                    ),
                    target=host,
                    risk_level="low",
                    details=cert_data,
                    exploitation_suggestions=[
                        "Deploy a certificate from a trusted public CA (e.g. Let's Encrypt) for production services.",
                        "Verify whether this host is an unauthorized development server."
                    ],
                    alert_type="tls_cert_self_signed"
                )

            return cert_data

        except asyncio.TimeoutError:
            logger.debug(f"[TLS Cert] Timeout connecting to {host}:{port}")
        except Exception as e:
            logger.debug(f"[TLS Cert] Could not grab certificate from {host}:{port}: {e}")
        return None

    # ------------------------------------------------------------------
    # 2. Raw Service Banner Grabbing on Non-HTTP / HTTP Ports
    # ------------------------------------------------------------------
    async def grab_service_banner(self, host: str, port: int, service_name: str = "", is_tls: bool = False) -> Optional[str]:
        """
        Send a protocol-aware probe to an open port and read the response banner.
        Supports both raw TCP and TLS-wrapped connections.
        Returns the parsed banner string (up to 300 chars), or None.
        """
        probe = BANNER_PROBES.get(port, b"")
        if isinstance(probe, bytes) and b"{host}" in probe:
            probe = probe.replace(b"{host}", host.encode())

        try:
            # Determine if TLS connection is needed
            ssl_context = None
            if is_tls or port in (443, 8443, 9443, 10443, 6443, 2376) or service_name in ('https', 'ssl', 'tls'):
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_context), timeout=4.0
            )

            if probe:
                writer.write(probe)
                await writer.drain()

            data = await asyncio.wait_for(reader.read(512), timeout=3.5)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if not data:
                return None

            # Special protocol handling for binary headers
            # 1. MySQL greeting packet
            if port == 3306 and len(data) > 5 and data[4] == 10:
                try:
                    server_ver = data[5:].split(b'\x00')[0].decode('latin1')
                    return f"MySQL Protocol 10 ({server_ver})"
                except Exception:
                    pass

            # 2. VNC RFB greeting
            if data.startswith(b"RFB "):
                return data.decode("ascii", errors="replace").strip()

            banner = data.decode("utf-8", errors="replace").strip()
            # Clean up Redis INFO output to a concise string
            if port == 6379 and "redis_version:" in banner:
                lines = [line.strip() for line in banner.splitlines() if line.startswith(("redis_version:", "os:", "process_id:"))]
                return "Redis " + ", ".join(lines)

            # Clean up Memcached stats
            if port == 11211 and "STAT version" in banner:
                for line in banner.splitlines():
                    if "STAT version" in line:
                        return f"Memcached ({line.strip()})"

            return banner[:300] if banner else None

        except Exception as e:
            logger.debug(f"[Banner] Could not grab banner from {host}:{port}: {e}")
        return None

    async def create_port_alert(self, root_domain, target, old_ports, new_ports):
        """Create an alert for opened/closed ports and record timeline history."""
        # Suppress port change alerts and history drift during the domain's initial scan cycle
        domain_doc = await self.domains_col.find_one({"domain": root_domain})
        if domain_doc and self.is_first_scan_cycle(domain_doc):
            logger.info(f"[FIRST-SCAN SUPPRESSED] Suppressed port change detection during initial domain scan for target '{target}' (domain: '{root_domain}')")
            return False

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
        risk = "high" if any(p.split('/')[0] in ['22', '3389', '21', '23', '445', '2375', '6443', '27017', '6379'] for p in added) else "medium"

        details = f"A change in open ports was detected for {target}.\n\nPrevious ports: {', '.join(old_set) or 'None'}\nNew ports: {', '.join(new_set) or 'None'}"
        exploitation = (
            "### Port Delta Analysis\n\n"
            "1. **Identify Service**: Inspect banners and TLS certificates on newly opened ports.\n"
            "2. **Verify Ingress Rules**: Confirm whether newly exposed ports are intentionally public.\n"
            "3. **Decommission Tracking**: If services were closed, determine if this is deliberate or an outage."
        )

        now_iso = datetime.datetime.utcnow().isoformat()
        history_events = []
        if added:
            history_events.append({
                "timestamp": now_iso,
                "event_type": "port_opened",
                "target": target,
                "details": f"Ports opened: {', '.join(added)}",
                "severity": "high" if risk == "high" else "medium"
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

        return await self.create_alert(title, description, target, risk, details, exploitation, alert_type="port_scanner_changes", root_domain=root_domain)

    async def update_scan_results_in_db(self, root_domain, target, ip, services):
        domain_doc = await self.domains_col.find_one({"domain": root_domain})
        old_systems = domain_doc.get("systems", []) if domain_doc else []

        latest_prev_scan = None
        for s_entry in reversed(old_systems):
            if s_entry.get("target") == target:
                latest_prev_scan = s_entry
                break

        changed_ports = set()
        if latest_prev_scan:
            old_services = latest_prev_scan.get("services", [])
            if services or old_services:
                await self.create_port_alert(root_domain, target, old_services, services)

            old_map = {p['port']: p for p in old_services}
            for s in services:
                if s['port'] not in old_map or old_map[s['port']] != s:
                    changed_ports.add(s['port'])
        else:
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
            # 1. Fetch ASN and infrastructure context for cloud-aware port hunting
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            sub_asn_org = ""
            sub_ptr = ""
            sub_ip = ""
            if domain_doc:
                subs = (domain_doc.get("infrastructure") or {}).get("subdomains", [])
                for s in subs:
                    if isinstance(s, dict) and s.get("name") == target:
                        sub_asn_org = s.get("as_org", "")
                        sub_ptr = s.get("ptr", "")
                        sub_ip = s.get("ip", "")
                        break
                if not sub_asn_org:
                    sub_asn_org = (domain_doc.get("asn_data") or {}).get("org", "")

            # Determine whether target is hosted on cloud infrastructure
            is_cloud = self._is_cloud_host(sub_asn_org, hostname=f"{target} {sub_ptr}", ip=sub_ip)

            # 2. Run standard top 1000 Nmap scan
            xml_data = await self.run_nmap(target)
            ip, services = self.parse_nmap_xml(xml_data)

            # 3. Dynamic Cloud Port Hunting: If cloud target, probe extended DevOps/microservice ports
            if is_cloud:
                existing_ports = {s['port'] for s in services}
                cloud_ports_to_check = [p for p in CLOUD_EXTRA_PORTS if p not in existing_ports]
                logger.info(f"[Cloud Port Hunt] Probing {len(cloud_ports_to_check)} targeted DevOps ports for cloud host {target}")
                discovered_cloud_services = await self.scan_cloud_ports(target, cloud_ports_to_check)

                if discovered_cloud_services:
                    for cs in discovered_cloud_services:
                        services.append(cs)
                        logger.warning(f"[Cloud Port Hunt] Discovered exposed cloud port {target}:{cs['port']} ({cs['service']})")

                        # Alert on exposed cloud management services
                        await self.create_alert(
                            title=f"Exposed Cloud DevOps Service: {target}:{cs['port']} ({cs['service']})",
                            description=(
                                f"The cloud infrastructure service '{cs['service']}' on {target}:{cs['port']} "
                                f"was found open on cloud-hosted infrastructure ({sub_asn_org or 'Cloud Provider'}). "
                                f"This service is typically intended for internal cluster communication."
                            ),
                            target=target,
                            risk_level="high",
                            details={
                                "port": cs['port'],
                                "service": cs['service'],
                                "target": target,
                                "asn_org": sub_asn_org
                            },
                            exploitation_suggestions=[
                                f"Restrict access to port {cs['port']} ({cs['service']}) using cloud Security Groups.",
                                "Verify that mutual TLS or strong identity authentication is strictly required.",
                                "Ensure internal microservices are isolated inside private VPC subnets."
                            ],
                            alert_type="cloud_devops_port_exposed"
                        )

            # 4. Save scan in systems collection
            changed_ports = await self.update_scan_results_in_db(root_domain, target, ip, services or [])

            # 5. Update infrastructure.subdomains
            open_port_numbers = [s['port'] for s in services]
            if target != root_domain:
                await self.domains_col.update_one(
                    {"domain": root_domain, "infrastructure.subdomains.name": target},
                    {"$set": {
                        "infrastructure.subdomains.$.scanned": True,
                        "infrastructure.subdomains.$.ip": ip,
                        "infrastructure.subdomains.$.open_ports": open_port_numbers,
                        "infrastructure.subdomains.$.last_scanned": datetime.datetime.utcnow().isoformat()
                    }}
                )

            if services:
                # 6. SSL/TLS Certificate Harvesting per TLS-enabled port
                tls_ports = [
                    s['port'] for s in services
                    if s.get('is_tls') or s['service'] in ('https', 'ssl', 'tls') or s['port'] in (443, 8443, 9443, 10443, 4443, 8444, 2376, 6443)
                ]

                cert_tasks = [self.grab_tls_certificate(target, p, root_domain) for p in tls_ports]
                cert_results = await asyncio.gather(*cert_tasks, return_exceptions=True)

                cert_map: Dict[int, Dict] = {}
                in_scope_sans = []
                for port, cert in zip(tls_ports, cert_results):
                    if isinstance(cert, dict):
                        cert_map[port] = cert
                        logger.info(f"[TLS Cert] {target}:{port} CN={cert.get('subject_cn')} SANs={len(cert.get('sans', []))} expires_in={cert.get('days_until_expiry')}d")

                        # Collect in-scope SANs for subdomain discovery
                        for san in cert.get("sans", []):
                            san_clean = san.lstrip("*.").lower().strip()
                            if self.is_in_scope(san_clean, root_domain) and san_clean != target:
                                in_scope_sans.append(san_clean)

                # Feed SAN-discovered hostnames back into the verification queue
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
                        logger.info(f"[TLS Cert SAN] Queued verification for {san_host} (discovered in cert SAN on {target})")

                # 7. Raw Service Banner Grabbing on all responsive ports
                banner_targets = [
                    s for s in services
                    if s['port'] in BANNER_PROBES or s['port'] in UNAUTHENTICATED_SERVICES or s['service'] in ('ftp', 'ssh', 'smtp', 'redis', 'http', 'https', 'mysql')
                ]

                banner_tasks = [
                    self.grab_service_banner(target, s['port'], s.get('service', ''), is_tls=bool(s.get('is_tls')))
                    for s in banner_targets
                ]
                banner_results = await asyncio.gather(*banner_tasks, return_exceptions=True)

                banner_map: Dict[int, str] = {}
                for svc, banner in zip(banner_targets, banner_results):
                    if isinstance(banner, str) and banner:
                        banner_map[svc['port']] = banner
                        logger.info(f"[Banner] {target}:{svc['port']} -> {banner[:80]!r}")

                        # Alert on unauthenticated sensitive internal services
                        if svc['port'] in UNAUTHENTICATED_SERVICES:
                            service_label = UNAUTHENTICATED_SERVICES[svc['port']]
                            await self.create_alert(
                                title=f"Unauthenticated {service_label} Exposed: {target}:{svc['port']}",
                                description=(
                                    f"The service {service_label} on {target}:{svc['port']} responded with valid data "
                                    f"without requiring authentication. This allows unauthorized data access or administration."
                                ),
                                target=target,
                                risk_level="critical",
                                details={
                                    "port": svc['port'],
                                    "service": service_label,
                                    "banner": banner[:250],
                                    "target": target
                                },
                                exploitation_suggestions=[
                                    f"Verify authentication controls on {service_label} ({target}:{svc['port']}).",
                                    f"Block external access to port {svc['port']} via network security group or firewall.",
                                    f"Review accessed data or command history on {service_label}."
                                ],
                                alert_type="unauthenticated_service_exposed"
                            )

                # Enrich service records with TLS certificate details and banners
                for svc in services:
                    if svc['port'] in cert_map:
                        svc['tls_cert'] = cert_map[svc['port']]
                    if svc['port'] in banner_map:
                        svc['banner'] = banner_map[svc['port']]

                # Update enriched services back into systems entry
                await self.domains_col.update_one(
                    {"domain": root_domain, "systems.target": target},
                    {"$set": {"systems.$.services": services}}
                )

                # 8. Trigger downstream tasks for web services
                for svc in services:
                    is_web = (
                        svc['port'] in [80, 443, 8080, 8443, 3000, 5000, 8000, 8888] or
                        svc['service'] in ['http', 'https'] or
                        svc.get('is_tls')
                    )
                    if is_web:
                        proto = 'https' if (svc.get('is_tls') or svc['port'] in [443, 8443] or svc['service'] == 'https') else 'http'

                        # Queue directory hunt
                        exists_dh = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": target,
                            "port": svc['port'],
                            "task_type": "directory_hunt"
                        })
                        if not exists_dh or svc['port'] in changed_ports:
                            if exists_dh:
                                await self.tasks_col.delete_one({"_id": exists_dh["_id"]})
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "protocol": proto,
                                "port": svc['port'],
                                "task_type": "directory_hunt",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Queued directory hunt for {target}:{svc['port']}")

                        # Queue tech fingerprinting
                        exists_tf = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": target,
                            "port": svc['port'],
                            "task_type": "tech_fingerprint"
                        })
                        if not exists_tf:
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

                # Trigger WAF & Load Balancer detection once per target
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

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            logger.info(f"Completed port scan for {target}")
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
