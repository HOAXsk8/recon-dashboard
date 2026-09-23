import asyncio
import datetime
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger
from dns_analytics import TakeoverDetector, AsnNetworkResolver

class AliveCheckAgent(BaseAgent):
    def __init__(self):
        super().__init__("alive_check", "Subdomain Alive Checking Tool")
        self.takeover_detector = TakeoverDetector()
        self.asn_resolver = AsnNetworkResolver()

    async def get_ip(self, target):
        """Resolve target to IP address with fallback to async DNS resolvers."""
        if not target:
            return None
        target = target.strip().rstrip(".")

        # 1. System resolver
        try:
            import socket
            loop = asyncio.get_event_loop()
            res = await asyncio.wait_for(loop.getaddrinfo(target, None), timeout=3.0)
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

    async def is_wildcard(self, domain):
        """Check if a domain has wildcard DNS."""
        if not domain:
            return None
        random_sub = f"check-{datetime.datetime.utcnow().timestamp()}.{domain}"
        ip = await self.get_ip(random_sub)
        return ip

    async def _check_single_port(self, target, port, timeout=3.0):
        try:
            conn = asyncio.open_connection(target, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def is_alive(self, target):
        """
        Verify if a target is alive by checking 16 common ports in parallel.
        Short-circuits immediately as soon as any single port completes a connection.
        """
        ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 8081, 22, 21, 25, 53, 3389, 8088]
        tasks = [asyncio.create_task(self._check_single_port(target, p, timeout=3.0)) for p in ports]

        try:
            for coro in asyncio.as_completed(tasks):
                res = await coro
                if res:
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    return True
        except Exception as e:
            logger.debug(f"is_alive check exception for {target}: {e}")
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
        return False

    async def process_tasks(self):
        task = await self.get_next_task("verification")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]

        try:
            # 1. Check for wildcard on the parent domain
            parent_domain = ".".join(target.split(".")[1:]) if "." in target else ""
            wildcard_ip = await self.is_wildcard(parent_domain) if parent_domain else None
            target_ip = await self.get_ip(target)

            is_potential_fp = False
            if wildcard_ip and target_ip == wildcard_ip:
                is_potential_fp = True
                logger.info(f"Target {target} matches wildcard IP {wildcard_ip}. Requiring open port.")

            # 2. Parallel alive check across common ports
            alive = await self.is_alive(target)

            # If it's a potential FP and no ports are open, mark as not alive
            if is_potential_fp and not alive:
                logger.info(f"Target {target} is a Wildcard FP (No ports open).")
                alive = False

            # 3. Autonomous Subdomain Takeover & Dangling DNS check
            takeover_res = None
            try:
                takeover_res = await self.takeover_detector.audit_subdomain_takeover(target)
                if takeover_res:
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

            # 4. Resolve ASN, Org, and Reverse PTR for discovered IP
            asn_info = {}
            if target_ip:
                try:
                    asn_info = await self.asn_resolver.resolve_ip(target_ip)
                except Exception as ae:
                    logger.debug(f"Error resolving ASN for {target_ip}: {ae}")

            # 5. Asset Validation:
            # - Dangling takeover detected: Valid asset
            # - Responded on an open port: Valid asset (alive=True)
            # - Resolves to a valid IP and is NOT a wildcard catch-all: Valid asset in DNS (eliminates false negatives)
            is_valid_asset = bool(takeover_res) or alive or (bool(target_ip) and not is_potential_fp)

            # 6. Build Subdomain Metadata & Track Infrastructure Drift History
            domain_doc = await self.domains_col.find_one(
                {"domain": root_domain, "infrastructure.subdomains.name": target},
                {"infrastructure.subdomains.$": 1}
            )
            existing_sub = None
            if domain_doc and domain_doc.get("infrastructure", {}).get("subdomains"):
                existing_sub = domain_doc["infrastructure"]["subdomains"][0]

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
            if asn_info.get("asn"):
                sub_update_fields["infrastructure.subdomains.$.asn"] = asn_info.get("asn")
                sub_update_fields["infrastructure.subdomains.$.as_org"] = asn_info.get("org")
                sub_update_fields["infrastructure.subdomains.$.cidr"] = asn_info.get("cidr")
            if asn_info.get("ptr"):
                sub_update_fields["infrastructure.subdomains.$.ptr"] = asn_info.get("ptr")

            if takeover_res:
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
                    if asn_info.get("asn"):
                        new_sub_doc["asn"] = asn_info.get("asn")
                        new_sub_doc["as_org"] = asn_info.get("org")
                        new_sub_doc["cidr"] = asn_info.get("cidr")
                    if asn_info.get("ptr"):
                        new_sub_doc["ptr"] = asn_info.get("ptr")
                    if takeover_res:
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

                # Add discovery task for recursion (depth < 2) only if responsive
                depth = target.count(".") - root_domain.count(".")
                if depth < 2 and alive:
                    exists_disc = await self.tasks_col.find_one({
                        "root_domain": root_domain,
                        "target": target,
                        "task_type": "discovery"
                    })
                    if not exists_disc:
                        await self.tasks_col.insert_one({
                            "root_domain": root_domain,
                            "target": target,
                            "task_type": "discovery",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        })

                # Queue Nmap port scan task (top 1000 ports) for all verified IP assets
                if target_ip or alive:
                    exists_scan = await self.tasks_col.find_one({
                        "root_domain": root_domain,
                        "target": target,
                        "task_type": "scan"
                    })
                    if not exists_scan:
                        await self.tasks_col.insert_one({
                            "root_domain": root_domain,
                            "target": target,
                            "task_type": "scan",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        })
                        logger.info(f"Queued Nmap port scan task for verified asset: {target}")

                # Record full enriched status in infrastructure.subdomains
                if target != root_domain:
                    await self.domains_col.update_one(
                        {"domain": root_domain, "infrastructure.subdomains.name": target},
                        {"$set": sub_update_fields}
                    )

                logger.info(f"Target {target} processed (alive={alive}, valid_asset=True, takeover={bool(takeover_res)}, asn={asn_info.get('asn')}).")
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

if __name__ == "__main__":
    agent = AliveCheckAgent()
    asyncio.run(agent.main_loop())
