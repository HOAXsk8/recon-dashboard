import asyncio
import datetime
import logging
import re
from typing import Any, Dict, List, Optional, Set
from base_agent import BaseAgent, logger

PRIVACY_KEYWORDS: Set[str] = {
    "privacy", "redacted", "gdpr", "whoisguard", "domainsbyproxy", "withheld",
    "proxy", "anonymise", "anonymized", "identity protect", "contact privacy",
    "private registration", "registration private", "domain privacy", "not disclosed"
}

PUBLIC_DNS_PROVIDERS: Set[str] = {
    "cloudflare.com", "awsdns", "googledomains.com", "domaincontrol.com",
    "registrar-servers.com", "azure-dns.com", "azure-dns.net", "azure-dns.org",
    "dnsimple.com", "ovh.net", "namecheaphosting.com", "nsone.net", "dnsv.jp",
    "dnspod.com", "he.net", "linode.com", "digitalocean.com", "dynect.net"
}


class WhoisAgent(BaseAgent):
    def __init__(self):
        super().__init__("whois_lookup", "WHOIS Lookup Tool")

    async def run_whois(self, domain: str) -> str:
        logger.info(f"Running WHOIS on {domain}")
        stdout, stderr = await self.run_command(["whois", domain])
        if stderr and "no match" not in stderr.lower():
            logger.warning(f"WHOIS stderr for {domain}: {stderr}")
        return stdout or ""

    def parse_whois(self, raw_data: str) -> Dict[str, Any]:
        """Comprehensive parsing of WHOIS data across standard and international registrars."""
        data: Dict[str, Any] = {
            "registrar": None,
            "registrant": None,
            "organization": None,
            "admin_email": None,
            "registrant_email": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "nameservers": [],
            "dnssec": None,
            "country": None,
            "status": []
        }

        patterns = {
            "registrar": [
                r"Registrar:\s*(.*)",
                r"Sponsoring Registrar:\s*(.*)",
                r"registrar-name:\s*(.*)",
                r"Registrar Name:\s*(.*)"
            ],
            "registrant": [
                r"Registrant Organization:\s*(.*)",
                r"OrgName:\s*(.*)",
                r"organisation:\s*(.*)",
                r"Registrant:\s*(.*)",
                r"owner:\s*(.*)",
                r"tech-organization:\s*(.*)"
            ],
            "admin_email": [
                r"Admin Email:\s*(.*)",
                r"Registrant Email:\s*(.*)",
                r"e-mail:\s*(.*)",
                r"Registrar Abuse Contact Email:\s*(.*)",
                r"Contact Email:\s*(.*)"
            ],
            "creation_date": [
                r"Creation Date:\s*(.*)",
                r"Registration Date:\s*(.*)",
                r"Created:\s*(.*)",
                r"Registered on:\s*(.*)",
                r"created:\s*(.*)"
            ],
            "expiration_date": [
                r"Registry Expiry Date:\s*(.*)",
                r"Expiration Date:\s*(.*)",
                r"Expiry Date:\s*(.*)",
                r"paid-till:\s*(.*)",
                r"free-date:\s*(.*)"
            ],
            "updated_date": [
                r"Updated Date:\s*(.*)",
                r"Last Updated:\s*(.*)",
                r"modified:\s*(.*)",
                r"changed:\s*(.*)"
            ],
            "dnssec": [
                r"DNSSEC:\s*(.*)",
                r"dnssec:\s*(.*)"
            ],
            "country": [
                r"Registrant Country:\s*(.*)",
                r"country:\s*(.*)"
            ]
        }

        for key, regex_list in patterns.items():
            for pat in regex_list:
                match = re.search(pat, raw_data, re.IGNORECASE)
                if match:
                    val = match.group(1).strip()
                    if val and val.lower() != "null" and val.lower() != "none":
                        data[key] = val
                        break

        # Normalize organization field
        if data.get("registrant"):
            data["organization"] = data["registrant"]

        # Parse nameservers
        ns_matches = re.findall(r"(?:Name Server|nserver):\s*([^\s]+)", raw_data, re.IGNORECASE)
        if ns_matches:
            clean_ns = []
            for ns in ns_matches:
                ns_clean = ns.strip().rstrip(".").lower()
                if ns_clean and ns_clean not in clean_ns and "." in ns_clean:
                    clean_ns.append(ns_clean)
            data["nameservers"] = clean_ns

        # Parse domain statuses
        status_matches = re.findall(r"(?:Domain Status|status):\s*([^\s]+)", raw_data, re.IGNORECASE)
        if status_matches:
            data["status"] = sorted(list(set(s.strip() for s in status_matches if s.strip())))

        return data

    @staticmethod
    def is_privacy_redacted(val: Optional[str]) -> bool:
        """Check if WHOIS field is masked by GDPR or WHOIS privacy proxy."""
        if not val:
            return True
        v_low = str(val).lower().strip()
        if len(v_low) < 3:
            return True
        return any(p in v_low for p in PRIVACY_KEYWORDS)

    @staticmethod
    def is_custom_nameserver(ns: str) -> bool:
        """Check if nameserver belongs to a custom/private infrastructure rather than public cloud DNS."""
        if not ns:
            return False
        ns_low = str(ns).lower().strip()
        return not any(pub in ns_low for pub in PUBLIC_DNS_PROVIDERS)

    async def correlate_registrant_domains(self, current_domain: str, parsed_whois: dict) -> dict:
        """
        Correlate registrant organization, administrative email, and custom nameservers
        against all other domains in the database to discover sister domains and acquisitions.
        """
        current_org = (parsed_whois.get("registrant") or parsed_whois.get("organization") or "").strip()
        current_email = (parsed_whois.get("admin_email") or parsed_whois.get("registrant_email") or "").strip().lower()
        current_ns = parsed_whois.get("nameservers") or []

        has_valid_org = not self.is_privacy_redacted(current_org)
        has_valid_email = not self.is_privacy_redacted(current_email) and "@" in current_email
        custom_ns = [ns for ns in current_ns if self.is_custom_nameserver(ns)]

        correlation_data = {
            "correlated_domains": [],
            "matches": [],
            "total_correlated": 0
        }

        # If all fields are redacted or empty, no cross-correlation possible
        if not (has_valid_org or has_valid_email or custom_ns):
            return correlation_data

        # Query all other tracked root domains in the database
        cursor = self.domains_col.find(
            {"domain": {"$ne": current_domain}},
            {"domain": 1, "ownership": 1}
        )

        matched_domains: Set[str] = set()
        matches_list: List[dict] = []

        async for other_doc in cursor:
            other_domain = other_doc.get("domain")
            if not other_domain:
                continue

            other_whois = other_doc.get("ownership") or {}
            other_org = (other_whois.get("registrant") or other_whois.get("organization") or "").strip()
            other_email = (other_whois.get("admin_email") or other_whois.get("registrant_email") or "").strip().lower()
            other_ns = other_whois.get("nameservers") or []

            reasons = []

            # 1. Matching Registrant Organization
            if has_valid_org and not self.is_privacy_redacted(other_org):
                if current_org.lower() == other_org.lower():
                    reasons.append(f"Matching Registrant Organization ('{current_org}')")

            # 2. Matching Administrative Contact Email
            if has_valid_email and not self.is_privacy_redacted(other_email):
                if current_email == other_email:
                    reasons.append(f"Matching Contact Email ('{current_email}')")

            # 3. Shared Custom / Branded Nameservers
            if custom_ns:
                shared_ns = [ns for ns in custom_ns if ns in [o.lower().rstrip(".") for o in other_ns]]
                if shared_ns:
                    reasons.append(f"Shared Custom Nameserver Infrastructure ({', '.join(shared_ns)})")

            if reasons:
                matched_domains.add(other_domain)
                matches_list.append({
                    "domain": other_domain,
                    "reasons": reasons
                })

        correlation_data["correlated_domains"] = sorted(list(matched_domains))
        correlation_data["matches"] = matches_list
        correlation_data["total_correlated"] = len(matched_domains)

        # Cross-link each matched sister domain back to current_domain in MongoDB
        for match in matches_list:
            sister = match["domain"]
            await self.domains_col.update_one(
                {"domain": sister},
                {
                    "$addToSet": {
                        "ownership.correlated_domains": current_domain,
                        "corporate_identity.sister_domains": current_domain
                    }
                }
            )

        return correlation_data

    async def process_domain_whois(self, domain: str, doc_id):
        """Execute WHOIS lookup, parse attributes, and correlate sister domains."""
        raw_whois = await self.run_whois(domain)
        if not raw_whois:
            return

        parsed = self.parse_whois(raw_whois)

        # Cross-Domain Registrant Correlation (Enhancement #3)
        correlation = await self.correlate_registrant_domains(domain, parsed)
        sister_domains = correlation.get("correlated_domains", [])

        ownership_payload = {
            **parsed,
            "correlated_domains": sister_domains,
            "correlation_matches": correlation.get("matches", [])
        }

        # Update root domain document
        await self.domains_col.update_one(
            {"_id": doc_id},
            {
                "$set": {
                    "ownership": ownership_payload,
                    "corporate_identity.sister_domains": sister_domains,
                    "whois_raw": raw_whois,
                    "whois_complete": True,
                    "whois_updated_at": datetime.datetime.utcnow().isoformat()
                }
            }
        )
        logger.info(f"Root WHOIS completed for {domain} ({len(sister_domains)} sister domains correlated)")

        # Create alert if new sister domains or corporate acquisitions were identified
        if sister_domains:
            await self.create_alert(
                title=f"Cross-Domain Entity Correlation: {len(sister_domains)} Sister Properties for {domain}",
                description=(
                    f"WHOIS organization and nameserver correlation identified {len(sister_domains)} related corporate properties "
                    f"sharing the same entity ownership or custom DNS infrastructure: {', '.join(sister_domains[:5])}."
                ),
                target=domain,
                risk_level="info",
                details={
                    "domain": domain,
                    "sister_domains": sister_domains,
                    "correlation_matches": correlation.get("matches", []),
                    "registrant_org": parsed.get("registrant"),
                    "nameservers": parsed.get("nameservers", [])
                },
                exploitation_suggestions=[
                    "Review discovered sister domains to expand the target attack surface.",
                    "Check if shared credentials, staging systems, or API keys exist across the sister properties.",
                    "Verify if newly acquired sister domains maintain weaker security postures or unpatched software."
                ],
                alert_type="whois_sister_domains"
            )

    async def process_tasks(self):
        # 1. Process tasks explicitly queued in tasks_col
        task = await self.get_next_task("whois_lookup")
        if not task:
            task = await self.get_next_task("whois")

        if task:
            root_domain = task.get("root_domain") or task.get("target")
            doc = await self.domains_col.find_one({
                "domain": root_domain,
                "blacklisted": {"$ne": True},
                "on_hold": {"$ne": True}
            })
            if doc:
                await self.process_domain_whois(root_domain, doc["_id"])
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
                )
            else:
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "failed", "error": "Domain not found or inactive"}}
                )
            return

        # 2. Process Pending Root Domains
        root_domains = await self.domains_col.find({
            "whois_complete": {"$ne": True},
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        }).to_list(length=5)

        for doc in root_domains:
            domain = doc["domain"]
            await self.process_domain_whois(domain, doc["_id"])
            await asyncio.sleep(2)

        # 3. Process Pending Subdomains
        doc_with_pending_subs = await self.domains_col.find_one({
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True},
            "infrastructure.subdomains": {
                "$elemMatch": {"whois_complete": {"$ne": True}}
            }
        })

        if doc_with_pending_subs:
            root_domain = doc_with_pending_subs["domain"]
            subs = doc_with_pending_subs.get("infrastructure", {}).get("subdomains", [])

            for i, sub in enumerate(subs):
                if not sub.get("whois_complete"):
                    sub_name = sub["name"]
                    raw_whois = await self.run_whois(sub_name)

                    update_fields = {
                        f"infrastructure.subdomains.{i}.whois_complete": True,
                        f"infrastructure.subdomains.{i}.whois_raw": raw_whois,
                        f"infrastructure.subdomains.{i}.whois_updated_at": datetime.datetime.utcnow().isoformat()
                    }

                    await self.domains_col.update_one(
                        {"_id": doc_with_pending_subs["_id"]},
                        {"$set": update_fields}
                    )
                    logger.info(f"Subdomain WHOIS completed for {sub_name}")

                    await asyncio.sleep(4)
                    if i >= 4:
                        break


if __name__ == "__main__":
    agent = WhoisAgent()
    asyncio.run(agent.main_loop())
