import asyncio
import base64
import datetime
import logging
import re
import sys
import os
from typing import Any, Dict, List, Optional, Set, Tuple
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dns.resolver
import httpx
from base_agent import BaseAgent, logger
from dns_analytics import DnsRecordHarvester, AsnNetworkResolver, DnssecAuditor

try:
    from cryptography.hazmat.primitives.serialization import load_der_public_key
except ImportError:
    load_der_public_key = None


class OsintAgent(BaseAgent):
    COMMON_DKIM_SELECTORS = [
        "default", "google", "k1", "k2", "k3", "s1", "s2", "mail", "email",
        "selector1", "selector2", "dkim", "smtp", "zoho", "office365", "sendgrid",
        "mandrill", "mailgun", "protonmail", "mesmtp", "sig1", "2023", "2024", "2025", "2026"
    ]

    def __init__(self):
        super().__init__("osint_collector", "OSINT Intelligence Agent")
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

    # ---------------------------------------------------------
    # DKIM Selector Hunting & Cryptographic Key Strength Auditing
    # ---------------------------------------------------------
    @staticmethod
    def calculate_dkim_key_bits(p_b64: str) -> Tuple[int, str, bool]:
        """Decode base64 DER public key and return (key_bits, strength_label, is_weak)."""
        clean_b64 = re.sub(r'\s+', '', p_b64)
        try:
            der = base64.b64decode(clean_b64)
        except Exception:
            return 0, "Invalid Base64 Key", False

        key_bits = 0
        if load_der_public_key:
            try:
                key = load_der_public_key(der)
                key_bits = getattr(key, "key_size", 0)
            except Exception:
                pass

        if not key_bits:
            # Fallback estimation from DER byte length
            der_len = len(der)
            if der_len < 130:
                key_bits = 512
            elif der_len < 220:
                key_bits = 1024
            elif der_len < 350:
                key_bits = 2048
            else:
                key_bits = 4096

        if key_bits <= 512:
            return key_bits, "CRITICAL (512-bit RSA - Factorable in hours)", True
        elif key_bits == 1024:
            return key_bits, "WEAK (1024-bit RSA - Deprecated by NIST, vulnerable to cloud factorization)", True
        elif key_bits >= 2048:
            return key_bits, f"SECURE ({key_bits}-bit RSA)", False
        return key_bits, f"{key_bits}-bit RSA", False

    async def audit_dkim_selectors(self, domain: str) -> Dict[str, Any]:
        """Audit common DKIM selectors for existence and cryptographic key strength."""
        dkim_summary = {
            "selectors_tested": len(self.COMMON_DKIM_SELECTORS),
            "selectors_found": [],
            "weak_keys": [],
            "records": [],
            "status": "No Selectors Found"
        }

        async def check_selector(sel: str):
            target = f"{sel}._domainkey.{domain}"
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, target, "TXT")
                for r in answers:
                    txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                    if "v=dkim1" in txt.lower() or "p=" in txt:
                        p_match = re.search(r'\bp=([a-zA-Z0-9+/=]+)', txt)
                        p_val = p_match.group(1) if p_match else ""
                        key_bits, strength, is_weak = self.calculate_dkim_key_bits(p_val) if p_val else (0, "No Public Key Found", False)
                        rec_data = {
                            "selector": sel,
                            "fqdn": target,
                            "key_bits": key_bits,
                            "strength": strength,
                            "is_weak": is_weak,
                            "raw_record": txt
                        }
                        return rec_data
            except Exception:
                pass
            return None

        tasks = [check_selector(s) for s in self.COMMON_DKIM_SELECTORS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r.get("selector"):
                dkim_summary["selectors_found"].append(r["selector"])
                dkim_summary["records"].append(r)
                if r.get("is_weak"):
                    dkim_summary["weak_keys"].append(r)

        if dkim_summary["weak_keys"]:
            dkim_summary["status"] = "Weak Cryptographic Keys Detected"
        elif dkim_summary["selectors_found"]:
            dkim_summary["status"] = "Secure (2048-bit+)"

        return dkim_summary

    # ---------------------------------------------------------
    # BIMI & MTA-STS Policy Verification (Enhancement #2)
    # ---------------------------------------------------------
    async def audit_bimi(self, domain: str) -> Dict[str, Any]:
        """Audit BIMI (Brand Indicators for Message Identification) record at default._bimi.<domain>."""
        bimi_summary = {
            "record": None,
            "status": "Not Configured",
            "logo_url": None,
            "vmc_url": None,
            "has_vmc": False
        }
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, f"default._bimi.{domain}", "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=bimi1" in txt.lower():
                    bimi_summary["record"] = txt
                    l_match = re.search(r'\bl=([^\s;]+)', txt)
                    a_match = re.search(r'\ba=([^\s;]+)', txt)
                    bimi_summary["logo_url"] = l_match.group(1) if l_match else None
                    bimi_summary["vmc_url"] = a_match.group(1) if a_match else None
                    bimi_summary["has_vmc"] = bool(bimi_summary["vmc_url"])

                    if bimi_summary["has_vmc"]:
                        bimi_summary["status"] = "Enforced (VMC Certificate Verified)"
                    elif bimi_summary["logo_url"]:
                        bimi_summary["status"] = "Self-Asserted (No VMC Certificate)"
                    else:
                        bimi_summary["status"] = "Configured"
                    break
        except Exception:
            pass
        return bimi_summary

    async def audit_mta_sts(self, domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
        """Audit MTA-STS TXT record and policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt."""
        sts_summary = {
            "dns_record": None,
            "status": "Not Configured",
            "policy_mode": None,
            "mx_hosts": [],
            "max_age": None,
            "policy_url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        }
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, f"_mta-sts.{domain}", "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=stsv1" in txt.lower():
                    sts_summary["dns_record"] = txt
                    sts_summary["status"] = "DNS Record Published"
                    break
        except Exception:
            pass

        if sts_summary["dns_record"]:
            try:
                resp = await client.get(sts_summary["policy_url"], timeout=4.0)
                if resp.status_code == 200:
                    body = resp.text
                    mode_m = re.search(r'mode:\s*([a-zA-Z]+)', body)
                    mx_list = re.findall(r'mx:\s*([^\s]+)', body)
                    age_m = re.search(r'max_age:\s*(\d+)', body)

                    mode_val = mode_m.group(1).lower() if mode_m else "unknown"
                    sts_summary["policy_mode"] = mode_val
                    sts_summary["mx_hosts"] = mx_list
                    sts_summary["max_age"] = int(age_m.group(1)) if age_m else None

                    if mode_val == "enforce":
                        sts_summary["status"] = "Strict TLS Enforced (mode=enforce)"
                    elif mode_val == "testing":
                        sts_summary["status"] = "Testing Mode (mode=testing)"
                    elif mode_val == "none":
                        sts_summary["status"] = "Disabled (mode=none)"
                    else:
                        sts_summary["status"] = f"Policy Published ({mode_val})"
                else:
                    sts_summary["status"] = f"Policy File Missing (HTTP {resp.status_code})"
            except Exception:
                sts_summary["status"] = "Policy Host Unreachable"

        return sts_summary

    async def audit_tls_rpt(self, domain: str) -> Dict[str, Any]:
        """Audit SMTP TLS Reporting TXT record at _smtp._tls.<domain>."""
        tls_summary = {
            "record": None,
            "status": "Not Configured",
            "rua": None
        }
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, f"_smtp._tls.{domain}", "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=tlsrptv1" in txt.lower():
                    tls_summary["record"] = txt
                    rua_m = re.search(r'rua=mailto:([^\s;]+)', txt)
                    tls_summary["rua"] = rua_m.group(1) if rua_m else None
                    tls_summary["status"] = "Configured"
                    break
        except Exception:
            pass
        return tls_summary

    # ---------------------------------------------------------
    # 1. Mail Security, Vendor Fingerprinting & Spoofing Risk
    # ---------------------------------------------------------
    async def analyze_mail_and_dns(self, domain, domain_doc):
        logger.info(f"[{domain}] Running Mail Security & DNS OSINT...")
        result = {
            "mx_records": [],
            "mail_provider": "Unknown",
            "security_vendors": [],
            "verified_services": [],
            "spf_record": None,
            "spf_status": "Missing",
            "dmarc_record": None,
            "dmarc_policy": "None / Missing",
            "dmarc_rua": None,
            "dkim": {},
            "bimi": {},
            "mta_sts": {},
            "tls_rpt": {},
            "spoofable": True,
            "spoofing_risk": "Critical",
            "summary": ""
        }

        detected_vendors = set()
        detected_services = set()

        # 1. Resolve MX
        try:
            answers = dns.resolver.resolve(domain, "MX")
            mx_hosts = [str(r.exchange).rstrip(".").lower() for r in answers]
            result["mx_records"] = mx_hosts
            for h in mx_hosts:
                if "google" in h or "aspmx" in h:
                    result["mail_provider"] = "Google Workspace"
                    detected_vendors.add("Google Workspace")
                elif "outlook" in h or "protection.outlook.com" in h:
                    result["mail_provider"] = "Microsoft 365"
                    detected_vendors.add("Microsoft 365")
                elif "mimecast" in h:
                    result["mail_provider"] = "Mimecast Secure Gateway"
                    detected_vendors.add("Mimecast")
                elif "pphosted" in h or "proofpoint" in h:
                    result["mail_provider"] = "Proofpoint Email Protection"
                    detected_vendors.add("Proofpoint")
                elif "atmail" in h:
                    result["mail_provider"] = "Atmail Cloud"
                    detected_vendors.add("Atmail Cloud")
                elif "zoho" in h:
                    result["mail_provider"] = "Zoho Mail"
                    detected_vendors.add("Zoho Mail")
            if result["mail_provider"] == "Unknown" and mx_hosts:
                result["mail_provider"] = mx_hosts[0]
        except Exception as e:
            logger.debug(f"[{domain}] No MX records found: {e}")

        # 2. Resolve TXT (SPF & Cloud Verification Tokens)
        spf_includes = []
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")

                # Check SPF
                if txt.startswith("v=spf1"):
                    result["spf_record"] = txt
                    if "+all" in txt:
                        result["spf_status"] = "Insecure (+all Permissive)"
                    elif "-all" in txt:
                        result["spf_status"] = "Strict (-all Hardfail)"
                    elif "~all" in txt:
                        result["spf_status"] = "Softfail (~all)"
                    elif "?all" in txt:
                        result["spf_status"] = "Neutral (?all)"
                    else:
                        result["spf_status"] = "Configured"

                    for inc in re.findall(r"include:([^\s]+)", txt):
                        spf_includes.append(inc)

                # Check Enterprise SaaS & Domain Verification Tokens
                if "google-site-verification" in txt:
                    detected_services.add("Google Cloud / Workspace")
                if "globalsign" in txt:
                    detected_services.add("GlobalSign SSL")
                if "atlassian" in txt:
                    detected_services.add("Atlassian Cloud (Jira/Confluence)")
                if "apple-domain-verification" in txt:
                    detected_services.add("Apple Business Manager")
                if "facebook-domain-verification" in txt:
                    detected_services.add("Meta / Facebook Business")
                if "ms=" in txt or "microsoft" in txt:
                    detected_services.add("Microsoft 365 / Azure")
                if "docusign" in txt:
                    detected_services.add("DocuSign Enterprise")
                if "stripe" in txt:
                    detected_services.add("Stripe Payments")
                if "amazonses" in txt:
                    detected_vendors.add("Amazon SES")
                if "sendgrid" in txt:
                    detected_vendors.add("SendGrid")
                if "mailgun" in txt:
                    detected_vendors.add("Mailgun")
        except Exception as e:
            logger.debug(f"[{domain}] No TXT records found: {e}")

        # 3. Resolve SPF Include Chains
        for inc in spf_includes[:4]:
            if "fireeye" in inc or "trellix" in inc:
                detected_vendors.add("Trellix / FireEye Email Security")
            if "atmail" in inc:
                detected_vendors.add("Atmail Cloud")
            if "proofpoint" in inc:
                detected_vendors.add("Proofpoint")
            if "mimecast" in inc:
                detected_vendors.add("Mimecast")
            if "google" in inc:
                detected_vendors.add("Google Workspace")
            if "outlook" in inc or "microsoft" in inc:
                detected_vendors.add("Microsoft 365")

        # 4. Resolve DMARC (TXT at _dmarc.<domain>)
        dmarc_target = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_target, "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=DMARC1" in txt:
                    result["dmarc_record"] = txt
                    policy_match = re.search(r"\bp=([a-zA-Z]+)", txt)
                    if policy_match:
                        result["dmarc_policy"] = policy_match.group(1).lower()

                    rua_match = re.search(r"rua=mailto:([^\s;]+)", txt)
                    if rua_match:
                        result["dmarc_rua"] = rua_match.group(1)
                        rua = rua_match.group(1).lower()
                        if "dmarcadvisor" in rua:
                            detected_vendors.add("DMARC Advisor")
                        elif "valimail" in rua:
                            detected_vendors.add("Valimail")
                        elif "ondmarc" in rua:
                            detected_vendors.add("OnDMARC")
                        elif "agari" in rua:
                            detected_vendors.add("Agari DMARC")
                    break
        except Exception as e:
            logger.debug(f"[{domain}] No DMARC record found: {e}")

        # 5. DKIM Selector Hunting & Key Strength Auditing (Enhancement #1)
        logger.info(f"[{domain}] Hunting DKIM selectors and auditing cryptographic key strength...")
        dkim_audit = await self.audit_dkim_selectors(domain)
        result["dkim"] = dkim_audit
        if dkim_audit.get("selectors_found"):
            logger.info(f"[{domain}] Found DKIM selectors: {dkim_audit['selectors_found']}")

        # Raise alert if weak DKIM keys (512 or 1024-bit RSA) detected
        for weak_key in dkim_audit.get("weak_keys", []):
            bits = weak_key.get("key_bits", 1024)
            severity = "critical" if bits <= 512 else "high"
            await self.create_alert(
                title=f"Weak DKIM Key Strength ({bits}-bit RSA): {weak_key['selector']}._domainkey.{domain}",
                description=(
                    f"The DKIM public key under selector '{weak_key['selector']}._domainkey.{domain}' uses a weak "
                    f"{bits}-bit RSA key. {bits}-bit keys can be mathematically factored using modern computational resources, "
                    f"allowing attackers to forge cryptographic DKIM signatures and bypass email spoofing filters."
                ),
                target=domain,
                risk_level=severity,
                details={
                    "selector": weak_key["selector"],
                    "fqdn": weak_key["fqdn"],
                    "key_bits": bits,
                    "strength": weak_key["strength"],
                    "raw_record": weak_key["raw_record"]
                },
                exploitation_suggestions=[
                    f"Upgrade the DKIM key for selector '{weak_key['selector']}' to at least 2048-bit RSA.",
                    "Revoke and remove the deprecated 1024-bit or 512-bit public key record from DNS.",
                    "Ensure DMARC alignment matches the newly generated 2048-bit key."
                ],
                alert_type="weak_dkim_key"
            )

        # 6. BIMI, MTA-STS & TLS-RPT Transport Security (Enhancement #2)
        logger.info(f"[{domain}] Auditing BIMI, MTA-STS, and SMTP TLS Reporting policies...")
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=False, headers=self.headers) as http_client:
            bimi_res, mta_res, tls_res = await asyncio.gather(
                self.audit_bimi(domain),
                self.audit_mta_sts(domain, http_client),
                self.audit_tls_rpt(domain),
                return_exceptions=True
            )
            result["bimi"] = bimi_res if isinstance(bimi_res, dict) else {"status": "Error"}
            result["mta_sts"] = mta_res if isinstance(mta_res, dict) else {"status": "Error"}
            result["tls_rpt"] = tls_res if isinstance(tls_res, dict) else {"status": "Error"}

        # 7. Evaluate Spoofability & Risk
        dmarc_pol = result["dmarc_policy"]
        if dmarc_pol == "reject":
            result["spoofable"] = False
            result["spoofing_risk"] = "Low"
            result["summary"] = "Domain is protected against direct email spoofing with a strict DMARC reject policy."
        elif dmarc_pol == "quarantine":
            result["spoofable"] = False
            result["spoofing_risk"] = "Medium"
            result["summary"] = "Domain enforces DMARC quarantine; unauthorized emails will likely be routed to spam folders."
        elif dmarc_pol == "none":
            result["spoofable"] = True
            result["spoofing_risk"] = "High"
            result["summary"] = "Vulnerable to direct email spoofing! DMARC policy is set to 'none' (monitoring only). Inbound mail servers will deliver forged emails claiming to be from this domain."
        else:
            result["spoofable"] = True
            result["spoofing_risk"] = "Critical"
            result["summary"] = "No DMARC record published! Attackers can forge emails from this domain without SPF/DMARC rejection."

        result["security_vendors"] = sorted(list(detected_vendors))
        result["verified_services"] = sorted(list(detected_services))

        # Alert if vulnerable to email spoofing
        if result["spoofable"]:
            await self.create_alert(
                title=f"Email Spoofing Risk: DMARC Policy is {dmarc_pol.upper()}",
                description=f"The domain {domain} has a weak or absent DMARC policy ({dmarc_pol}), leaving it susceptible to business email compromise (BEC), phishing, and domain impersonation.",
                target=domain,
                risk_level=result["spoofing_risk"].lower(),
                details={
                    "dmarc_record": result["dmarc_record"],
                    "spf_record": result["spf_record"],
                    "mx_records": result["mx_records"],
                    "mail_provider": result["mail_provider"],
                    "security_vendors": result["security_vendors"],
                    "dkim_selectors": dkim_audit.get("selectors_found", []),
                    "bimi_status": result["bimi"].get("status"),
                    "mta_sts_status": result["mta_sts"].get("status")
                },
                exploitation_suggestions=[
                    f"Send a test email spoofing admin@{domain} to verify inbox delivery.",
                    "Implement a DMARC policy of p=reject with valid rua/ruf reporting addresses.",
                    "Ensure SPF hardfail (-all) is configured and aligned with DKIM selectors."
                ],
                alert_type="osint_email_spoofing"
            )

        return result

    # ---------------------------------------------------------
    # 2. Corporate Identity, Discovered Emails & Pattern
    # ---------------------------------------------------------
    async def extract_corporate_identity(self, domain, domain_doc):
        logger.info(f"[{domain}] Extracting corporate emails, organization, and social presence...")
        social_links = {}
        emails_found = set()

        # 1. Pull from WHOIS if already available
        ownership = domain_doc.get("ownership", {})
        org_name = ownership.get("registrant") or ownership.get("organization")
        admin_email = ownership.get("admin_email")

        if admin_email and "@" in admin_email and "anonymised" not in admin_email.lower() and "privacy" not in admin_email.lower():
            emails_found.add(admin_email.lower().strip())

        # 2. Web Surface Crawl
        urls_to_check = [
            f"https://{domain}",
            f"https://www.{domain}",
            f"http://{domain}",
            f"https://{domain}/about",
            f"https://{domain}/contact",
            f"https://{domain}/support"
        ]

        patterns = {
            "twitter": re.compile(r'https?://(?:www\.)?(?:twitter\.com|x\.com)/([a-zA-Z0-9_]{1,30})', re.I),
            "linkedin": re.compile(r'https?://(?:www\.)?linkedin\.com/(?:company|in)/([a-zA-Z0-9_\-\.]+)', re.I),
            "github": re.compile(r'https?://(?:www\.)?github\.com/([a-zA-Z0-9_\-\.]+)', re.I),
            "facebook": re.compile(r'https?://(?:www\.)?facebook\.com/([a-zA-Z0-9_\-\.]+)', re.I),
            "instagram": re.compile(r'https?://(?:www\.)?instagram\.com/([a-zA-Z0-9_\-\.]+)', re.I),
            "youtube": re.compile(r'https?://(?:www\.)?youtube\.com/(?:c/|channel/|user/|@)?([a-zA-Z0-9_\-\.]+)', re.I),
            "discord": re.compile(r'https?://(?:discord\.gg|discord\.com/invite)/([a-zA-Z0-9_\-]+)', re.I),
            "reddit": re.compile(r'https?://(?:www\.)?reddit\.com/(?:r|user)/([a-zA-Z0-9_]+)', re.I)
        }

        ignored_handles = {"home", "share", "intent", "login", "signup", "search", "policies", "terms", "privacy", "about", "sharer", "sharer.php"}

        escaped_domain = re.escape(domain)
        email_regex = re.compile(rf'[a-zA-Z0-9_.+-]+@{escaped_domain}', re.I)
        mailto_regex = re.compile(r'mailto:([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', re.I)

        async def fetch_page(client, url):
            try:
                resp = await client.get(url, timeout=3.5)
                if resp.status_code in (200, 301, 302):
                    return resp.text
            except Exception:
                pass
            return ""

        async with httpx.AsyncClient(timeout=3.5, follow_redirects=True, verify=False, headers=self.headers) as client:
            pages = await asyncio.gather(*[fetch_page(client, u) for u in urls_to_check], return_exceptions=True)
            for html in pages:
                if not isinstance(html, str) or not html:
                    continue

                # Social profiles
                for platform, pattern in patterns.items():
                    if platform in social_links:
                        continue
                    matches = pattern.findall(html)
                    for handle in matches:
                        if handle.lower() not in ignored_handles and len(handle) > 1:
                            if platform == "twitter":
                                social_links["twitter"] = f"https://x.com/{handle}"
                            elif platform == "linkedin":
                                social_links["linkedin"] = f"https://linkedin.com/company/{handle}"
                            elif platform == "github":
                                social_links["github"] = f"https://github.com/{handle}"
                            elif platform == "youtube":
                                social_links["youtube"] = f"https://youtube.com/@{handle}"
                            elif platform == "discord":
                                social_links["discord"] = f"https://discord.gg/{handle}"
                            else:
                                social_links[platform] = f"https://{platform}.com/{handle}"
                            break

                # Scrape emails
                for m in email_regex.findall(html):
                    clean = m.lower().strip(".")
                    if not any(clean.endswith(ext) for ext in [".png", ".jpg", ".svg", ".css", ".js", ".woff", ".woff2"]):
                        emails_found.add(clean)

                for m in mailto_regex.findall(html):
                    clean = m.lower().strip(".")
                    if domain in clean:
                        emails_found.add(clean)

        # 3. Format Discovered Emails & Deduce Pattern
        formatted_emails = []
        has_first_dot_last = False
        has_first_initial_last = False

        for email in sorted(emails_found):
            user_part = email.split("@")[0]
            if "." in user_part and len(user_part.split(".")) == 2:
                has_first_dot_last = True
            elif len(user_part) > 3 and user_part[0].isalpha() and user_part[1:].isalpha():
                has_first_initial_last = True

            role = "Corporate Contact"
            if any(k in user_part for k in ["support", "help"]):
                role = "Customer Support"
            elif any(k in user_part for k in ["sales", "billing"]):
                role = "Sales & Billing"
            elif any(k in user_part for k in ["admin", "root", "webmaster"]):
                role = "IT / Administration"
            elif any(k in user_part for k in ["security", "abuse", "soc"]):
                role = "Security / Abuse Team"
            elif any(k in user_part for k in ["press", "media"]):
                role = "Public Relations"
            elif "." in user_part:
                role = "Employee / Staff"

            formatted_emails.append({
                "email": email,
                "role": role,
                "source": "Web Surface Crawler"
            })

        pattern_name = "Unknown"
        if has_first_dot_last:
            pattern_name = "{first}.{last}@" + domain
        elif has_first_initial_last:
            pattern_name = "{f}{last}@" + domain

        return {
            "organization": org_name or "N/A",
            "social_links": social_links,
            "discovered_emails": formatted_emails,
            "email_pattern": pattern_name
        }

    # ---------------------------------------------------------
    # 3. Cloud Storage Assets (AWS S3 & GCP)
    # ---------------------------------------------------------
    async def check_cloud_assets(self, domain):
        logger.info(f"[{domain}] Enumerating cloud storage assets...")
        clean_name = domain.split(".")[0].lower()
        if len(clean_name) < 3:
            return []

        candidates = [
            clean_name,
            f"{clean_name}-assets",
            f"{clean_name}-backup",
            f"{clean_name}-public",
            f"{clean_name}-data",
            f"{clean_name}-dev",
            f"{clean_name}-media",
            domain.replace(".", "-")
        ]

        found_assets = []

        async def probe(client, provider, name, url):
            try:
                r = await client.head(url, timeout=2.5)
                if r.status_code == 200:
                    return {
                        "provider": provider,
                        "name": name,
                        "url": url,
                        "status": "Public Read (OPEN)",
                        "risk": "Critical"
                    }
                elif r.status_code == 403:
                    return {
                        "provider": provider,
                        "name": name,
                        "url": url,
                        "status": "Access Denied (Protected)",
                        "risk": "Low"
                    }
            except Exception:
                pass
            return None

        async with httpx.AsyncClient(timeout=2.5, follow_redirects=True, headers=self.headers) as client:
            tasks = []
            for name in candidates:
                tasks.append(probe(client, "AWS S3", name, f"https://{name}.s3.amazonaws.com"))
                tasks.append(probe(client, "Google Cloud Storage", name, f"https://storage.googleapis.com/{name}"))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, dict) and res:
                    found_assets.append(res)
                    if res["risk"] == "Critical":
                        await self.create_alert(
                            title=f"Exposed Public {res['provider']} Bucket: {res['name']}",
                            description=f"A cloud storage bucket associated with {domain} is publicly accessible without authentication.",
                            target=domain,
                            risk_level="critical",
                            details={"bucket_url": res["url"], "status_code": 200},
                            exploitation_suggestions=[
                                f"Inspect bucket contents using CLI tool: aws s3 ls s3://{res['name']} --no-sign-request",
                                "Restrict bucket ACL and enable Block Public Access immediately."
                            ],
                            alert_type="osint_public_buckets"
                        )

        return found_assets

    # ---------------------------------------------------------
    # 4. Domain Processing Execution
    # ---------------------------------------------------------
    async def process_domain_osint(self, domain_doc):
        domain = domain_doc["domain"]
        logger.info(f"=== Starting Comprehensive OSINT Gathering for {domain} ===")

        # 1. Mail Security, DNS & Vendor Analysis
        mail_sec = await self.analyze_mail_and_dns(domain, domain_doc)

        # 2. Corporate Identity, Social Links & Emails
        corp_id = await self.extract_corporate_identity(domain, domain_doc)

        # 3. Cloud Storage Asset Enumeration
        cloud_assets = await self.check_cloud_assets(domain)
        for asset in (cloud_assets or []):
            if isinstance(asset, dict):
                is_crit = asset.get("risk") == "Critical" or "open" in asset.get("status", "").lower()
                status = "open" if is_crit else "secured"
                http_status = 200 if status == "open" else 403
                await self.sync_bucket_to_footprint(
                    target=domain,
                    bucket_data={
                        "name": asset.get("name") or asset.get("url"),
                        "raw": asset.get("name") or asset.get("url"),
                        "url": asset.get("url"),
                        "provider": asset.get("provider") or "AWS S3",
                        "status": status,
                        "http_status": http_status,
                        "details": asset.get("details") or (f"{asset.get('provider')} bucket allows public read/listing (HTTP 200)" if status == "open" else f"{asset.get('provider')} bucket is protected (HTTP 403)"),
                        "source_app": domain,
                        "discovered_by": self.agent_name,
                        "discovered_at": datetime.datetime.utcnow().isoformat()
                    }
                )

        # 4. Advanced DNS Record Analytics (TXT, MX, SRV, CAA, SOA, NS)
        logger.info(f"[{domain}] Harvesting deep DNS records and service configurations...")
        dns_harvester = DnsRecordHarvester()
        dns_records = {}
        try:
            dns_records = await dns_harvester.harvest(domain)
        except Exception as de:
            logger.error(f"[{domain}] Error harvesting DNS records: {de}")

        # 5. ASN, Network Range & Infrastructure Mapping
        logger.info(f"[{domain}] Resolving BGP ASN, CIDR prefixes and reverse PTRs...")
        asn_resolver = AsnNetworkResolver()
        all_ips = list(set((dns_records.get("a") or []) + (dns_records.get("aaaa") or [])))
        subs = (domain_doc.get("infrastructure") or {}).get("subdomains", [])
        for s in subs:
            if isinstance(s, dict) and s.get("ip"):
                all_ips.append(s["ip"])

        asn_map = {}
        adjacent_hosts = []
        try:
            asn_map = await asn_resolver.resolve_batch(all_ips)
            # Reverse PTR sweep on primary domain IPs (range exploration)
            for ip in (dns_records.get("a") or [])[:2]:
                swept = await asn_resolver.sweep_range_ptrs(ip, count=8)
                adjacent_hosts.extend(swept)
        except Exception as ae:
            logger.error(f"[{domain}] Error resolving ASNs: {ae}")

        # 6. DNSSEC Audit & NSEC Zone Walk
        logger.info(f"[{domain}] Auditing DNSSEC configuration and checking for NSEC zone walk...")
        dnssec_auditor = DnssecAuditor()
        dnssec_info = {}
        nsec_zone_names = []
        try:
            dnssec_info = await dnssec_auditor.check_dnssec(domain)
            if dnssec_info.get("zone_walkable"):
                logger.warning(f"[{domain}] DNSSEC NSEC zone walk possible — attempting enumeration")
                nsec_zone_names = await dnssec_auditor.attempt_nsec_walk(domain)
                if nsec_zone_names:
                    await self.create_alert(
                        title=f"DNSSEC NSEC Zone Enumeration: {domain}",
                        description=(
                            f"The zone {domain} uses plain NSEC records (not NSEC3), allowing an attacker to enumerate "
                            f"all DNS names in the zone without brute-forcing. "
                            f"{len(nsec_zone_names)} zone names were discovered via NSEC chain walking."
                        ),
                        target=domain,
                        risk_level="medium",
                        details={
                            "dnssec_algorithm": dnssec_info.get("algorithm"),
                            "nsec_type": "NSEC",
                            "zone_names_count": len(nsec_zone_names),
                            "zone_names_sample": nsec_zone_names[:20]
                        },
                        exploitation_suggestions=[
                            f"Migrate the zone to NSEC3 with opt-out to prevent zone enumeration.",
                            f"Review the {len(nsec_zone_names)} enumerated zone names for internal or sensitive hostnames."
                        ],
                        alert_type="dnssec_nsec_zone_walk"
                    )
                    # Feed discovered zone names into verification queue
                    for zone_name in nsec_zone_names:
                        if self.is_in_scope(zone_name, domain):
                            exists = await self.tasks_col.find_one({
                                "root_domain": domain,
                                "target": zone_name,
                                "task_type": "verification"
                            })
                            if not exists:
                                await self.tasks_col.insert_one({
                                    "root_domain": domain,
                                    "target": zone_name,
                                    "task_type": "verification",
                                    "status": "pending",
                                    "source": "dnssec_nsec_walk",
                                    "created_at": datetime.datetime.utcnow()
                                })
        except Exception as dnse:
            logger.error(f"[{domain}] DNSSEC audit error: {dnse}")

        # Retain existing leaked credentials or empty list
        existing_osint = domain_doc.get("osint", {})
        leaked_creds = existing_osint.get("leaked_credentials", [])

        # Build OSINT Payload
        osint_payload = {
            "completed_at": datetime.datetime.utcnow().isoformat(),
            "organization": corp_id["organization"],
            "social_links": corp_id["social_links"],
            "mail_security": mail_sec,
            "dns_records": dns_records,
            "asn_data": asn_map,
            "adjacent_hosts": adjacent_hosts,
            "corporate_identity": {
                "organization": corp_id["organization"],
                "email_pattern": corp_id["email_pattern"],
                "discovered_emails": corp_id["discovered_emails"]
            },
            "leaked_credentials": leaked_creds,
            "cloud_assets": cloud_assets,
            "dnssec": {
                **dnssec_info,
                "zone_names": nsec_zone_names,
                "zone_names_count": len(nsec_zone_names)
            },
            "summary": {
                "emails_count": len(corp_id["discovered_emails"]),
                "social_count": len(corp_id["social_links"]),
                "cloud_assets_count": len(cloud_assets),
                "security_vendors_count": len(mail_sec["security_vendors"]),
                "verified_services_count": len(mail_sec["verified_services"]) + len(dns_records.get("identity_tokens", [])),
                "identity_tokens_count": len(dns_records.get("identity_tokens", [])),
                "authorized_senders_count": len(dns_records.get("authorized_senders", [])),
                "srv_services_count": len(dns_records.get("srv", [])),
                "caa_authorities_count": len(dns_records.get("ssl_authorities", [])),
                "dnssec_enabled": dnssec_info.get("enabled", False),
                "dnssec_zone_walkable": dnssec_info.get("zone_walkable", False),
                "spoofing_risk": mail_sec["spoofing_risk"]
            }
        }

        # Save to Database (save directly at root of domain document as well for fast indexing)
        await self.domains_col.update_one(
            {"_id": domain_doc["_id"]},
            {
                "$set": {
                    "osint": osint_payload,
                    "dns_records": dns_records,
                    "asn_data": asn_map,
                    "adjacent_hosts": adjacent_hosts,
                    "osint_complete": True,
                    "osint_updated_at": datetime.datetime.utcnow().isoformat()
                }
            }
        )

        # Complete tasks in tasks_col
        await self.tasks_col.update_many(
            {"root_domain": domain, "task_type": "osint", "status": {"$in": ["pending", "processing"]}},
            {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
        )

        logger.info(f"=== Completed OSINT for {domain}: Spoofing={mail_sec['spoofing_risk']}, Vendors={len(mail_sec['security_vendors'])}, Cloud={len(cloud_assets)}, Emails={len(corp_id['discovered_emails'])} ===")

    async def process_tasks(self):
        # 1. Process tasks explicitly queued in tasks_col
        task = await self.get_next_task("osint")

        if task:
            root_domain = task["root_domain"]
            domain_doc = await self.domains_col.find_one({
                "domain": root_domain,
                "blacklisted": {"$ne": True},
                "on_hold": {"$ne": True}
            })
            if domain_doc:
                await self.process_domain_osint(domain_doc)
            else:
                await self.tasks_col.update_one({"_id": task["_id"]}, {"$set": {"status": "failed", "error": "Domain not found or inactive"}})
            return

        # 2. Check for domains where osint_complete is not True
        pending_domain = await self.domains_col.find_one({
            "osint_complete": {"$ne": True},
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        })

        if pending_domain:
            await self.process_domain_osint(pending_domain)
            await asyncio.sleep(2)
        else:
            await asyncio.sleep(5)

if __name__ == "__main__":
    agent = OsintAgent()
    asyncio.run(agent.main_loop())
