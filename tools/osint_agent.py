import asyncio
import datetime
import logging
import re
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dns.resolver
import httpx
from base_agent import BaseAgent, logger

class OsintAgent(BaseAgent):
    def __init__(self):
        super().__init__("osint_collector", "OSINT Intelligence Agent")
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

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

                    # Parse SPF includes for vendor detection
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

        # 3. Resolve SPF Include Chains (one hop) for email infrastructure insight
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
            try:
                sub_answers = dns.resolver.resolve(inc, "TXT")
                for r in sub_answers:
                    sub_txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                    if "fireeye" in sub_txt:
                        detected_vendors.add("Trellix / FireEye Email Security")
                    if "atmail" in sub_txt:
                        detected_vendors.add("Atmail Cloud")
            except Exception:
                pass

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

        # 5. Evaluate Spoofability & Risk
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

        # Alert if vulnerable
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
                    "security_vendors": result["security_vendors"]
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

        # Retain existing leaked credentials or empty list
        existing_osint = domain_doc.get("osint", {})
        leaked_creds = existing_osint.get("leaked_credentials", [])

        # Build OSINT Payload
        osint_payload = {
            "completed_at": datetime.datetime.utcnow().isoformat(),
            "organization": corp_id["organization"],
            "social_links": corp_id["social_links"],
            "mail_security": mail_sec,
            "corporate_identity": {
                "organization": corp_id["organization"],
                "email_pattern": corp_id["email_pattern"],
                "discovered_emails": corp_id["discovered_emails"]
            },
            "leaked_credentials": leaked_creds,
            "cloud_assets": cloud_assets,
            "summary": {
                "emails_count": len(corp_id["discovered_emails"]),
                "social_count": len(corp_id["social_links"]),
                "cloud_assets_count": len(cloud_assets),
                "security_vendors_count": len(mail_sec["security_vendors"]),
                "verified_services_count": len(mail_sec["verified_services"]),
                "spoofing_risk": mail_sec["spoofing_risk"]
            }
        }

        # Save to Database
        await self.domains_col.update_one(
            {"_id": domain_doc["_id"]},
            {
                "$set": {
                    "osint": osint_payload,
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
