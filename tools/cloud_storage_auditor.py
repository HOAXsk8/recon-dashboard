import asyncio
import datetime
import hashlib
import os
import random
import re
import string
import urllib.parse
from typing import Dict, List, Optional, Set
import httpx

from base_agent import BaseAgent, logger


class CloudStorageAuditorAgent(BaseAgent):
    def __init__(self):
        super().__init__("cloud_storage_auditor", "Cloud Storage Auditor")
        self.user_agent = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        )
        self.common_suffixes = [
            "assets", "static", "media", "public", "data", "backup",
            "backups", "files", "uploads", "cdn", "logs", "archive",
            "dev", "prod", "stage", "staging", "test", "internal",
            "bucket", "app", "storage", "images", "content"
        ]

    def extract_brand_keywords(self, domain: str) -> List[str]:
        """Extract brand/company name variants from domain."""
        domain_clean = domain.lower().strip().split(":")[0]
        parts = domain_clean.split(".")
        if len(parts) >= 2:
            # Handle co.uk, com.au, etc.
            if parts[-2] in ["co", "com", "org", "gov", "ac", "net"] and len(parts) >= 3:
                brand = parts[-3]
            else:
                brand = parts[-2]
        else:
            brand = parts[0]

        keywords = [brand]
        # Remove hyphens or split
        if "-" in brand:
            keywords.append(brand.replace("-", ""))
            keywords.extend([p for p in brand.split("-") if len(p) > 2])

        # Also add full base domain without TLD if clean
        clean_full = domain_clean.replace(".", "-")
        if clean_full != brand:
            keywords.append(clean_full)

        return list(dict.fromkeys(k for k in keywords if len(k) >= 2))

    def generate_candidate_names(self, keywords: List[str]) -> List[str]:
        """Generate targeted candidate bucket names from keywords."""
        candidates = set()
        for kw in keywords:
            candidates.add(kw)
            for suffix in self.common_suffixes:
                candidates.add(f"{kw}-{suffix}")
                candidates.add(f"{kw}{suffix}")
                candidates.add(f"{suffix}-{kw}")
                # Cross environments
                if suffix in ["assets", "static", "data", "media", "backup"]:
                    candidates.add(f"{kw}-dev-{suffix}")
                    candidates.add(f"{kw}-prod-{suffix}")

        # Ensure valid AWS S3 bucket naming rules (3-63 chars, lowercase, letters/digits/hyphens)
        valid_candidates = []
        for c in candidates:
            c_clean = re.sub(r'[^a-z0-9\-]', '', c.lower()).strip("-")
            if 3 <= len(c_clean) <= 63 and not c_clean.startswith("xn--"):
                valid_candidates.append(c_clean)

        return sorted(list(set(valid_candidates)))

    async def probe_bucket(self, client: httpx.AsyncClient, name: str, provider: str, base_url: str) -> Optional[dict]:
        """Audit a single cloud storage endpoint for access, permissions, and takeovers."""
        probe_url = base_url.format(name=name)
        result = {
            "name": name,
            "raw": probe_url.replace("https://", "").replace("http://", "").rstrip("/"),
            "url": probe_url,
            "provider": provider,
            "status": "unknown",
            "is_open": False,
            "is_writable": False,
            "is_takeover": False,
            "is_secured": False,
            "http_status": None,
            "details": "",
            "discovered_at": datetime.datetime.utcnow().isoformat()
        }

        try:
            # 1. READ / LISTING CHECK
            resp = await client.get(
                probe_url,
                headers={"User-Agent": self.user_agent},
                timeout=7.0,
                follow_redirects=True
            )
            result["http_status"] = resp.status_code
            text = resp.text[:4000]

            # --- AWS S3 / DigitalOcean Spaces / S3-Compatible ---
            if provider in ["AWS S3", "DigitalOcean Spaces"]:
                if resp.status_code == 200 and ("<ListBucketResult" in text or "<ListAllMyBucketsResult" in text or "<Contents>" in text):
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Public Directory Listing (HTTP 200). Objects and keys are readable unauthenticated."
                elif resp.status_code == 404:
                    # Guessed bucket permutation does not exist. Not an asset or takeover vulnerability without a dangling reference.
                    return None
                elif resp.status_code in [401, 403] or "<Code>AccessDenied</Code>" in text:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"Bucket is private and protected (HTTP {resp.status_code} AccessDenied)."
                else:
                    # Other status code (e.g. 400 Bad Request if region mismatch)
                    if "PermanentRedirect" in text:
                        result["status"] = "secured"
                        result["is_secured"] = True
                        result["details"] = "Bucket exists in another AWS region (Access restricted)."
                    else:
                        return None

            # --- Google Cloud Storage ---
            elif provider == "Google Cloud Storage":
                if resp.status_code == 200 and ("<ListBucketResult" in text or '"items":' in text or "<Contents>" in text):
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "GCS bucket allows public directory listing (HTTP 200)."
                elif resp.status_code == 404:
                    # Guessed permutation does not exist
                    return None
                elif resp.status_code in [401, 403] or "AccessDenied" in text:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"GCS bucket is private/restricted (HTTP {resp.status_code})."
                else:
                    return None

            # --- Azure Blob Storage ---
            elif provider == "Azure Blob":
                # For Azure, test root and ?comp=list
                if resp.status_code == 200 and "<EnumerationResults" in text:
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Azure Blob container enumeration allowed (HTTP 200)."
                elif resp.status_code == 404:
                    # Guessed permutation does not exist
                    return None
                elif resp.status_code in [400, 403]:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"Azure storage exists and is restricted (HTTP {resp.status_code})."
                else:
                    return None

            # 2. WRITE PERMISSION CHECK (if bucket exists and is reachable)
            if result["is_open"] or result["status"] == "secured":
                # Attempt safe unauthenticated write test
                test_token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
                test_file_name = f".recon_audit_probe_{test_token}.tmp"
                test_put_url = f"{probe_url.rstrip('/')}/{test_file_name}"
                try:
                    put_resp = await client.put(
                        test_put_url,
                        content=b"recon-dashboard-cloud-storage-permission-probe",
                        headers={"User-Agent": self.user_agent, "Content-Type": "text/plain"},
                        timeout=5.0
                    )
                    if put_resp.status_code in [200, 201]:
                        result["status"] = "vulnerable_write"
                        result["is_writable"] = True
                        result["is_open"] = True
                        result["details"] = f"CRITICAL: Unauthenticated Public Write Allowed (HTTP {put_resp.status_code})."
                        # Clean up immediately
                        try:
                            await client.delete(test_put_url, timeout=4.0)
                        except Exception:
                            pass
                except Exception:
                    pass

            return result

        except Exception as e:
            logger.debug(f"Probe error for {probe_url}: {e}")
            return None

    async def audit_existing_assets(self, root_domain: str, client: httpx.AsyncClient) -> List[dict]:
        """Audit existing cloud storage assets registered under this domain in MongoDB."""
        doc = await self.domains_col.find_one({"domain": root_domain}, {"infrastructure.cloud_footprint": 1})
        existing_cf = (doc or {}).get("infrastructure", {}).get("cloud_footprint") or {}

        existing_items = []
        for b in existing_cf.get("s3_buckets", []):
            if isinstance(b, dict):
                existing_items.append({"name": b.get("name") or b.get("raw"), "provider": b.get("provider", "AWS S3"), "url": b.get("url")})
        for b in existing_cf.get("azure_blobs", []):
            if isinstance(b, dict):
                existing_items.append({"name": b.get("name") or b.get("raw"), "provider": b.get("provider", "Azure Blob"), "url": b.get("url")})
        for b in existing_cf.get("gcp_buckets", []):
            if isinstance(b, dict):
                existing_items.append({"name": b.get("name") or b.get("raw"), "provider": b.get("provider", "Google Cloud Storage"), "url": b.get("url")})
        for b in existing_cf.get("other_buckets", []):
            if isinstance(b, dict):
                existing_items.append({"name": b.get("name") or b.get("raw"), "provider": b.get("provider", "DigitalOcean Spaces"), "url": b.get("url")})

        audited = []
        for item in existing_items:
            raw_url = item.get("url") or f"https://{item['name']}"
            name = item.get("name") or raw_url
            prov = item.get("provider", "AWS S3")
            res = await self.probe_bucket(client, name, prov, raw_url)
            if res:
                audited.append(res)

        return audited

    async def process_tasks(self):
        """Process queued cloud_storage_audit tasks."""
        task = await self.get_next_task("cloud_storage_audit")
        if not task:
            return

        target = task.get("target") or task.get("root_domain")
        root_domain = task["root_domain"]
        logger.info(f"[{self.agent_name}] Starting Cloud Storage Audit for target: {target} (Root: {root_domain})")

        try:
            keywords = self.extract_brand_keywords(target)
            if root_domain not in keywords:
                keywords.extend(self.extract_brand_keywords(root_domain))
            keywords = list(dict.fromkeys(keywords))
            candidate_names = self.generate_candidate_names(keywords)

            logger.info(f"[{self.agent_name}] Generated {len(candidate_names)} candidate bucket names for keywords {keywords}")

            all_audited: List[dict] = []

            async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
                # 1. Audit existing discovered buckets
                existing_results = await self.audit_existing_assets(root_domain, client)
                all_audited.extend(existing_results)

                # 2. Probe candidate bucket permutations across providers
                # Limit concurrency to 20 parallel requests to keep system fast and respectful
                semaphore = asyncio.Semaphore(20)

                async def sem_probe(name: str, prov: str, url_tmpl: str):
                    async with semaphore:
                        return await self.probe_bucket(client, name, prov, url_tmpl)

                probe_tasks = []
                for name in candidate_names[:60]:  # Top 60 targeted variations
                    probe_tasks.append(sem_probe(name, "AWS S3", "https://{name}.s3.amazonaws.com"))
                    probe_tasks.append(sem_probe(name, "Google Cloud Storage", "https://storage.googleapis.com/{name}"))
                    probe_tasks.append(sem_probe(name, "Azure Blob", "https://{name}.blob.core.windows.net/"))
                    probe_tasks.append(sem_probe(name, "DigitalOcean Spaces", "https://{name}.nyc3.digitaloceanspaces.com"))

                results = await asyncio.gather(*probe_tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, dict):
                        all_audited.append(r)

            # Deduplicate by URL
            unique_assets: Dict[str, dict] = {}
            for item in all_audited:
                u_key = item["url"].rstrip("/").lower()
                # If we have duplicate, prioritize vulnerable_write > open > secured
                if u_key in unique_assets:
                    prev = unique_assets[u_key]
                    priority_rank = {"vulnerable_write": 3, "open": 2, "secured": 1, "unknown": 0}
                    if priority_rank.get(item["status"], 0) > priority_rank.get(prev.get("status"), 0):
                        unique_assets[u_key] = item
                else:
                    unique_assets[u_key] = item

            valid_assets = list(unique_assets.values())
            logger.info(f"[{self.agent_name}] Identified {len(valid_assets)} confirmed cloud assets for {target}")

            # 3. Store in infrastructure.cloud_footprint
            s3_items = []
            azure_items = []
            gcp_items = []
            other_items = []

            for asset in valid_assets:
                asset_obj = {
                    "name": asset["name"],
                    "raw": asset["raw"],
                    "url": asset["url"],
                    "provider": asset["provider"],
                    "status": asset["status"],
                    "http_status": asset.get("http_status"),
                    "details": asset.get("details", ""),
                    "source_app": target,
                    "discovered_by": "cloud_storage_auditor",
                    "discovered_at": asset["discovered_at"]
                }
                if asset["provider"] == "AWS S3":
                    s3_items.append(asset_obj)
                elif asset["provider"] == "Azure Blob":
                    azure_items.append(asset_obj)
                elif asset["provider"] == "Google Cloud Storage":
                    gcp_items.append(asset_obj)
                else:
                    other_items.append(asset_obj)

            if s3_items or azure_items or gcp_items or other_items:
                doc = await self.domains_col.find_one({"domain": root_domain}, {"infrastructure.cloud_footprint": 1})
                existing_cf = (doc or {}).get("infrastructure", {}).get("cloud_footprint") or {}

                def merge_buckets(existing_list, new_items):
                    merged = {}
                    for it in (existing_list or []):
                        if isinstance(it, dict):
                            u = (it.get("url") or it.get("raw") or it.get("name") or "").strip().lower().rstrip("/")
                            src = (it.get("source_app") or "").strip().lower()
                            if u:
                                merged[(u, src)] = it
                    for it in new_items:
                        u = (it.get("url") or it.get("raw") or it.get("name") or "").strip().lower().rstrip("/")
                        src = (it.get("source_app") or "").strip().lower()
                        if u:
                            merged[(u, src)] = it
                    return list(merged.values())

                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {
                        "infrastructure.cloud_footprint.s3_buckets": merge_buckets(existing_cf.get("s3_buckets"), s3_items),
                        "infrastructure.cloud_footprint.azure_blobs": merge_buckets(existing_cf.get("azure_blobs"), azure_items),
                        "infrastructure.cloud_footprint.gcp_buckets": merge_buckets(existing_cf.get("gcp_buckets"), gcp_items),
                        "infrastructure.cloud_footprint.other_buckets": merge_buckets(existing_cf.get("other_buckets"), other_items),
                    }}
                )

                if target and target.lower() != root_domain.lower():
                    t_doc = await self.domains_col.find_one({"domain": target}, {"infrastructure.cloud_footprint": 1})
                    if t_doc:
                        t_existing_cf = (t_doc or {}).get("infrastructure", {}).get("cloud_footprint") or {}
                        await self.domains_col.update_one(
                            {"domain": target},
                            {"$set": {
                                "infrastructure.cloud_footprint.s3_buckets": merge_buckets(t_existing_cf.get("s3_buckets"), s3_items),
                                "infrastructure.cloud_footprint.azure_blobs": merge_buckets(t_existing_cf.get("azure_blobs"), azure_items),
                                "infrastructure.cloud_footprint.gcp_buckets": merge_buckets(t_existing_cf.get("gcp_buckets"), gcp_items),
                                "infrastructure.cloud_footprint.other_buckets": merge_buckets(t_existing_cf.get("other_buckets"), other_items),
                            }}
                        )

            # 4. Generate Centralized Leads / Alerts for Vulnerable Findings
            for asset in valid_assets:
                # Secured assets are recorded in inventory but not alerted
                if asset["status"] == "secured":
                    continue

                if asset["status"] == "vulnerable_write":
                    await self.create_alert(
                        title=f"Cloud Storage Vulnerability: Publicly Writable {asset['provider']} Bucket",
                        description=f"Storage bucket '{asset['name']}' allows UNRESTRICTED unauthenticated object uploads / file write (HTTP 200/201).",
                        target=asset["raw"],
                        risk_level="critical",
                        details=f"Target: {target}\nBucket URL: {asset['url']}\nProvider: {asset['provider']}\nStatus: {asset['details']}",
                        exploitation_suggestions=(
                            "### Publicly Writable Cloud Storage Remediation\n\n"
                            "1. **Immediate Remediation**: Enable S3 'Block Public Access' and revoke anonymous write/PUT permissions in IAM bucket policies.\n"
                            "2. **Audit Uploaded Files**: Check bucket access logs to verify if unauthorized objects or malware were uploaded.\n"
                            "3. **Impact**: Attackers can overwrite legitimate frontend assets or host malware/phishing payloads on your trusted domain."
                        ),
                        alert_type="cloud_storage_writable"
                    )
                elif asset["status"] == "open":
                    await self.create_alert(
                        title=f"Cloud Storage Leak: Publicly Listable {asset['provider']} Bucket",
                        description=f"Storage bucket '{asset['name']}' allows unrestricted unauthenticated directory listing and object downloads (HTTP 200).",
                        target=asset["raw"],
                        risk_level="high",
                        details=f"Target: {target}\nBucket URL: {asset['url']}\nProvider: {asset['provider']}\nStatus: {asset['details']}",
                        exploitation_suggestions=(
                            "### Public Bucket Remediation\n\n"
                            "1. **Inspect Exposed Objects**: Download the bucket's XML/JSON index to identify exposed customer PII, database backups, or API keys.\n"
                            "2. **Remediation**: Configure bucket ACLs and policies to private-only."
                        ),
                        alert_type="cloud_storage_listable"
                    )

            # Mark task completed
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {
                    "$set": {
                        "status": "completed",
                        "assets_found": len(valid_assets),
                        "completed_at": datetime.datetime.utcnow()
                    }
                }
            )
            await self.check_completion(root_domain)
            logger.info(f"[{self.agent_name}] Completed Cloud Storage Audit for {target}. Found {len(valid_assets)} assets.")

        except Exception as e:
            logger.error(f"[{self.agent_name}] Error processing audit for {target}: {e}", exc_info=True)
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )


if __name__ == "__main__":
    agent = CloudStorageAuditorAgent()
    asyncio.run(agent.main_loop())
