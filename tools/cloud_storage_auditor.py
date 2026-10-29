import asyncio
import datetime
import hashlib
import json
import os
import random
import re
import string
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple
import httpx

from base_agent import BaseAgent, logger

# Human-readable AWS region mapping
AWS_REGION_NAMES: Dict[str, str] = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "af-south-1": "Africa (Cape Town)",
    "ap-east-1": "Asia Pacific (Hong Kong)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-south-2": "Asia Pacific (Hyderabad)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-3": "Asia Pacific (Jakarta)",
    "ap-southeast-4": "Asia Pacific (Melbourne)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ca-central-1": "Canada (Central)",
    "ca-west-1": "Canada West (Calgary)",
    "eu-central-1": "Europe (Frankfurt)",
    "eu-central-2": "Europe (Zurich)",
    "eu-west-1": "Europe (Ireland)",
    "eu-west-2": "Europe (London)",
    "eu-west-3": "Europe (Paris)",
    "eu-south-1": "Europe (Milan)",
    "eu-south-2": "Europe (Spain)",
    "eu-north-1": "Europe (Stockholm)",
    "il-central-1": "Israel (Tel Aviv)",
    "me-south-1": "Middle East (Bahrain)",
    "me-central-1": "Middle East (UAE)",
    "sa-east-1": "South America (São Paulo)"
}

# Sensitive file detection patterns across categories
SENSITIVE_PATTERNS: Dict[str, Dict[str, Any]] = {
    "database_dump": {
        "extensions": [".sql", ".dump", ".db", ".sqlite", ".sqlite3", ".bak", ".backup", ".rdb", ".frm", ".ibd", ".mdb", ".accdb"],
        "keywords": ["dump", "sqldump", "mysqldump", "pg_dump", "database", "schema", "db_backup"],
        "severity": "critical",
        "description": "Exposed Database Dump / Backup File"
    },
    "credentials_secrets": {
        "extensions": [".env", ".pem", ".key", ".pkcs12", ".p12", ".pfx", ".kdbx", ".id_rsa", ".id_ed25519", ".id_dsa", ".ovpn", ".htpasswd"],
        "keywords": [
            "credentials", "secret", "password", "passwd", "id_rsa", "id_ed25519", "aws_credentials",
            "service-account", "service_account", "client_secret", "master_key", "jwt_secret",
            "access_token", "privatekey", "private_key", "wp-config", "database.yml"
        ],
        "severity": "critical",
        "description": "Exposed Private Key, Credentials, or Secrets"
    },
    "configuration": {
        "extensions": [".conf", ".config", ".cfg", ".ini", ".properties"],
        "keywords": [
            "web.config", "settings.py", "local.settings.json", "application.yml", "application.properties",
            "config.json", "config.yaml", "config.yml", "parameters.yml", "connectionstrings"
        ],
        "severity": "high",
        "description": "Exposed Application Configuration File"
    },
    "financial_pii": {
        "extensions": [".pdf", ".csv", ".xlsx", ".xls", ".doc", ".docx"],
        "keywords": [
            "invoice", "statement", "tax", "passport", "ssn", "payroll", "salary",
            "employee", "customer", "confidential", "contract", "nda", "audit", "kyc"
        ],
        "severity": "high",
        "description": "Exposed Financial, Legal or PII Document"
    },
    "archive_backup": {
        "extensions": [".zip", ".tar.gz", ".tgz", ".tar", ".7z", ".rar", ".gz", ".bz2", ".xz"],
        "keywords": ["backup", "archive", "export", "source", "snapshot", "fullbackup"],
        "severity": "high",
        "description": "Exposed Compressed Archive or System Snapshot"
    },
    "log_traces": {
        "extensions": [".log", ".out", ".trace"],
        "keywords": ["access.log", "error.log", "production.log", "debug.log", "laravel.log", "system.log", "audit.log"],
        "severity": "medium",
        "description": "Exposed System or Application Logs"
    }
}

# Common Azure public container names
COMMON_AZURE_CONTAINERS = [
    "public", "assets", "media", "uploads", "data", "backup", "backups", "files", "images", "$web", "$root", "documents"
]


def classify_object_key(key: str) -> Optional[dict]:
    """Classify an object key against known high-value sensitive categories."""
    key_clean = key.strip()
    key_lower = key_clean.lower()
    file_name = os.path.basename(key_lower)

    # 1. Critical & High priority: Always flagged regardless of directory
    for category in ["credentials_secrets", "database_dump", "configuration", "archive_backup"]:
        meta = SENSITIVE_PATTERNS[category]
        for ext in meta["extensions"]:
            if key_lower.endswith(ext) or f"{ext}." in file_name or f"{ext}_" in file_name:
                return {
                    "category": category,
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "match_type": f"extension ({ext})"
                }
        for kw in meta["keywords"]:
            if kw in file_name or (kw.endswith("/") and kw in key_lower):
                return {
                    "category": category,
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "match_type": f"keyword ({kw})"
                }

    # 2. Financial / PII: requires keyword match in path/filename to avoid false-flagging brochures
    meta_pii = SENSITIVE_PATTERNS["financial_pii"]
    has_pii_kw = any(kw in key_lower for kw in meta_pii["keywords"])
    if has_pii_kw:
        for ext in meta_pii["extensions"]:
            if key_lower.endswith(ext) or f"{ext}." in file_name:
                return {
                    "category": "financial_pii",
                    "severity": meta_pii["severity"],
                    "description": meta_pii["description"],
                    "match_type": f"pii_keyword + {ext}"
                }

    # 3. Log traces
    meta_log = SENSITIVE_PATTERNS["log_traces"]
    for ext in meta_log["extensions"]:
        if key_lower.endswith(ext):
            return {
                "category": "log_traces",
                "severity": meta_log["severity"],
                "description": meta_log["description"],
                "match_type": f"extension ({ext})"
            }

    return None


def strip_ns(tag: str) -> str:
    """Strip XML namespace prefix from an ElementTree tag."""
    return tag.split("}")[-1] if "}" in tag else tag


def parse_bucket_object_listing(content: str, provider: str = "AWS S3") -> dict:
    """
    Parse XML or JSON cloud storage object listings, extract keys, sizes,
    and identify high-value / sensitive exposed files.
    """
    listing_summary = {
        "total_objects_listed": 0,
        "is_truncated": False,
        "sensitive_count": 0,
        "category_counts": {
            "database_dump": 0,
            "credentials_secrets": 0,
            "configuration": 0,
            "financial_pii": 0,
            "archive_backup": 0,
            "log_traces": 0
        },
        "sensitive_files": [],
        "sample_objects": [],
        "highest_risk": "none"
    }

    raw_items = []
    is_truncated = False

    # 1. Check for JSON format (e.g., GCS storage API or custom listings)
    content_stripped = content.strip()
    if content_stripped.startswith("{") and ("\"items\"" in content_stripped or "\"kind\"" in content_stripped):
        try:
            j_data = json.loads(content_stripped)
            if "items" in j_data and isinstance(j_data["items"], list):
                for it in j_data["items"]:
                    k = (it.get("name") or it.get("key") or "").strip()
                    if k:
                        raw_items.append({
                            "key": k,
                            "size": int(it.get("size") or 0),
                            "last_modified": (it.get("updated") or it.get("timeCreated") or "").strip()
                        })
                if j_data.get("nextPageToken"):
                    is_truncated = True
        except Exception:
            pass

    # 2. Check for XML format (AWS S3, DO Spaces, Azure Blob, GCS XML)
    if not raw_items and ("<ListBucketResult" in content or "<EnumerationResults" in content or "<Contents" in content or "<Blob" in content):
        try:
            root = ET.fromstring(content)
            for elem in root.iter():
                t = strip_ns(elem.tag)
                if t == "IsTruncated":
                    is_truncated = (elem.text or "").strip().lower() == "true"
                elif t == "Contents":  # S3 / DigitalOcean Spaces / GCS XML
                    item = {"key": "", "size": 0, "last_modified": ""}
                    for c in elem:
                        ct = strip_ns(c.tag)
                        if ct == "Key":
                            item["key"] = (c.text or "").strip()
                        elif ct == "Size":
                            try:
                                item["size"] = int(c.text or 0)
                            except Exception:
                                pass
                        elif ct == "LastModified":
                            item["last_modified"] = (c.text or "").strip()
                    if item["key"]:
                        raw_items.append(item)
                elif t == "Blob":  # Azure Blob EnumerationResults
                    item = {"key": "", "size": 0, "last_modified": ""}
                    for c in elem:
                        ct = strip_ns(c.tag)
                        if ct == "Name":
                            item["key"] = (c.text or "").strip()
                        elif ct == "Properties":
                            for p in c:
                                pt = strip_ns(p.tag)
                                if pt in ("Content-Length", "Size"):
                                    try:
                                        item["size"] = int(p.text or 0)
                                    except Exception:
                                        pass
                                elif pt in ("Last-Modified", "LastModified"):
                                    item["last_modified"] = (p.text or "").strip()
                    if item["key"]:
                        raw_items.append(item)
        except Exception:
            # Resilient fallback regex if XML is partial or malformed
            regex_keys = re.findall(r'<Key>([^<]+)</Key>', content)
            if not regex_keys:
                regex_keys = re.findall(r'<Name>([^<]+)</Name>', content)
            for k in regex_keys:
                raw_items.append({"key": k.strip(), "size": 0, "last_modified": ""})
            if "<IsTruncated>true</IsTruncated>" in content:
                is_truncated = True

    listing_summary["total_objects_listed"] = len(raw_items)
    listing_summary["is_truncated"] = is_truncated

    # Classify files and determine risk levels
    has_critical = False
    has_high = False

    for item in raw_items:
        key = item["key"]
        classified = classify_object_key(key)
        if classified:
            listing_summary["sensitive_count"] += 1
            cat = classified["category"]
            listing_summary["category_counts"][cat] = listing_summary["category_counts"].get(cat, 0) + 1

            if classified["severity"] == "critical":
                has_critical = True
            elif classified["severity"] == "high":
                has_high = True

            if len(listing_summary["sensitive_files"]) < 50:
                listing_summary["sensitive_files"].append({
                    "key": key,
                    "size": item["size"],
                    "last_modified": item["last_modified"],
                    "category": cat,
                    "severity": classified["severity"],
                    "description": classified["description"],
                    "match_type": classified["match_type"]
                })
        else:
            if len(listing_summary["sample_objects"]) < 20:
                listing_summary["sample_objects"].append(item)

    if has_critical:
        listing_summary["highest_risk"] = "critical"
    elif has_high:
        listing_summary["highest_risk"] = "high"
    elif listing_summary["total_objects_listed"] > 0:
        listing_summary["highest_risk"] = "medium"

    return listing_summary


def extract_bucket_fingerprint(resp: httpx.Response, url: str, provider: str) -> dict:
    """Extract cloud storage region, storage account, and infrastructure fingerprint."""
    fingerprint = {
        "region": None,
        "region_name": None,
        "account": None,
        "endpoint": url,
        "request_id": None,
        "server": resp.headers.get("server") or ""
    }

    # 1. AWS S3 Region Extraction
    s3_region = resp.headers.get("x-amz-bucket-region") or resp.headers.get("x-amz-region")
    if not s3_region:
        loc = resp.headers.get("location") or ""
        m_loc = re.search(r'\.s3[.-]([a-z0-9\-]+)\.amazonaws\.com', loc)
        if m_loc:
            s3_region = m_loc.group(1)
    if not s3_region:
        text = resp.text[:4000]
        m_ep = re.search(r'<Endpoint>[^<]*\.s3[.-]([a-z0-9\-]+)\.amazonaws\.com</Endpoint>', text)
        if m_ep:
            s3_region = m_ep.group(1)
        else:
            m_reg = re.search(r'<(?:Bucket)?Region>([a-z0-9\-]+)</(?:Bucket)?Region>', text)
            if m_reg:
                s3_region = m_reg.group(1)

    if s3_region:
        fingerprint["region"] = s3_region.strip().lower()
        fingerprint["region_name"] = AWS_REGION_NAMES.get(fingerprint["region"], f"AWS {fingerprint['region']}")

    # 2. DigitalOcean Spaces Region Extraction from URL
    m_do = re.search(r'\.([a-z0-9]{3,4})\.digitaloceanspaces\.com', url)
    if m_do:
        do_region = m_do.group(1).lower()
        fingerprint["region"] = do_region
        fingerprint["region_name"] = f"DigitalOcean {do_region.upper()}"

    # 3. Google Cloud Storage
    if "storage.googleapis.com" in url or resp.headers.get("x-guploader-uploadid"):
        fingerprint["request_id"] = resp.headers.get("x-guploader-uploadid")
        text = resp.text[:4000]
        m_gcs_loc = re.search(r'<LocationConstraint>([A-Za-z0-9\-]+)</LocationConstraint>', text)
        if m_gcs_loc:
            fingerprint["region"] = m_gcs_loc.group(1)
            fingerprint["region_name"] = f"GCS {m_gcs_loc.group(1)}"

    # 4. Azure Blob Account Fingerprint
    m_azure = re.search(r'https?://([a-z0-9\-]+)\.blob\.core\.windows\.net', url)
    if m_azure:
        fingerprint["account"] = m_azure.group(1)
    if resp.headers.get("x-ms-request-id"):
        fingerprint["request_id"] = resp.headers.get("x-ms-request-id")
    if resp.headers.get("x-amz-request-id"):
        fingerprint["request_id"] = resp.headers.get("x-amz-request-id")

    return fingerprint


async def execute_canary_write_test(
    client: httpx.AsyncClient,
    probe_url: str,
    user_agent: str,
    provider: str = "AWS S3"
) -> dict:
    """
    Perform a safe, non-destructive canary write test by uploading a uniquely
    generated test key and attempting immediate deletion if write succeeds.
    """
    canary_id = uuid.uuid4().hex[:12]
    canary_filename = f"audit_probe_test_{canary_id}.txt"
    test_put_url = f"{probe_url.rstrip('/')}/{canary_filename}"

    headers = {
        "User-Agent": user_agent,
        "Content-Type": "text/plain"
    }
    # Azure Blob requires x-ms-blob-type for block blob uploads
    if provider == "Azure Blob":
        headers["x-ms-blob-type"] = "BlockBlob"

    canary_payload = b"RDash Cloud Storage Security Audit Probe - Non-destructive canary verification."

    write_result = {
        "attempted": True,
        "is_writable": False,
        "canary_key": canary_filename,
        "canary_url": test_put_url,
        "put_status": None,
        "cleaned_up": False,
        "delete_status": None
    }

    try:
        put_resp = await client.put(
            test_put_url,
            content=canary_payload,
            headers=headers,
            timeout=5.0
        )
        write_result["put_status"] = put_resp.status_code

        if put_resp.status_code in [200, 201, 204]:
            write_result["is_writable"] = True
            # Attempt immediate deletion
            del_headers = {"User-Agent": user_agent}
            try:
                del_resp = await client.delete(test_put_url, headers=del_headers, timeout=4.0)
                write_result["delete_status"] = del_resp.status_code
                write_result["cleaned_up"] = del_resp.status_code in [200, 204, 404]
            except Exception as e_del:
                logger.debug(f"Canary cleanup DELETE failed for {test_put_url}: {e_del}")
    except Exception as e_put:
        logger.debug(f"Canary write PUT test error for {test_put_url}: {e_put}")

    return write_result


class CloudStorageAuditorAgent(BaseAgent):
    def __init__(self):
        super().__init__("cloud_storage_auditor", "Cloud Storage Auditor")
        self.user_agent = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        )

    async def probe_bucket(self, client: httpx.AsyncClient, name: str, provider: str, base_url: str) -> Optional[dict]:
        """
        Audit a single cloud storage endpoint for access, object listings,
        sensitive files, write permissions, and region fingerprinting.
        """
        probe_url = base_url.format(name=name) if "{name}" in base_url else base_url
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
            "region": None,
            "region_name": None,
            "http_status": None,
            "details": "",
            "listing_summary": None,
            "write_test": None,
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
            text = resp.text

            # Extract fingerprint & region
            fp = extract_bucket_fingerprint(resp, probe_url, provider)
            result["region"] = fp.get("region")
            result["region_name"] = fp.get("region_name")

            # --- AWS S3 / DigitalOcean Spaces / S3-Compatible ---
            if provider in ["AWS S3", "DigitalOcean Spaces", "Cloudflare R2"]:
                # If PermanentRedirect or AuthorizationHeaderMalformed with regional endpoint:
                # Re-probe the regional endpoint to get accurate listing & permissions
                if ("PermanentRedirect" in text or resp.status_code in [301, 307, 400]) and fp.get("region") and provider == "AWS S3":
                    reg = fp["region"]
                    if reg != "us-east-1":
                        reg_url = f"https://{name}.s3.{reg}.amazonaws.com/"
                        try:
                            reg_resp = await client.get(reg_url, headers={"User-Agent": self.user_agent}, timeout=7.0, follow_redirects=True)
                            if reg_resp.status_code in [200, 403]:
                                resp = reg_resp
                                probe_url = reg_url
                                result["url"] = reg_url
                                result["raw"] = reg_url.replace("https://", "").replace("http://", "").rstrip("/")
                                result["http_status"] = resp.status_code
                                text = resp.text
                        except Exception:
                            pass

                if resp.status_code == 200 and ("<ListBucketResult" in text or "<ListAllMyBucketsResult" in text or "<Contents>" in text):
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Public Directory Listing (HTTP 200). Objects and keys are readable unauthenticated."
                elif resp.status_code == 404:
                    return None
                elif resp.status_code in [401, 403] or "<Code>AccessDenied</Code>" in text:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    region_str = f" in {fp['region_name']}" if fp.get("region_name") else ""
                    result["details"] = f"Bucket is private and protected{region_str} (HTTP {resp.status_code} AccessDenied)."
                elif "PermanentRedirect" in text or resp.status_code in [301, 307]:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    region_str = f" in {fp['region_name']}" if fp.get("region_name") else ""
                    result["details"] = f"Bucket exists{region_str} (Access restricted / redirect)."
                else:
                    return None

            # --- Google Cloud Storage ---
            elif provider == "Google Cloud Storage":
                if resp.status_code == 200 and ("<ListBucketResult" in text or '"items":' in text or "<Contents>" in text):
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "GCS bucket allows public directory listing (HTTP 200)."
                elif resp.status_code == 404:
                    return None
                elif resp.status_code in [401, 403] or "AccessDenied" in text:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"GCS bucket is private/restricted (HTTP {resp.status_code})."
                else:
                    return None

            # --- Azure Blob Storage ---
            elif provider == "Azure Blob":
                if resp.status_code == 200 and "<EnumerationResults" in text:
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Azure Blob container enumeration allowed (HTTP 200)."
                elif resp.status_code == 404:
                    return None
                elif resp.status_code in [400, 403]:
                    # Storage account exists. Check common public containers
                    found_container = False
                    for container in COMMON_AZURE_CONTAINERS[:6]:
                        container_url = f"https://{name}.blob.core.windows.net/{container}?restype=container&comp=list"
                        try:
                            c_resp = await client.get(container_url, headers={"User-Agent": self.user_agent}, timeout=5.0)
                            if c_resp.status_code == 200 and "<EnumerationResults" in c_resp.text:
                                result["status"] = "open"
                                result["is_open"] = True
                                result["url"] = f"https://{name}.blob.core.windows.net/{container}"
                                result["raw"] = f"{name}.blob.core.windows.net/{container}"
                                result["details"] = f"Azure Blob container '{container}' enumeration allowed (HTTP 200)."
                                resp = c_resp
                                text = c_resp.text
                                probe_url = result["url"]
                                found_container = True
                                break
                        except Exception:
                            pass

                    if not found_container:
                        result["status"] = "secured"
                        result["is_secured"] = True
                        result["details"] = f"Azure storage exists and is restricted (HTTP {resp.status_code})."
                else:
                    return None

            # 2. OBJECT LISTING PARSER (if bucket is open and contents returned)
            if result["is_open"]:
                listing_summary = parse_bucket_object_listing(text, provider=provider)
                result["listing_summary"] = listing_summary
                total = listing_summary["total_objects_listed"]
                sens = listing_summary["sensitive_count"]
                if total > 0:
                    trunc_str = " (truncated)" if listing_summary["is_truncated"] else ""
                    sens_str = f" Found {sens} high-value/sensitive files." if sens > 0 else ""
                    result["details"] += f" Listing contains {total} objects{trunc_str}.{sens_str}"

            # 3. NON-DESTRUCTIVE WRITE PERMISSION CHECK (Canary Test)
            if result["is_open"] or result["status"] == "secured":
                write_test = await execute_canary_write_test(client, probe_url, self.user_agent, provider=provider)
                result["write_test"] = write_test

                if write_test["is_writable"]:
                    result["status"] = "vulnerable_write"
                    result["is_writable"] = True
                    result["is_open"] = True
                    clean_str = "Canary object verified and deleted." if write_test["cleaned_up"] else "Canary object uploaded."
                    result["details"] = f"CRITICAL: Public Write Allowed (HTTP {write_test['put_status']}). {clean_str}"

            return result

        except Exception as e:
            logger.debug(f"Probe error for {probe_url}: {e}")
            return None

    async def audit_existing_assets(self, root_domain: str, target: str, client: httpx.AsyncClient) -> List[dict]:
        """Audit existing cloud storage assets referenced in code under this domain/target in MongoDB."""
        docs_to_check = [root_domain]
        if target and target.lower() != root_domain.lower():
            docs_to_check.append(target)

        existing_items = []
        seen_keys = set()

        for d_name in set(docs_to_check):
            doc = await self.domains_col.find_one({"domain": d_name}, {"infrastructure.cloud_footprint": 1, "web_applications": 1})
            if not doc:
                continue

            existing_cf = (doc.get("infrastructure") or {}).get("cloud_footprint") or {}
            for prov_key, prov_name in [
                ("s3_buckets", "AWS S3"),
                ("azure_blobs", "Azure Blob"),
                ("gcp_buckets", "Google Cloud Storage"),
                ("other_buckets", "DigitalOcean Spaces")
            ]:
                for b in existing_cf.get(prov_key, []):
                    if isinstance(b, dict):
                        raw_u = b.get("url") or b.get("raw") or b.get("name")
                        if raw_u and raw_u.lower() not in seen_keys:
                            seen_keys.add(raw_u.lower())
                            existing_items.append({
                                "name": b.get("name") or raw_u,
                                "provider": b.get("provider", prov_name),
                                "url": b.get("url") or f"https://{raw_u}"
                            })

            # Check web_applications for code-referenced cloud assets from JS
            for app in doc.get("web_applications", []):
                for ca in app.get("cloud_assets", []):
                    if isinstance(ca, dict):
                        raw_u = ca.get("url") or ca.get("probe_url") or ca.get("raw") or ca.get("name")
                        if raw_u and raw_u.lower() not in seen_keys:
                            seen_keys.add(raw_u.lower())
                            existing_items.append({
                                "name": ca.get("name") or ca.get("bucket_name") or raw_u,
                                "provider": ca.get("provider", "AWS S3"),
                                "url": ca.get("url") or ca.get("probe_url") or f"https://{raw_u}"
                            })

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
        """Process queued cloud_storage_audit tasks by auditing code-referenced storage assets."""
        task = await self.get_next_task("cloud_storage_audit")
        if not task:
            return

        target = task.get("target") or task.get("root_domain")
        root_domain = task["root_domain"]
        logger.info(f"[{self.agent_name}] Starting Cloud Storage Audit for target: {target} (Root: {root_domain})")

        try:
            all_audited: List[dict] = []

            async with httpx.AsyncClient(verify=False, timeout=8.0, headers={"User-Agent": self.user_agent}) as client:
                # Strictly audit existing code-referenced assets from JavaScript / inventory (NO BLIND GUESSING)
                existing_results = await self.audit_existing_assets(root_domain, target, client)
                all_audited.extend(existing_results)

            if not all_audited:
                logger.info(f"[{self.agent_name}] No code-referenced cloud assets found for {target} (Root: {root_domain}). Permutation guessing is disabled.")
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow().isoformat()}}
                )
                return

            # Deduplicate by URL
            unique_assets: Dict[str, dict] = {}
            for item in all_audited:
                u_key = item["url"].rstrip("/").lower()
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
                    "region": asset.get("region"),
                    "region_name": asset.get("region_name"),
                    "http_status": asset.get("http_status"),
                    "details": asset.get("details", ""),
                    "listing_summary": asset.get("listing_summary"),
                    "write_test": asset.get("write_test"),
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
                            if (u, src) in merged:
                                prev = merged[(u, src)]
                                merged[(u, src)] = {**prev, **it}
                            else:
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

            # 4. Generate Centralized Alerts for Vulnerable Findings
            for asset in valid_assets:
                if asset["status"] == "secured":
                    continue

                region_display = asset.get("region_name") or asset.get("region") or "Global / Unknown"
                w_test = asset.get("write_test") or {}
                l_sum = asset.get("listing_summary") or {}

                if asset["status"] == "vulnerable_write":
                    clean_status_text = (
                        f"Non-destructive canary object `{w_test.get('canary_key')}` was uploaded and deleted immediately (HTTP {w_test.get('delete_status')})."
                        if w_test.get("cleaned_up")
                        else f"Canary object `{w_test.get('canary_key')}` was uploaded. Immediate automated deletion requires manual confirmation."
                    )
                    details_str = (
                        f"Target: {target}\n"
                        f"Bucket URL: {asset['url']}\n"
                        f"Provider: {asset['provider']}\n"
                        f"Region: {region_display}\n"
                        f"Public Write Status: CRITICAL (HTTP {w_test.get('put_status')})\n"
                        f"Verification: {clean_status_text}\n"
                        f"Details: {asset['details']}"
                    )
                    await self.create_alert(
                        title=f"Cloud Storage Vulnerability: Publicly Writable {asset['provider']} Bucket ({asset['name']})",
                        description=f"Storage bucket '{asset['name']}' allows UNRESTRICTED unauthenticated object uploads / file write (HTTP {w_test.get('put_status', 200)}).",
                        target=asset["raw"],
                        risk_level="critical",
                        details=details_str,
                        exploitation_suggestions=(
                            "### Publicly Writable Cloud Storage Remediation\n\n"
                            "1. **Immediate Remediation**:\n"
                            "   - **AWS S3**: Enable S3 'Block Public Access' at the account and bucket level. Update the bucket policy to require authenticated AWS IAM identities.\n"
                            "   - **Azure Blob**: Disable anonymous access by setting container access level to Private (off).\n"
                            "   - **Google Cloud Storage**: Enforce Uniform Bucket-Level Access (UBLA) and remove `allUsers` / `allAuthenticatedUsers` from `roles/storage.objectCreator` or `roles/storage.admin`.\n"
                            "2. **Log Review**: Audit access logs (AWS S3 server access logging or CloudTrail data events) to check if unauthorized or malicious files have been planted.\n"
                            "3. **Impact**: Attackers can overwrite legitimate application assets, deface websites, host malicious phishing payloads, or execute supply-chain attacks on software distributions."
                        ),
                        alert_type="cloud_storage_writable"
                    )

                elif asset["status"] == "open":
                    sensitive_count = l_sum.get("sensitive_count", 0)
                    total_objects = l_sum.get("total_objects_listed", 0)
                    highest_risk = l_sum.get("highest_risk", "high")

                    # If database dumps or credentials were leaked, escalate severity to Critical
                    alert_risk = "critical" if (sensitive_count > 0 and highest_risk == "critical") else "high"

                    # Format sensitive file samples
                    samples_markdown = ""
                    if l_sum.get("sensitive_files"):
                        samples_markdown = "\n\n### Exposed High-Value Files Detected:\n"
                        for s_file in l_sum["sensitive_files"][:10]:
                            samples_markdown += f"- `{s_file['key']}` ({s_file['category'].replace('_', ' ').title()}) - {s_file['description']}\n"
                        if len(l_sum["sensitive_files"]) > 10:
                            samples_markdown += f"- *...and {len(l_sum['sensitive_files']) - 10} more sensitive files.*\n"

                    cat_counts = l_sum.get("category_counts", {})
                    category_summary = (
                        f"- Database Dumps: {cat_counts.get('database_dump', 0)}\n"
                        f"- Credentials & Secrets: {cat_counts.get('credentials_secrets', 0)}\n"
                        f"- Configuration Files: {cat_counts.get('configuration', 0)}\n"
                        f"- Financial / PII Documents: {cat_counts.get('financial_pii', 0)}\n"
                        f"- Compressed Archives: {cat_counts.get('archive_backup', 0)}\n"
                    ) if sensitive_count > 0 else "None identified in initial index."

                    details_str = (
                        f"Target: {target}\n"
                        f"Bucket URL: {asset['url']}\n"
                        f"Provider: {asset['provider']}\n"
                        f"Region: {region_display}\n"
                        f"Total Objects Exposed: {total_objects}{' (truncated listing)' if l_sum.get('is_truncated') else ''}\n"
                        f"Sensitive Files Count: {sensitive_count}\n"
                        f"Sensitive Breakdown:\n{category_summary}\n"
                        f"Details: {asset['details']}"
                    )

                    alert_title = (
                        f"Cloud Storage Critical Leak: High-Value Files in Public {asset['provider']} Bucket ({asset['name']})"
                        if alert_risk == "critical"
                        else f"Cloud Storage Leak: Publicly Listable {asset['provider']} Bucket ({asset['name']})"
                    )

                    await self.create_alert(
                        title=alert_title,
                        description=f"Storage bucket '{asset['name']}' allows public directory listing exposing {total_objects} objects ({sensitive_count} sensitive files).",
                        target=asset["raw"],
                        risk_level=alert_risk,
                        details=details_str,
                        exploitation_suggestions=(
                            f"### Public Cloud Storage Remediation\n\n"
                            f"1. **Emergency Isolation**: Disable public listing and anonymous read permissions immediately on `{asset['name']}`.\n"
                            f"2. **Sensitive Asset Containment**:{samples_markdown if sensitive_count > 0 else ' Review bucket contents for sensitive data.'}\n"
                            f"3. **Credential Invalidation**: If credentials, `.env` files, or private keys were exposed, revoke and cycle all associated API tokens and passwords immediately.\n"
                            f"4. **Audit Access**: Inspect cloud access logs to evaluate the extent of unauthorized third-party downloads."
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
