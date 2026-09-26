import asyncio
import os
import datetime
import logging
import urllib.parse
import hashlib
import re
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Optional, Dict, Any

# --- Configuration ---
MONGO_ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD")
if not MONGO_ROOT_PASSWORD:
    raise RuntimeError("MONGO_ROOT_PASSWORD environment variable is not set")
PASSWORD = urllib.parse.quote_plus(MONGO_ROOT_PASSWORD)
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_URI = f"mongodb://admin:{PASSWORD}@{MONGO_HOST}:27017/?authSource=admin"
DB_NAME = "recon_db"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Standard common modern browser user-agent
COMMON_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
DEFAULT_USER_AGENT = COMMON_USER_AGENT

CHANGE_ALERT_TYPES = {
    "port_scanner_changes",
    "tech_stack_changes",
    "security_header_regressions"
}

class BaseAgent:
    def __init__(self, agent_key, agent_name, type="script"):
        self.agent_key = agent_key
        self.agent_name = agent_name
        self.type = type
        self.user_agent = COMMON_USER_AGENT
        self.default_headers = {
            "User-Agent": COMMON_USER_AGENT,
            "Accept": "*/*"
        }
        self.client = AsyncIOMotorClient(MONGO_URI)
        self.db = self.client[DB_NAME]
        self.domains_col = self.db["domains"]
        self.scanners_col = self.db["scanners"]
        self.tasks_col = self.db["tasks"]
        self.leads_col = self.db["leads"]
        self.fingerprints_col = self.db["alert_fingerprints"]
        self.settings_col = self.db["settings"]
        self.workspaces_col = self.db["workspaces"]
        self.pause_event = asyncio.Event()
        self.pause_event.set() # Default to running
        self._last_serviced_ws = None

    @staticmethod
    def is_in_scope(target: str, root_domain: str, single_domain_only: bool = False) -> bool:
        """
        Validate that target is strictly within the scope of root_domain.
        If single_domain_only is True, target must strictly equal root_domain.
        Otherwise, target must be root_domain itself or a subdomain (*.root_domain).
        Strips protocols, credentials, ports, and paths if present.
        """
        if not target or not root_domain:
            return False
        
        target = str(target).strip().lower()
        root_domain = str(root_domain).strip().lower().rstrip(".")
        
        # Handle URLs
        if "://" in target:
            try:
                parsed = urllib.parse.urlparse(target)
                target = parsed.hostname or target
            except Exception:
                pass
        
        # Strip path or query if remaining
        if "/" in target:
            target = target.split("/")[0]
        if "?" in target:
            target = target.split("?")[0]
        
        # Strip port if present (e.g. host:8080)
        if ":" in target:
            target = target.split(":")[0]
            
        target = target.strip().rstrip(".")
        
        if single_domain_only:
            return target == root_domain

        # Exact match or subdomain
        return target == root_domain or target.endswith(f".{root_domain}")

    async def is_domain_active(self, root_domain: str) -> bool:
        """Check if root_domain exists in domains_col and is not blacklisted or on hold."""
        if not root_domain:
            return False
        root_domain = str(root_domain).strip().lower()
        doc = await self.domains_col.find_one({
            "domain": root_domain,
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        })
        return doc is not None

    async def get_next_task(self, task_type: str):
        """
        Fetch the next valid, in-scope pending task for task_type using fair-share
        round-robin across active workspaces. Paused workspaces are strictly excluded.
        Automatically discards and cancels tasks for deleted/inactive domains or out-of-scope targets.
        """
        while True:
            now = datetime.datetime.utcnow()

            # 1. Identify any paused workspaces
            paused_ws_ids = []
            try:
                paused_docs = await self.workspaces_col.find({"scan_paused": True}, {"_id": 1}).to_list(100)
                paused_ws_ids = [str(w["_id"]) for w in paused_docs]
            except Exception as e:
                logger.debug(f"Error querying paused workspaces: {e}")

            base_filter = {"task_type": task_type, "status": "pending"}
            if paused_ws_ids:
                base_filter["workspace_id"] = {"$nin": paused_ws_ids}

            # 2. Fair-share round-robin: pick next workspace among those with pending tasks
            task = None
            try:
                candidate_ws_ids = await self.tasks_col.distinct("workspace_id", base_filter)
                candidate_ws_ids = [str(w) for w in candidate_ws_ids if w and str(w) not in paused_ws_ids]

                if candidate_ws_ids and len(candidate_ws_ids) > 1:
                    if self._last_serviced_ws in candidate_ws_ids:
                        idx = candidate_ws_ids.index(self._last_serviced_ws)
                        chosen_ws = candidate_ws_ids[(idx + 1) % len(candidate_ws_ids)]
                    else:
                        chosen_ws = candidate_ws_ids[0]

                    task = await self.tasks_col.find_one_and_update(
                        {**base_filter, "workspace_id": chosen_ws},
                        {"$set": {"status": "processing", "started_at": now, "last_activity": now}},
                        sort=[("priority", -1), ("created_at", 1)]
                    )
                    if task:
                        self._last_serviced_ws = chosen_ws
            except Exception as e:
                logger.debug(f"Fair-share selection error, falling back: {e}")

            # 3. Fallback: pop any pending task matching base filter
            if not task:
                task = await self.tasks_col.find_one_and_update(
                    base_filter,
                    {"$set": {"status": "processing", "started_at": now, "last_activity": now}},
                    sort=[("priority", -1), ("created_at", 1)]
                )
                if task and task.get("workspace_id"):
                    self._last_serviced_ws = str(task["workspace_id"])

            if not task:
                return None

            root_domain = task.get("root_domain")
            target = task.get("target")

            # 4. Check if the root domain is currently active in the workspace
            domain_doc = await self.domains_col.find_one({
                "domain": root_domain,
                "blacklisted": {"$ne": True},
                "on_hold": {"$ne": True}
            })
            if not domain_doc:
                logger.warning(f"[{self.agent_name}] Discarding task {task.get('_id')} for inactive/deleted domain: {root_domain}")
                await self.tasks_col.delete_many({
                    "root_domain": root_domain,
                    "status": "pending"
                })
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "cancelled", "error": "Root domain not active or out of scope", "completed_at": datetime.datetime.utcnow()}}
                )
                continue

            is_single = domain_doc.get("single_domain_only", False)

            # 5. If domain is single_domain_only, discard any discovery tasks
            if is_single and task_type == "discovery":
                logger.info(f"[{self.agent_name}] Cancelling discovery task {task.get('_id')} because {root_domain} is a single target.")
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "cancelled", "error": "Single target domain", "completed_at": datetime.datetime.utcnow()}}
                )
                continue

            # 6. Check if the target is within the scope of root_domain
            if target and not self.is_in_scope(target, root_domain, single_domain_only=is_single):
                logger.warning(f"[{self.agent_name}] Discarding task {task.get('_id')} with out-of-scope target: {target} (Root: {root_domain}, Single: {is_single})")
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "cancelled", "error": f"Target {target} out of scope for {root_domain}", "completed_at": datetime.datetime.utcnow()}}
                )
                continue

            # 7. Ensure task inherits workspace_id from active domain document if missing
            ws_id = domain_doc.get("workspace_id")
            if ws_id and not task.get("workspace_id"):
                task["workspace_id"] = str(ws_id)
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"workspace_id": str(ws_id)}}
                )

            return task

    async def check_global_pause(self):
        """Check if scanning is globally paused."""
        try:
            settings = await self.settings_col.find_one({"key": "global_settings"})
            if settings and settings.get("scan_pause", False):
                return True
        except Exception as e:
            logger.error(f"Error checking global pause: {e}")
        return False

    def classify_alert_type(self, title: str, alert_type: Optional[str] = None) -> str:
        if alert_type:
            return alert_type
        t = (title or "").lower()

        # Cloud Storage Auditor
        if "publicly writable" in t or "writable" in t:
            return "cloud_storage_writable"
        if "publicly listable" in t or "listable" in t:
            return "cloud_storage_listable"

        # Directory & File Hunter
        if "favicon" in t or "murmur" in t:
            return "favicon_fingerprint"
        if "openid" in t or "oauth server" in t:
            return "well_known_openid_configuration"
        if "internal/pre-release" in t or "pre-release ios" in t:
            return "well_known_internal_app"
        if "mobile app" in t or "assetlink" in t or "universal links" in t or "aasa" in t:
            return "well_known_mobile_apps"
        if "trace" in t or "xst" in t:
            return "http_method_trace_xst"
        if "webdav" in t:
            return "http_method_webdav_enabled"
        if "arbitrary write" in t or "arbitrary http" in t:
            return "http_method_arbitrary_write"
        if "critical file exposed" in t or ("sensitive discovery" in t and any(p in t for p in [".env", ".git", ".aws", "credentials", "dump.sql", "id_rsa", "backup.zip"])):
            return "sensitive_files_critical"
        if "high-risk file exposed" in t or "config" in t or "admin" in t or "login" in t or ".htpasswd" in t or "passwd" in t:
            return "sensitive_files_high"
        if "diagnostic" in t or "actuator" in t or "swagger" in t or "openapi" in t or "phpinfo" in t or "metrics" in t:
            return "sensitive_files_diagnostic"
        if "sensitive discovery" in t or "file exposed" in t:
            return "sensitive_files_critical"

        # JS Collector & API Discovery
        if "hardcoded" in t or "credential" in t:
            return "js_hardcoded_secrets"
        if "unclaimed" in t or "takeover" in t:
            return "js_cloud_storage_takeover"
        if "exposed source map" in t or "source map" in t:
            return "js_source_maps"
        if "jwt token" in t or "exposed jwt" in t:
            return "js_jwt_tokens"
        if "cloud storage leak" in t or ("cloud storage" in t and "public" in t):
            return "js_cloud_storage_leaks"
        if "comment" in t or "todo" in t or "fixme" in t:
            return "sensitive_comment_leak"
        if "api spec" in t or "postman" in t or "insomnia" in t:
            return "api_spec_discovered"
        if "introspection" in t:
            return "graphql_introspection_enabled"
        if "graphql ide" in t or "playground" in t or "graphiql" in t:
            return "graphql_ide_exposed"
        if "hydration" in t:
            return "js_hydration_payload_leak"
        if "client-side route" in t or "framework route" in t:
            return "js_client_framework_routes"
        if "tracker" in t or "attribution" in t:
            return "js_third_party_tracker_pivots"

        # 403 Bypass
        if "403 bypass" in t:
            return "bypass_403_success"

        # OSINT & Mail Security
        if "dkim" in t:
            return "weak_dkim_key"
        if "nsec" in t or "zone walk" in t:
            return "dnssec_nsec_zone_walk"
        if "email spoofing" in t or "dmarc" in t or "spf" in t:
            return "osint_email_spoofing"
        if "exposed public" in t and "bucket" in t:
            return "osint_public_buckets"

        # WHOIS & Entity Correlation
        if "sister" in t or "cross-domain" in t or "corporate properties" in t:
            return "whois_sister_domains"

        # Port Scanner & TLS
        if "expired tls" in t or "certificate expired" in t:
            return "tls_cert_expired"
        if "expiry" in t and "tls" in t:
            return "tls_cert_expiry"
        if "internal domain leak" in t or "internal hostname" in t:
            return "tls_internal_domain_leak"
        if "self-signed" in t:
            return "tls_cert_self_signed"
        if "devops" in t or "cloud/devops" in t:
            return "cloud_devops_port_exposed"
        if "unauthenticated" in t and ("database" in t or "service" in t or "memcached" in t or "redis" in t):
            return "unauthenticated_service_exposed"
        if "port change" in t:
            return "port_scanner_changes"

        # Tech Fingerprinter & Vulnerabilities
        if "cve-" in t or "vulnerability" in t or "cisa kev" in t:
            return "known_vulnerability_detected"
        if "cookie" in t:
            return "insecure_cookie_configuration"
        if "technology stack changed" in t or "tech stack" in t:
            return "tech_stack_changes"
        if "security header regression" in t or "header regression" in t:
            return "security_header_regressions"

        # Historical Archive Hunter
        if "historical subdomain" in t:
            return "historical_subdomain_discovery"
        if "historical archive leak" in t or "archive" in t:
            return "archive_historical_leaks"

        # WAF & Edge
        if "waf protection gap" in t:
            return "waf_protection_gap"
        if "waf bypass" in t or "direct origin" in t:
            return "waf_origin_bypass"

        # Alive Check & Infrastructure
        if "dual-stack" in t or "ipv6" in t:
            return "dual_stack_origin_exposure"
        if "origin ip" in t or "uncloaked" in t:
            return "origin_ip_exposed"
        if "takeover" in t or "dangling" in t:
            return "dangling_dns_takeover"

        return "general_alert"

    @staticmethod
    def is_first_scan_cycle(domain_doc: Optional[dict]) -> bool:
        """
        Determine whether a domain is on its initial (first-ever) scan cycle.
        Returns True if the domain has never completed a scan cycle.
        """
        if not domain_doc:
            return False
        if domain_doc.get("initial_scan_completed") is True:
            return False
        last_scanned = domain_doc.get("last_scanned")
        if last_scanned and str(last_scanned).strip().lower() not in ["never", "none", ""]:
            return False
        if domain_doc.get("last_cycle_completed"):
            return False
        if (domain_doc.get("scan_cycle_count") or 0) > 0:
            return False
        if domain_doc.get("scanned") is True and last_scanned:
            return False
        return True

    async def get_root_domain_for_target(self, target: str, root_domain: Optional[str] = None) -> Optional[dict]:
        """
        Find the domain document for a given target or root_domain.
        """
        if root_domain:
            doc = await self.domains_col.find_one({"domain": root_domain.strip().lower()})
            if doc:
                return doc

        if not target:
            return None

        target_clean = str(target).strip().lower()
        if "://" in target_clean:
            try:
                target_clean = urllib.parse.urlparse(target_clean).hostname or target_clean
            except Exception:
                pass
        target_clean = target_clean.split(":")[0].strip()

        # 1. Direct match on domain
        doc = await self.domains_col.find_one({"domain": target_clean})
        if doc:
            return doc

        # 2. Subdomain match
        doc = await self.domains_col.find_one({"infrastructure.subdomains.name": target_clean})
        if doc:
            return doc

        # 3. Suffix match against domain parts
        parts = target_clean.split(".")
        for i in range(1, len(parts) - 1):
            parent_candidate = ".".join(parts[i:])
            doc = await self.domains_col.find_one({"domain": parent_candidate})
            if doc:
                return doc

        return None

    async def create_alert(self, title, description, target, risk_level, details, exploitation_suggestions, response_size=None, extra_key=None, alert_type=None, root_domain=None):
        """
        Create a new alert (lead) with fingerprint-based deduplication and alert setting checks.
        Prevents repeats even if the user deletes the lead.
        Suppresses change/regression alerts if the domain is on its initial scan cycle.
        """
        alert_key = self.classify_alert_type(title, alert_type)

        # Check if this alert indicates a change/regression and should be suppressed on first scan cycle
        is_change_alert = (
            alert_key in CHANGE_ALERT_TYPES
            or "change" in alert_key
            or "regression" in alert_key
            or "change detected" in title.lower()
            or "header regression" in title.lower()
        )

        # Resolve domain document to check first-scan and attach workspace_id
        domain_doc = await self.get_root_domain_for_target(target, root_domain=root_domain)
        workspace_id = str(domain_doc["workspace_id"]) if (domain_doc and domain_doc.get("workspace_id")) else None

        if is_change_alert:
            if domain_doc and self.is_first_scan_cycle(domain_doc):
                logger.info(
                    f"[FIRST-SCAN SUPPRESSED] Suppressed change alert '{alert_key}' ('{title}') during initial domain scan for target '{target}' (domain: '{domain_doc.get('domain')}')"
                )
                return False

        # Check if this alert type is disabled in Global Settings
        try:
            settings = await self.settings_col.find_one({"key": "global_settings"})
            if settings and "alerts" in settings:
                alerts_cfg = settings["alerts"]
                val = alerts_cfg.get(alert_key)
                if val is False or str(val).lower() == "false" or val == 0:
                    logger.info(f"[ALERT SUPPRESSED BY SETTINGS] '{alert_key}' is disabled: {title} on {target}")
                    return False
        except Exception as e:
            logger.error(f"Error checking alert settings for {alert_key}: {e}")

        # Create a unique fingerprint based on target, title, and optional extra_key (e.g. source map URL or secret)
        fingerprint_input = f"{target}|{title}|{extra_key}" if extra_key else f"{target}|{title}"
        fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()

        # 1. Check if this fingerprint is explicitly suppressed
        suppressed = await self.fingerprints_col.find_one({"fingerprint": fingerprint, "status": "suppressed"})
        if suppressed:
            logger.info(f"Skipping suppressed alert: {title} on {target}")
            return False

        # 2. Check if a lead with this fingerprint already exists
        existing_lead = await self.leads_col.find_one({"fingerprint": fingerprint})
        if existing_lead:
            # If it exists, we don't create a new one. 
            # We could update the timestamp, but let's stick to "tuning out repeats".
            return False

        # 3. Create the new lead
        lead_doc = {
            "title": title,
            "description": description,
            "target": target,
            "risk_level": risk_level,
            "status": "new",
            "source": self.agent_name,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "details": details,
            "exploitation_suggestions": exploitation_suggestions,
            "fingerprint": fingerprint,
            "acknowledged": False,
            "response_size": int(response_size) if response_size is not None else 0,
            "alert_type": alert_key
        }
        if workspace_id:
            lead_doc["workspace_id"] = workspace_id
        
        await self.leads_col.insert_one(lead_doc)
        
        # 4. Save/Update the fingerprint record
        fp_set = {
            "target": target,
            "title": title,
            "last_seen": datetime.datetime.utcnow(),
            "status": "active"
        }
        if workspace_id:
            fp_set["workspace_id"] = workspace_id

        await self.fingerprints_col.update_one(
            {"fingerprint": fingerprint},
            {"$set": fp_set},
            upsert=True
        )
        
        logger.info(f"Created NEW ALERT: {title} on {target}")

        # 5. Automatically ensure any cloud bucket alert is saved to the domain's cloud storage footprint
        try:
            if alert_key in ["osint_public_buckets", "cloud_storage_writable", "cloud_storage_listable", "js_cloud_storage_leaks", "js_cloud_storage_takeover"] or (details and isinstance(details, dict) and "bucket_url" in details) or ("bucket" in title.lower()):
                bucket_url = ""
                bucket_name = ""
                provider = "AWS S3"

                if isinstance(details, dict):
                    bucket_url = details.get("bucket_url") or details.get("url") or ""
                    bucket_name = details.get("bucket_name") or details.get("name") or ""
                elif isinstance(details, str):
                    m = re.search(r"Bucket URL:\s*([^\s\n]+)", details)
                    if m: bucket_url = m.group(1)
                    m2 = re.search(r"Provider:\s*([^\s\n]+)", details)
                    if m2: provider = m2.group(1)

                if not bucket_name:
                    m3 = re.search(r"Bucket:\s*([^\s\n]+)", title)
                    if m3:
                        bucket_name = m3.group(1)
                    elif ":" in title:
                        bucket_name = title.split(":")[-1].strip()

                if "google" in title.lower() or (bucket_url and "storage.googleapis.com" in bucket_url):
                    provider = "Google Cloud Storage"
                elif "azure" in title.lower() or (bucket_url and "blob.core.windows.net" in bucket_url):
                    provider = "Azure Blob"
                elif "s3" in title.lower() or (bucket_url and "s3.amazonaws.com" in bucket_url):
                    provider = "AWS S3"

                if "writable" in alert_key or "writable" in title.lower():
                    status = "vulnerable_write"
                elif "takeover" in alert_key or "unclaimed" in title.lower():
                    status = "vulnerable_takeover"
                else:
                    status = "open"

                if not bucket_url and bucket_name:
                    if provider == "Google Cloud Storage":
                        bucket_url = f"https://storage.googleapis.com/{bucket_name}"
                    elif provider == "AWS S3":
                        bucket_url = f"https://{bucket_name}.s3.amazonaws.com"

                if bucket_url or bucket_name:
                    await self.sync_bucket_to_footprint(
                        target=target,
                        bucket_data={
                            "name": bucket_name or bucket_url,
                            "raw": bucket_url.replace("https://", "").replace("http://", "").rstrip("/"),
                            "url": bucket_url,
                            "provider": provider,
                            "status": status,
                            "http_status": 200,
                            "details": description,
                            "source_app": target,
                            "discovered_by": self.agent_name,
                            "discovered_at": datetime.datetime.utcnow().isoformat()
                        }
                    )
        except Exception as e:
            logger.error(f"Error auto-syncing cloud bucket alert to footprint: {e}")

        return True

    async def sync_bucket_to_footprint(self, target: str, bucket_data: dict, root_domain: Optional[str] = None):
        """
        Ensure that a discovered or alerted cloud storage bucket is persistently saved
        into the associated domain's (and root domain's) infrastructure.cloud_footprint.
        """
        try:
            target_clean = (target or "").strip().lower()
            if not target_clean:
                return

            prov = bucket_data.get("provider") or "AWS S3"
            name = bucket_data.get("name") or bucket_data.get("raw") or ""
            raw = bucket_data.get("raw") or name
            url = bucket_data.get("url") or ""
            status = bucket_data.get("status") or "open"
            http_status = bucket_data.get("http_status") or 200
            details = bucket_data.get("details") or ""
            source_app = bucket_data.get("source_app") or target_clean
            discovered_by = bucket_data.get("discovered_by") or self.agent_name
            discovered_at = bucket_data.get("discovered_at") or datetime.datetime.utcnow().isoformat()

            asset_obj = {
                "name": name,
                "raw": raw,
                "url": url,
                "provider": prov,
                "status": status,
                "http_status": http_status,
                "details": details,
                "source_app": source_app,
                "discovered_by": discovered_by,
                "discovered_at": discovered_at
            }

            prov_lower = prov.lower()
            if "s3" in prov_lower or "aws" in prov_lower:
                category = "s3_buckets"
            elif "azure" in prov_lower or "blob" in prov_lower:
                category = "azure_blobs"
            elif "google" in prov_lower or "gcp" in prov_lower or "gcs" in prov_lower:
                category = "gcp_buckets"
            else:
                category = "other_buckets"

            domains_to_update = set()
            if root_domain:
                domains_to_update.add(root_domain.strip().lower())

            # Direct match
            if await self.domains_col.find_one({"domain": target_clean}):
                domains_to_update.add(target_clean)

            # Subdomain parent match
            parent = await self.domains_col.find_one({"infrastructure.subdomains.name": target_clean}, {"domain": 1})
            if parent:
                domains_to_update.add(parent["domain"].strip().lower())
            else:
                async for d in self.domains_col.find({}, {"domain": 1}):
                    d_name = d["domain"].strip().lower()
                    if target_clean == d_name or target_clean.endswith("." + d_name):
                        domains_to_update.add(d_name)

            def merge_into_list(existing_list, item):
                merged = {}
                for it in (existing_list or []):
                    if isinstance(it, dict):
                        u = (it.get("url") or it.get("raw") or it.get("name") or "").strip().lower().rstrip("/")
                        src = (it.get("source_app") or "").strip().lower()
                        if u:
                            merged[(u, src)] = it
                u = (item.get("url") or item.get("raw") or item.get("name") or "").strip().lower().rstrip("/")
                src = (item.get("source_app") or "").strip().lower()
                if u:
                    if (u, src) in merged:
                        prev = merged[(u, src)]
                        rank = {"vulnerable_write": 4, "vulnerable_takeover": 3, "open": 2, "secured": 1, "unknown": 0}
                        if rank.get(item.get("status"), 0) >= rank.get(prev.get("status"), 0):
                            merged[(u, src)] = {**prev, **item}
                    else:
                        merged[(u, src)] = item
                return list(merged.values())

            for d_name in domains_to_update:
                doc = await self.domains_col.find_one({"domain": d_name}, {f"infrastructure.cloud_footprint.{category}": 1})
                if doc is not None:
                    existing = (doc.get("infrastructure") or {}).get("cloud_footprint", {}).get(category) or []
                    updated_list = merge_into_list(existing, asset_obj)
                    await self.domains_col.update_one(
                        {"domain": d_name},
                        {"$set": {f"infrastructure.cloud_footprint.{category}": updated_list}}
                    )
        except Exception as e:
            logger.error(f"Error syncing bucket {bucket_data} to footprint: {e}")

    async def update_heartbeat(self):
        """Update agent status and check for pause/resume commands."""
        import resource
        rss_mb = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)

        await self.scanners_col.update_one(
            {"key": self.agent_key},
            {
                "$set": {
                    "name": self.agent_name,
                    "type": self.type,
                    "status": "Running",
                    "last_heartbeat": datetime.datetime.utcnow(),
                    "pid": os.getpid(),
                    "rss_mb": rss_mb
                }
            },
            upsert=True
        )

        while True:
            try:
                rss_mb = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
                await self.scanners_col.update_one(
                    {"key": self.agent_key},
                    {
                        "$set": {
                            "name": self.agent_name,
                            "type": self.type,
                            "status": "Running",
                            "last_heartbeat": datetime.datetime.utcnow(),
                            "pid": os.getpid(),
                            "rss_mb": rss_mb
                        }
                    },
                    upsert=True
                )

                scanner = await self.scanners_col.find_one({"key": self.agent_key})
                global_paused = await self.check_global_pause()
                
                if global_paused:
                    if self.pause_event.is_set():
                        logger.info(f"{self.agent_name} PAUSED (Global Pause Active).")
                        self.pause_event.clear()
                    # Optionally update status in scanners_col to reflect global pause
                    await self.scanners_col.update_one(
                        {"key": self.agent_key},
                        {"$set": {"status": "Paused (Global)"}}
                    )
                elif scanner and scanner.get("status") == "Stopped":
                    if self.pause_event.is_set():
                        logger.info(f"{self.agent_name} PAUSED via UI.")
                        self.pause_event.clear()
                else:
                    if not self.pause_event.is_set():
                        logger.info(f"{self.agent_name} RESUMED.")
                        self.pause_event.set()
                    # Ensure status is Running if it was previously Paused (Global)
                    if scanner and scanner.get("status") == "Paused (Global)":
                        await self.scanners_col.update_one(
                            {"key": self.agent_key},
                            {"$set": {"status": "Running"}}
                        )

            except Exception as e:
                logger.error(f"Heartbeat update failed: {e}")
            await asyncio.sleep(10)

    async def check_completion(self, root_domain):
        """Check if all tasks for this root domain are completed."""
        pending = await self.tasks_col.count_documents({
            "root_domain": root_domain,
            "status": {"$in": ["pending", "processing"]}
        })
        if pending == 0:
            now_iso = datetime.datetime.utcnow().isoformat()
            await self.domains_col.update_one(
                {"domain": root_domain},
                {
                    "$set": {
                        "scanned": True,
                        "last_scanned": now_iso,
                        "initial_scan_completed": True
                    },
                    "$inc": {"scan_cycle_count": 1}
                }
            )
            try:
                await self.domains_col.update_one(
                    {"domain": root_domain, "infrastructure.subdomains": {"$exists": True, "$type": "array", "$ne": []}},
                    {"$set": {
                        "infrastructure.subdomains.$[].scanned": True
                    }}
                )
            except Exception as se:
                logger.warning(f"Could not update subdomains.scanned for {root_domain}: {se}")
            logger.info(f"Root domain {root_domain} fully scanned.")

    async def run_command(self, cmd, timeout=300):
        """Helper to run shell commands asynchronously with a timeout."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return stdout.decode().strip(), stderr.decode().strip()
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError(f"Command '{' '.join(cmd)}' timed out after {timeout} seconds")
        except Exception as e:
            raise RuntimeError(f"Error running command '{' '.join(cmd)}': {e}")

    async def reverse_dns_lookup(self, ip: str, timeout: int = 5) -> list:
        """
        Perform a reverse DNS lookup using `dig -x <ip> +short`.
        Falls back to public DNS (@8.8.8.8) and dnspython if needed.
        Returns a list of FQDNs.
        """
        if not ip:
            return []
        ip = str(ip).strip()
        fqdns = []

        # 1. Try dig -x <ip> +short (system resolver)
        try:
            stdout, _ = await self.run_command(["dig", "-x", ip, "+short"], timeout=timeout)
            for line in stdout.splitlines():
                clean = line.strip().rstrip(".")
                if clean and not clean.startswith(";;") and clean not in fqdns:
                    fqdns.append(clean)
        except Exception:
            pass

        # 2. If empty, try dig -x <ip> @8.8.8.8 +short (public resolver)
        if not fqdns:
            try:
                stdout, _ = await self.run_command(["dig", "-x", ip, "@8.8.8.8", "+short"], timeout=timeout)
                for line in stdout.splitlines():
                    clean = line.strip().rstrip(".")
                    if clean and not clean.startswith(";;") and clean not in fqdns:
                        fqdns.append(clean)
            except Exception:
                pass

        # 3. If still empty and dnspython is installed, try dnspython
        if not fqdns:
            try:
                import dns.reversename
                import dns.asyncresolver
                rev_name = dns.reversename.from_address(ip)
                resolver = dns.asyncresolver.Resolver()
                resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
                resolver.timeout = timeout
                resolver.lifetime = timeout
                ans = await resolver.resolve(rev_name, "PTR")
                for rdata in ans:
                    clean = str(rdata).strip().rstrip(".")
                    if clean and clean not in fqdns:
                        fqdns.append(clean)
            except Exception:
                pass

        return fqdns

    async def main_loop(self):
        asyncio.create_task(self.update_heartbeat())
        while True:
            await self.pause_event.wait()
            try:
                await self.process_tasks()
            except Exception as e:
                logger.error(f"Main loop error: {e}")
            await asyncio.sleep(5)

    async def process_tasks(self):
        raise NotImplementedError("Subclasses must implement process_tasks")
