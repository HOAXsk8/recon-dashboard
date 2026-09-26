from bson import ObjectId
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Optional, List, Union, Set
import os
import io
import json
import urllib.parse
import logging
import pandas as pd
import asyncio

from datetime import datetime, timedelta
import re
import ipaddress

from app.resource_monitor import read_system_vitals, estimate_pipeline_footprint

logger = logging.getLogger(__name__)

from app.database import domains_col, users_col, audit_logs_col, leads_col, scanners_col, settings_col, tasks_col, source_maps_col, findings_col, workspaces_col
from app.security import (
    verify_password, 
    create_access_token, 
    verify_totp, 
    get_password_hash, 
    get_totp_uri, 
    generate_totp_secret,
    validate_password,
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    DISABLE_2FA
)
from jose import jwt, JWTError

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="RDash")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

COMMON_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

templates = Jinja2Templates(directory="templates")
templates.env.globals["disable_2fa"] = DISABLE_2FA

# Mount Screenshots directory
SCREENSHOTS_DIR = os.environ.get("SCREENSHOTS_DIR", "/app/screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
app.mount("/screenshots", StaticFiles(directory=SCREENSHOTS_DIR), name="screenshots")

# Security Middleware for Headers
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data: https://flagcdn.com; font-src 'self' data:; frame-ancestors 'self';"
        return response

app.add_middleware(SecurityHeadersMiddleware)


# --- Helpers ---

def format_domain_item(d: dict):
    # Extract IP from systems if possible
    ip = "N/A"
    if d.get("systems") and len(d["systems"]) > 0:
        ip = d["systems"][0].get("ip", "N/A")
    
    # Count subdomains
    sub_count = 0
    if d.get("infrastructure") and d.get("infrastructure", {}).get("subdomains"):
        subs = d["infrastructure"]["subdomains"]
        if isinstance(subs, list):
            sub_count = len(subs)
        elif isinstance(subs, dict):
            sub_count = len(subs.keys())
    
    # Collect technologies
    techs = []
    if d.get("web_applications"):
        for app_info in d["web_applications"]:
            techs.extend(app_info.get("tech_stack", []))
    techs = list(set(techs))
    
    return {
        "id": str(d["_id"]),
        "domain": d.get("domain"),
        "ip": ip,
        "scanned": d.get("scanned", False),
        "subdomain_count": sub_count,
        "technologies": techs[:5],
        "tech_str": ", ".join(techs),
        "country_id": get_country_code(ip),
        "recon_date": d.get("recon_date", "N/A"),
        "last_scanned": d.get("last_scanned", "Never")
    }

def get_flattened_pipeline(
    root_query: dict,
    q: Optional[str] = None,
    status_val: Optional[str] = None,
    tech: Optional[str] = None,
    port: Optional[int] = None,
    waf: Optional[str] = None,
    lb: Optional[str] = None,
    mutator: Optional[str] = None,
    ip: Optional[str] = None,
    api_routes: Optional[str] = None,
    cloud_assets: Optional[str] = None,
    secrets: Optional[str] = None,
    jwt: Optional[str] = None,
    base64: Optional[str] = None,
    alive_apps: Optional[str] = None,
    historical: Optional[str] = None,
    takeover: Optional[str] = None,
    hide_parked: Optional[str] = None,
    api_spec: Optional[str] = None,
    drift: Optional[str] = None
):
    pipeline = [
        {"$match": root_query},
        {
            "$project": {
                "targets": {
                    "$reduce": {
                        "input": {
                            "$concatArrays": [
                                [{"name": "$domain", "is_root": True, "added_at": "$added_at", "source": {"$ifNull": ["$source", "user"]}}],
                                {"$ifNull": ["$infrastructure.subdomains", []]}
                            ]
                        },
                        "initialValue": [],
                        "in": {
                            "$cond": [
                                {"$in": ["$$this.name", {"$map": {"input": "$$value", "as": "v", "in": "$$v.name"}}]},
                                "$$value",
                                {"$concatArrays": ["$$value", ["$$this"]]}
                            ]
                        }
                    }
                },
                "subdomain_count": {
                    "$cond": {
                        "if": {"$isArray": "$infrastructure.subdomains"},
                        "then": {"$size": "$infrastructure.subdomains"},
                        "else": 0
                    }
                },
                "domain": 1,
                "infrastructure": 1,
                "systems": {"$ifNull": ["$systems", []]},
                "web_applications": {"$ifNull": ["$web_applications", []]},
                "archive_urls": 1,
                "history": {"$ifNull": ["$history", []]},
                "scanned": 1,
                "blacklisted": 1,
                "on_hold": 1,
                "added_at": 1,
                "scan_interval": 1,
                "single_domain_only": 1
            }
        },
        {"$unwind": "$targets"},
        {
            "$project": {
                "domain": "$targets.name",
                "root_domain": "$domain",
                "is_root": {"$ifNull": ["$targets.is_root", False]},
                "source": {"$ifNull": ["$targets.source", "$source"]},
                "subdomain_scanned": {"$ifNull": ["$targets.scanned", False]},
                "scanned_flag": "$scanned",
                "on_hold_flag": "$on_hold",
                "single_domain_only": {"$ifNull": ["$single_domain_only", False]},
                "scan_interval": {"$ifNull": ["$scan_interval", 720]},
                "subdomain_count": 1,
                "recon_date": {"$ifNull": ["$targets.added_at", "$added_at"]},
                "asn": {"$ifNull": ["$targets.asn", "$infrastructure.asn_data.primary_asn"]},
                "as_org": {"$ifNull": ["$targets.as_org", "$infrastructure.asn_data.primary_org"]},
                "cidr": {"$ifNull": ["$targets.cidr", None]},
                "ptr": {"$ifNull": ["$targets.ptr", None]},
                "dangling_takeover": {"$ifNull": ["$targets.dangling_takeover", False]},
                "cname": {"$ifNull": ["$targets.cname", None]},
                "takeover_provider": {"$ifNull": ["$targets.takeover_provider", None]},
                "system": {
                    "$arrayElemAt": [
                        {
                            "$filter": {
                                "input": "$systems",
                                "as": "s",
                                "cond": {"$eq": ["$$s.target", "$targets.name"]}
                            }
                        },
                        0
                    ]
                },
                "target_ips": {
                    "$setUnion": [
                        {
                            "$map": {
                                "input": {
                                    "$filter": {
                                        "input": "$systems",
                                        "as": "s",
                                        "cond": {"$eq": ["$$s.target", "$targets.name"]}
                                    }
                                },
                                "as": "m",
                                "in": "$$m.ip"
                            }
                        },
                        {
                            "$cond": [
                                {"$ne": [{"$ifNull": ["$targets.ip", None]}, None]},
                                ["$targets.ip"],
                                []
                            ]
                        },
                        {"$ifNull": ["$targets.ips", []]}
                    ]
                },
                "web_app": {
                    "$arrayElemAt": [
                        {
                            "$filter": {
                                "input": "$web_applications",
                                "as": "w",
                                "cond": {"$eq": ["$$w.target", "$targets.name"]}
                            }
                        },
                        0
                    ]
                },
                "web_applications": 1,
                "infrastructure": 1,
                "archive_urls": 1,
                "history": 1,
                "waf": {
                    "$ifNull": [
                        "$targets.waf",
                        {
                            "$ifNull": [
                                "$web_app.waf",
                                {
                                    "$cond": [
                                        {"$eq": ["$targets.name", "$domain"]},
                                        "$infrastructure.waf",
                                        None
                                    ]
                                }
                            ]
                        }
                    ]
                },
                "load_balancer": {
                    "$ifNull": [
                        "$targets.load_balancer",
                        {
                            "$ifNull": [
                                "$web_app.load_balancer",
                                {
                                    "$cond": [
                                        {"$eq": ["$targets.name", "$domain"]},
                                        "$infrastructure.load_balancer",
                                        None
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        },
        {
            "$project": {
                "domain": 1,
                "root_domain": 1,
                "is_root": 1,
                "source": 1,
                "subdomain_scanned": 1,
                "scanned_flag": 1,
                "on_hold_flag": 1,
                "single_domain_only": 1,
                "scan_interval": 1,
                "subdomain_count": 1,
                "recon_date": 1,
                "asn": 1,
                "as_org": 1,
                "cidr": 1,
                "ptr": 1,
                "dangling_takeover": 1,
                "cname": 1,
                "takeover_provider": 1,
                "system": 1,
                "target_ips": 1,
                "web_app": 1,
                "waf": 1,
                "load_balancer": 1,
                "has_api_routes": {
                    "$cond": [
                        {"$or": [
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.dynamic_js.extracted_endpoints", []]}}, 0]},
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.archive_urls.api_endpoints", []]}}, 0]},
                            {"$and": [
                                {"$eq": ["$is_root", True]},
                                {"$or": [
                                    {"$gt": [{"$size": {"$ifNull": ["$archive_urls.api_endpoints", []]}}, 0]},
                                    {"$gt": [
                                        {"$size": {
                                            "$filter": {
                                                "input": "$web_applications",
                                                "as": "wa",
                                                "cond": {"$gt": [{"$size": {"$ifNull": ["$$wa.dynamic_js.extracted_endpoints", []]}}, 0]}
                                            }
                                        }},
                                        0
                                    ]}
                                ]}
                            ]}
                        ]},
                        True,
                        False
                    ]
                },
                "has_cloud_assets": {
                    "$cond": [
                        {"$or": [
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.cloud_assets", []]}}, 0]},
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.dynamic_js.extracted_cloud_assets", []]}}, 0]},
                            {"$and": [
                                {"$eq": ["$is_root", True]},
                                {"$or": [
                                    {"$gt": [{"$size": {"$ifNull": ["$infrastructure.cloud_footprint.s3_buckets", []]}}, 0]},
                                    {"$gt": [{"$size": {"$ifNull": ["$infrastructure.cloud_footprint.azure_blobs", []]}}, 0]},
                                    {"$gt": [{"$size": {"$ifNull": ["$infrastructure.cloud_footprint.gcp_buckets", []]}}, 0]},
                                    {"$gt": [{"$size": {"$ifNull": ["$infrastructure.cloud_footprint.other_buckets", []]}}, 0]},
                                    {"$gt": [
                                        {"$size": {
                                            "$filter": {
                                                "input": "$web_applications",
                                                "as": "wa",
                                                "cond": {"$or": [
                                                    {"$gt": [{"$size": {"$ifNull": ["$$wa.cloud_assets", []]}}, 0]},
                                                    {"$gt": [{"$size": {"$ifNull": ["$$wa.dynamic_js.extracted_cloud_assets", []]}}, 0]}
                                                ]}
                                            }
                                        }},
                                        0
                                    ]}
                                ]}
                            ]}
                        ]},
                        True,
                        False
                    ]
                },
                "has_secrets": {
                    "$cond": [
                        {"$or": [
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.dynamic_js.extracted_secrets", []]}}, 0]},
                            {"$and": [
                                {"$eq": ["$is_root", True]},
                                {"$gt": [
                                    {"$size": {
                                        "$filter": {
                                            "input": "$web_applications",
                                            "as": "wa",
                                            "cond": {"$gt": [{"$size": {"$ifNull": ["$$wa.dynamic_js.extracted_secrets", []]}}, 0]}
                                        }
                                    }},
                                    0
                                ]}
                            ]}
                        ]},
                        True,
                        False
                    ]
                },
                "has_jwt": {
                    "$cond": [
                        {"$or": [
                            {"$gt": [{"$ifNull": ["$web_app.dynamic_js.jwt_count", 0]}, 0]},
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.dynamic_js.extracted_jwts", []]}}, 0]},
                            {"$and": [
                                {"$eq": ["$is_root", True]},
                                {"$gt": [
                                    {"$size": {
                                        "$filter": {
                                            "input": "$web_applications",
                                            "as": "wa",
                                            "cond": {"$or": [
                                                {"$gt": [{"$ifNull": ["$$wa.dynamic_js.jwt_count", 0]}, 0]},
                                                {"$gt": [{"$size": {"$ifNull": ["$$wa.dynamic_js.extracted_jwts", []]}}, 0]}
                                            ]}
                                        }
                                    }},
                                    0
                                ]}
                            ]}
                        ]},
                        True,
                        False
                    ]
                },
                "has_base64": {
                    "$cond": [
                        {"$or": [
                            {"$gt": [{"$ifNull": ["$web_app.dynamic_js.base64_count", 0]}, 0]},
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.dynamic_js.extracted_base64", []]}}, 0]},
                            {"$and": [
                                {"$eq": ["$is_root", True]},
                                {"$gt": [
                                    {"$size": {
                                        "$filter": {
                                            "input": "$web_applications",
                                            "as": "wa",
                                            "cond": {"$or": [
                                                {"$gt": [{"$ifNull": ["$$wa.dynamic_js.base64_count", 0]}, 0]},
                                                {"$gt": [{"$size": {"$ifNull": ["$$wa.dynamic_js.extracted_base64", []]}}, 0]}
                                            ]}
                                        }
                                    }},
                                    0
                                ]}
                            ]}
                        ]},
                        True,
                        False
                    ]
                },
                "has_alive_web_app": {
                    "$cond": [
                        {"$or": [
                            {"$gt": [{"$strLenCP": {"$ifNull": ["$web_app.target", ""]}}, 0]},
                            {"$and": [
                                {"$eq": ["$is_root", True]},
                                {"$gt": [{"$size": "$web_applications"}, 0]}
                            ]}
                        ]},
                        True,
                        False
                    ]
                },
                "has_historical_urls": {
                    "$cond": [
                        {"$or": [
                            {"$gt": [{"$ifNull": ["$web_app.archive_urls.total_urls", 0]}, 0]},
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.archive_urls.all_urls", []]}}, 0]},
                            {"$and": [
                                {"$eq": ["$is_root", True]},
                                {"$or": [
                                    {"$gt": [{"$ifNull": ["$archive_urls.total_urls", 0]}, 0]},
                                    {"$gt": [{"$size": {"$ifNull": ["$archive_urls.all_urls", []]}}, 0]},
                                    {"$gt": [
                                        {"$size": {
                                            "$filter": {
                                                "input": "$web_applications",
                                                "as": "wa",
                                                "cond": {"$gt": [{"$ifNull": ["$$wa.archive_urls.total_urls", 0]}, 0]}
                                            }
                                        }},
                                        0
                                    ]}
                                ]}
                            ]}
                        ]},
                        True,
                        False
                    ]
                },
                "has_api_specs": {
                    "$cond": [
                        {"$or": [
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.dynamic_js.api_specifications", []]}}, 0]},
                            {"$gt": [{"$size": {"$ifNull": ["$api_specifications", []]}}, 0]}
                        ]},
                        True,
                        False
                    ]
                },
                "has_graphql": {
                    "$cond": [
                        {"$or": [
                            {"$gt": [{"$size": {"$ifNull": ["$web_app.dynamic_js.graphql_endpoints", []]}}, 0]},
                            {"$gt": [{"$size": {"$ifNull": ["$graphql_endpoints", []]}}, 0]}
                        ]},
                        True,
                        False
                    ]
                },
                "subdomain_drift_events": {
                    "$filter": {
                        "input": {"$ifNull": ["$history", []]},
                        "as": "h",
                        "cond": {
                            "$and": [
                                {"$ne": ["$is_root", True]},
                                {"$or": [
                                    {"$eq": [{"$toLower": "$$h.target"}, {"$toLower": "$domain"}]},
                                    {"$in": [{"$toLower": "$$h.target"}, {"$map": {"input": "$target_ips", "as": "tip", "in": {"$toLower": "$$tip"}}}]}
                                ]}
                            ]
                        }
                    }
                }
            }
        },
        # --- Cross-Document Domain Deduplication ---
        {
            "$addFields": {
                "_has_webapp": {"$cond": [{"$ne": ["$web_app", None]}, 1, 0]},
                "_has_system": {"$cond": [{"$ne": ["$system", None]}, 1, 0]},
                "subdomain_drift_count": {"$size": "$subdomain_drift_events"},
                "latest_subdomain_drift_time": {"$max": "$subdomain_drift_events.timestamp"}
            }
        },
        {
            "$sort": {
                "is_root": -1,
                "single_domain_only": -1,
                "_has_webapp": -1,
                "_has_system": -1,
                "scanned_flag": -1,
                "subdomain_scanned": -1
            }
        },
        {
            "$group": {
                "_id": "$domain",
                "orig_id": {"$first": "$_id"},
                "domain": {"$first": "$domain"},
                "root_domain": {"$first": "$root_domain"},
                "is_root": {"$first": "$is_root"},
                "source": {"$first": "$source"},
                "subdomain_scanned": {"$max": "$subdomain_scanned"},
                "scanned_flag": {"$max": "$scanned_flag"},
                "on_hold_flag": {"$first": "$on_hold_flag"},
                "single_domain_only": {"$first": "$single_domain_only"},
                "scan_interval": {"$first": "$scan_interval"},
                "subdomain_count": {"$first": "$subdomain_count"},
                "recon_date": {"$first": "$recon_date"},
                "systems_list": {"$push": "$system"},
                "webapps_list": {"$push": "$web_app"},
                "wafs_list": {"$push": "$waf"},
                "lbs_list": {"$push": "$load_balancer"},
                "all_target_ips": {"$push": "$target_ips"},
                "has_api_routes": {"$max": "$has_api_routes"},
                "has_cloud_assets": {"$max": "$has_cloud_assets"},
                "has_secrets": {"$max": "$has_secrets"},
                "has_jwt": {"$max": "$has_jwt"},
                "has_base64": {"$max": "$has_base64"},
                "has_alive_web_app": {"$max": "$has_alive_web_app"},
                "has_historical_urls": {"$max": "$has_historical_urls"},
                "asn": {"$first": "$asn"},
                "as_org": {"$first": "$as_org"},
                "cidr": {"$first": "$cidr"},
                "ptr": {"$first": "$ptr"},
                "dangling_takeover": {"$max": "$dangling_takeover"},
                "cname": {"$first": "$cname"},
                "takeover_provider": {"$first": "$takeover_provider"},
                "has_api_specs": {"$max": "$has_api_specs"},
                "has_graphql": {"$max": "$has_graphql"},
                "subdomain_drift_count": {"$max": "$subdomain_drift_count"},
                "latest_subdomain_drift_time": {"$max": "$latest_subdomain_drift_time"}
            }
        },
        {
            "$project": {
                "_id": "$orig_id",
                "domain": 1,
                "root_domain": 1,
                "is_root": 1,
                "source": 1,
                "subdomain_scanned": 1,
                "scanned_flag": 1,
                "on_hold_flag": 1,
                "single_domain_only": 1,
                "scan_interval": 1,
                "subdomain_count": 1,
                "recon_date": 1,
                "system": {
                    "$arrayElemAt": [
                        {
                            "$filter": {
                                "input": "$systems_list",
                                "as": "item",
                                "cond": {"$ne": ["$$item", None]}
                            }
                        },
                        0
                    ]
                },
                "target_ips": {
                    "$reduce": {
                        "input": "$all_target_ips",
                        "initialValue": [],
                        "in": {"$setUnion": ["$$value", "$$this"]}
                    }
                },
                "web_app": {
                    "$arrayElemAt": [
                        {
                            "$filter": {
                                "input": "$webapps_list",
                                "as": "item",
                                "cond": {"$ne": ["$$item", None]}
                            }
                        },
                        0
                    ]
                },
                "waf": {
                    "$ifNull": [
                        {
                            "$arrayElemAt": [
                                {
                                    "$filter": {
                                        "input": "$wafs_list",
                                        "as": "w",
                                        "cond": {"$and": [{"$ne": ["$$w", None]}, {"$eq": ["$$w.detected", True]}]}
                                    }
                                },
                                0
                            ]
                        },
                        {
                            "$arrayElemAt": [
                                {
                                    "$filter": {
                                        "input": "$wafs_list",
                                        "as": "w",
                                        "cond": {"$ne": ["$$w", None]}
                                    }
                                },
                                0
                            ]
                        }
                    ]
                },
                "load_balancer": {
                    "$ifNull": [
                        {
                            "$arrayElemAt": [
                                {
                                    "$filter": {
                                        "input": "$lbs_list",
                                        "as": "l",
                                        "cond": {"$and": [{"$ne": ["$$l", None]}, {"$eq": ["$$l.detected", True]}]}
                                    }
                                },
                                0
                            ]
                        },
                        {
                            "$arrayElemAt": [
                                {
                                    "$filter": {
                                        "input": "$lbs_list",
                                        "as": "l",
                                        "cond": {"$ne": ["$$l", None]}
                                    }
                                },
                                0
                            ]
                        }
                    ]
                },
                "has_api_routes": 1,
                "has_cloud_assets": 1,
                "has_secrets": 1,
                "has_jwt": 1,
                "has_base64": 1,
                "has_alive_web_app": 1,
                "has_historical_urls": 1,
                "asn": 1,
                "as_org": 1,
                "cidr": 1,
                "ptr": 1,
                "dangling_takeover": 1,
                "cname": 1,
                "takeover_provider": 1,
                "has_api_specs": 1,
                "has_graphql": 1,
                "subdomain_drift_count": {"$ifNull": ["$subdomain_drift_count", 0]},
                "latest_subdomain_drift_time": 1
            }
        }
    ]
    
    # Apply filters after flattening
    match_stage = {}
    if q:
        safe_q = re.escape(q.strip())
        match_stage["$or"] = [
            {"domain": {"$regex": safe_q, "$options": "i"}},
            {"target_ips": {"$regex": safe_q, "$options": "i"}},
            {"system.services.software": {"$regex": safe_q, "$options": "i"}},
            {"system.services.service": {"$regex": safe_q, "$options": "i"}}
        ]
    
    if ip and ip.strip():
        match_stage["target_ips"] = ip.strip()
    
    if tech:
        match_stage["web_app.tech_stack"] = {"$regex": re.escape(tech), "$options": "i"}
        
    if port:
        match_stage["system.services.port"] = port

    if waf:
        waf_clean = waf.strip().lower()
        if waf_clean in ["true", "detected", "any"]:
            match_stage["waf.detected"] = True
        elif waf_clean in ["false", "none", "no"]:
            match_stage["$or"] = [
                {"waf.detected": False},
                {"waf": None},
                {"waf.detected": {"$exists": False}}
            ]
        else:
            match_stage["waf.firewall"] = {"$regex": re.escape(waf), "$options": "i"}

    if lb:
        lb_clean = lb.strip().lower()
        if lb_clean in ["true", "detected", "any"]:
            match_stage["load_balancer.detected"] = True
        elif lb_clean in ["false", "none", "no"]:
            match_stage["$or"] = [
                {"load_balancer.detected": False},
                {"load_balancer": None},
                {"load_balancer.detected": {"$exists": False}}
            ]
        else:
            match_stage["load_balancer.method"] = {"$regex": re.escape(lb), "$options": "i"}


    # Additional Domain & Reconnaissance Findings Filters
    if api_routes:
        ar_clean = str(api_routes).strip().lower()
        if ar_clean in ["true", "1", "yes"]:
            match_stage["has_api_routes"] = True
        elif ar_clean in ["false", "0", "no"]:
            match_stage["has_api_routes"] = False

    if cloud_assets:
        ca_clean = str(cloud_assets).strip().lower()
        if ca_clean in ["true", "1", "yes"]:
            match_stage["has_cloud_assets"] = True
        elif ca_clean in ["false", "0", "no"]:
            match_stage["has_cloud_assets"] = False

    if secrets:
        sec_clean = str(secrets).strip().lower()
        if sec_clean in ["true", "1", "yes"]:
            match_stage["has_secrets"] = True
        elif sec_clean in ["false", "0", "no"]:
            match_stage["has_secrets"] = False

    if jwt:
        jwt_clean = str(jwt).strip().lower()
        if jwt_clean in ["true", "1", "yes"]:
            match_stage["has_jwt"] = True
        elif jwt_clean in ["false", "0", "no"]:
            match_stage["has_jwt"] = False

    if base64:
        b64_clean = str(base64).strip().lower()
        if b64_clean in ["true", "1", "yes"]:
            match_stage["has_base64"] = True
        elif b64_clean in ["false", "0", "no"]:
            match_stage["has_base64"] = False

    if alive_apps:
        aa_clean = str(alive_apps).strip().lower()
        if aa_clean in ["true", "1", "yes"]:
            match_stage["has_alive_web_app"] = True
        elif aa_clean in ["false", "0", "no"]:
            match_stage["has_alive_web_app"] = False

    if historical:
        h_clean = str(historical).strip().lower()
        if h_clean in ["true", "1", "yes"]:
            match_stage["has_historical_urls"] = True
        elif h_clean in ["false", "0", "no"]:
            match_stage["has_historical_urls"] = False

    if takeover:
        to_clean = str(takeover).strip().lower()
        if to_clean in ["true", "1", "yes"]:
            match_stage["dangling_takeover"] = True
        elif to_clean in ["false", "0", "no"]:
            match_stage["dangling_takeover"] = False

    if hide_parked and str(hide_parked).strip().lower() in ["true", "1", "yes"]:
        match_stage["$nor"] = [
            {"web_app.status": {"$in": [502, 503, 521, 522, 523]}},
            {"web_app.title": {"$regex": r"(parked|domain for sale|buy this domain|default web site page|iis windows server|apache2 ubuntu default page|nginx test page)", "$options": "i"}}
        ]

    if api_spec:
        as_clean = str(api_spec).strip().lower()
        if as_clean in ["true", "1", "yes"]:
            match_stage["$or"] = [
                {"has_api_specs": True},
                {"has_graphql": True}
            ]
        elif as_clean in ["false", "0", "no"]:
            match_stage["has_api_specs"] = False
            match_stage["has_graphql"] = False

    if drift:
        dr_clean = str(drift).strip().lower()
        if dr_clean in ["true", "1", "yes", "has_drift"]:
            match_stage["is_root"] = False
            match_stage["subdomain_drift_count"] = {"$gt": 0}
        elif dr_clean in ["recent", "24h", "new", "today"]:
            cutoff_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            match_stage["is_root"] = False
            match_stage["latest_subdomain_drift_time"] = {"$gte": cutoff_24h}
        elif dr_clean in ["7d", "week", "recent_7d"]:
            cutoff_7d = (datetime.utcnow() - timedelta(days=7)).isoformat()
            match_stage["is_root"] = False
            match_stage["latest_subdomain_drift_time"] = {"$gte": cutoff_7d}
        elif dr_clean in ["false", "0", "no", "none"]:
            match_stage["is_root"] = False
            match_stage["subdomain_drift_count"] = {"$lte": 0}

    if status_val:
        if status_val == "scanned":
            # Consider an asset scanned if it has system data OR has subdomain_scanned=True OR is a root marked as scanned
            pipeline.append({"$match": {"$or": [
                {"system": {"$ne": None}},
                {"subdomain_scanned": True},
                {"$and": [{"is_root": True}, {"scanned_flag": True}]}
            ]}})
        elif status_val == "pending":
            pipeline.append({"$match": {"$and": [
                {"system": None},
                {"subdomain_scanned": {"$ne": True}},
                {"$or": [
                    {"is_root": False},
                    {"$and": [{"is_root": True}, {"scanned_flag": False}]}
                ]}
            ]}})
        elif status_val == "on_hold":
            match_stage["on_hold_flag"] = True

    if match_stage:
        pipeline.append({"$match": match_stage})
        
    return pipeline

def get_query_filters(q: Optional[str], status_val: Optional[str], has_subdomains: Optional[str], tech: Optional[str], blacklisted: Optional[str], port: Optional[int] = None, ws_clause: Optional[dict] = None):
    query = {}
    if ws_clause:
        query.update(ws_clause)
    
    # Text search, status, tech, and port are now handled in the flattened pipeline
    
    if has_subdomains == "true":
        query["infrastructure.subdomains.0"] = {"$exists": True}
    elif has_subdomains == "false":
        query["$or"] = [
            {"infrastructure.subdomains": {"$size": 0}},
            {"infrastructure.subdomains": {"$exists": False}}
        ]
        
    if blacklisted == "true":
        query["blacklisted"] = True
    elif blacklisted == "false":
        query["blacklisted"] = {"$ne": True}
    else:
        # Default: exclude blacklisted
        query["blacklisted"] = {"$ne": True}

    return query

# Auth Helper
async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        user = await users_col.find_one({"username": username})
        if not user or user.get("disabled", False):
            return None
        # Ensure role exists (migration fallback)
        if "role" not in user:
            user["role"] = "admin" if user.get("is_admin") else "analyst"
        return user
    except JWTError:
        return None

def check_admin(user: dict):
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrative privileges required")

def check_analyst(user: dict):
    if not user or user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Analyst privileges required")

def check_viewer(user: dict):
    if not user:
        raise HTTPException(status_code=401)

# Workspace Helpers
async def get_or_create_default_workspace():
    ws = await workspaces_col.find_one({"is_default": True})
    if not ws:
        ws = await workspaces_col.find_one({})
    if not ws:
        ws = {
            "name": "Default Workspace",
            "description": "Default workspace for reconnaissance targets",
            "is_default": True,
            "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "created_by": "system"
        }
        res = await workspaces_col.insert_one(ws)
        ws["_id"] = res.inserted_id
    elif not ws.get("is_default"):
        await workspaces_col.update_one({"_id": ws["_id"]}, {"$set": {"is_default": True}})
        ws["is_default"] = True
    return ws

async def get_active_workspace(user: Optional[dict], request: Optional[Request] = None) -> dict:
    target_id = None
    if request:
        target_id = request.cookies.get("active_workspace_id")
    if not target_id and user:
        target_id = user.get("active_workspace_id")
        
    ws = None
    if target_id:
        try:
            ws = await workspaces_col.find_one({"_id": ObjectId(target_id)})
        except Exception:
            pass
            
    if not ws:
        ws = await get_or_create_default_workspace()
        
    ws_id_str = str(ws["_id"])
    if user and user.get("active_workspace_id") != ws_id_str and "_id" in user:
        await users_col.update_one({"_id": user["_id"]}, {"$set": {"active_workspace_id": ws_id_str}})
        user["active_workspace_id"] = ws_id_str
        
    return ws

def workspace_match_clause(ws_id, is_default: bool = False) -> dict:
    """Builds a query clause to match records belonging to ws_id (as string or ObjectId)."""
    ws_str = str(ws_id)
    valid_obj_id = None
    try:
        valid_obj_id = ObjectId(ws_str)
    except Exception:
        pass

    ws_matches = [{"workspace_id": ws_str}]
    if valid_obj_id:
        ws_matches.append({"workspace_id": valid_obj_id})

    if is_default:
        return {"$or": ws_matches + [{"workspace_id": {"$exists": False}}, {"workspace_id": None}, {"workspace_id": ""}]}
    return {"$or": ws_matches}

async def task_workspace_match_clause(ws_id: str, is_default: bool = False) -> dict:
    """Matches tasks belonging to the workspace either directly by workspace_id or via their root_domain."""
    ws_c = workspace_match_clause(ws_id, is_default)
    try:
        ws_domains = await domains_col.distinct("domain", ws_c)
        if ws_domains:
            return {"$or": [ws_c, {"root_domain": {"$in": ws_domains}}]}
    except Exception:
        pass
    return ws_c

async def render_page(request: Request, template_name: str, context: dict, user: dict):
    active_ws = await get_active_workspace(user, request)
    active_ws_id = str(active_ws["_id"])
    is_default = bool(active_ws.get("is_default"))
    
    # Get all workspaces with domain count
    all_ws_cursor = workspaces_col.find({}).sort("name", 1)
    all_workspaces = []
    async for w in all_ws_cursor:
        w_id = str(w["_id"])
        w_is_def = bool(w.get("is_default"))
        dom_query = workspace_match_clause(w_id, w_is_def)
        dom_count = await domains_col.count_documents(dom_query)
        all_workspaces.append({
            "id": w_id,
            "name": w.get("name", "Unnamed"),
            "description": w.get("description", ""),
            "is_default": w_is_def,
            "is_active": (w_id == active_ws_id),
            "domains_count": dom_count
        })
        
    full_context = {
        "user": user,
        "active_workspace": {
            "id": active_ws_id,
            "name": active_ws.get("name", "Default Workspace"),
            "description": active_ws.get("description", ""),
            "is_default": is_default
        },
        "workspaces": all_workspaces,
        **context
    }
    response = templates.TemplateResponse(request, template_name, full_context)
    if request.cookies.get("active_workspace_id") != active_ws_id:
        response.set_cookie(key="active_workspace_id", value=active_ws_id, httponly=False, samesite="lax", max_age=86400*30)
    return response

# Workspace API Endpoints
@app.get("/api/workspaces")
async def list_workspaces(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    active_ws_id = str(active_ws["_id"])
    
    workspaces = []
    async for w in workspaces_col.find({}).sort("name", 1):
        w_id = str(w["_id"])
        w_is_def = bool(w.get("is_default"))
        dom_clause = workspace_match_clause(w_id, w_is_def)
        dom_count = await domains_col.count_documents(dom_clause)
        lead_clause = workspace_match_clause(w_id, w_is_def)
        lead_count = await leads_col.count_documents(lead_clause)
        
        workspaces.append({
            "id": w_id,
            "name": w.get("name", "Unnamed"),
            "description": w.get("description", ""),
            "is_default": w_is_def,
            "is_active": (w_id == active_ws_id),
            "created_at": w.get("created_at"),
            "created_by": w.get("created_by"),
            "domains_count": dom_count,
            "leads_count": lead_count,
            "default_scan_interval": w.get("default_scan_interval", 720),
            "scan_paused": bool(w.get("scan_paused", False)),
            "pause_reason": w.get("pause_reason", "")
        })
    return {"workspaces": workspaces, "active_workspace_id": active_ws_id}

@app.post("/api/workspaces")
async def create_workspace(
    request: Request,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            body = {}
    else:
        form = await request.form()
        body = dict(form)

    name_clean = str(body.get("name") or "").strip()
    description = str(body.get("description") or "").strip()

    if not name_clean:
        raise HTTPException(status_code=400, detail="Workspace name cannot be empty")
        
    existing = await workspaces_col.find_one({"name": {"$regex": f"^{re.escape(name_clean)}$", "$options": "i"}})
    if existing:
        raise HTTPException(status_code=400, detail="A workspace with this name already exists")
        
    default_scan_interval = body.get("default_scan_interval")
    try:
        default_scan_interval = int(default_scan_interval) if default_scan_interval is not None else 720
    except (ValueError, TypeError):
        default_scan_interval = 720

    ws_doc = {
        "name": name_clean,
        "description": description,
        "is_default": False,
        "default_scan_interval": default_scan_interval,
        "scan_paused": False,
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "created_by": user.get("username", "admin")
    }
    res = await workspaces_col.insert_one(ws_doc)
    ws_id = str(res.inserted_id)
    
    await users_col.update_one({"_id": user["_id"]}, {"$set": {"active_workspace_id": ws_id}})
    await log_audit(user["username"], "CREATE_WORKSPACE", f"Created workspace: {name_clean} (ID: {ws_id})", request)
    
    from fastapi.responses import JSONResponse
    resp = JSONResponse(content={
        "status": "success",
        "workspace_id": ws_id,
        "workspace": {
            "id": ws_id,
            "name": name_clean,
            "description": description,
            "is_default": False
        }
    })
    resp.set_cookie(key="active_workspace_id", value=ws_id, httponly=False, samesite="lax", max_age=86400*30)
    return resp

@app.post("/api/workspaces/{workspace_id}/switch")
async def switch_workspace(
    workspace_id: str,
    request: Request,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
        
    try:
        ws = await workspaces_col.find_one({"_id": ObjectId(workspace_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid workspace ID")
        
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
        
    ws_id_str = str(ws["_id"])
    await users_col.update_one({"_id": user["_id"]}, {"$set": {"active_workspace_id": ws_id_str}})
    
    from fastapi.responses import JSONResponse
    resp = JSONResponse(content={"status": "success", "workspace_id": ws_id_str, "name": ws.get("name")})
    resp.set_cookie(key="active_workspace_id", value=ws_id_str, httponly=False, samesite="lax", max_age=86400*30)
    return resp

@app.put("/api/workspaces/{workspace_id}")
async def update_workspace(
    workspace_id: str,
    request: Request,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            body = {}
    else:
        form = await request.form()
        body = dict(form)

    name_clean = str(body.get("name") or "").strip()
    description = str(body.get("description") or "").strip()

    if not name_clean:
        raise HTTPException(status_code=400, detail="Workspace name cannot be empty")
        
    try:
        ws = await workspaces_col.find_one({"_id": ObjectId(workspace_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid workspace ID")
        
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
        
    existing = await workspaces_col.find_one({
        "_id": {"$ne": ObjectId(workspace_id)},
        "name": {"$regex": f"^{re.escape(name_clean)}$", "$options": "i"}
    })
    if existing:
        raise HTTPException(status_code=400, detail="Another workspace with this name already exists")
        
    update_fields = {
        "name": name_clean,
        "description": description,
        "updated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    if "default_scan_interval" in body:
        try:
            update_fields["default_scan_interval"] = int(body["default_scan_interval"])
        except (ValueError, TypeError):
            pass
    if "scan_paused" in body:
        update_fields["scan_paused"] = bool(body["scan_paused"])
        if not update_fields["scan_paused"]:
            update_fields["pause_reason"] = ""

    await workspaces_col.update_one(
        {"_id": ObjectId(workspace_id)},
        {"$set": update_fields}
    )
    await log_audit(user["username"], "UPDATE_WORKSPACE", f"Updated workspace: {name_clean} (ID: {workspace_id})", request)
    return {
        "status": "success",
        "workspace": {
            "id": workspace_id,
            "name": name_clean,
            "description": description,
            "default_scan_interval": update_fields.get("default_scan_interval", ws.get("default_scan_interval", 720)),
            "scan_paused": update_fields.get("scan_paused", ws.get("scan_paused", False))
        }
    }

@app.delete("/api/workspaces/{workspace_id}")
async def delete_workspace(
    workspace_id: str,
    request: Request,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    try:
        ws = await workspaces_col.find_one({"_id": ObjectId(workspace_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid workspace ID")
        
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
        
    total_ws = await workspaces_col.count_documents({})
    if total_ws <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the only workspace. Create another workspace first.")
        
    ws_id_str = str(ws["_id"])
    ws_name = ws.get("name", "Workspace")
    is_default = bool(ws.get("is_default"))
    
    # Cascade delete all data belonging to this workspace
    dom_clause = workspace_match_clause(ws_id_str, is_default)
    del_dom_res = await domains_col.delete_many(dom_clause)
    del_leads_res = await leads_col.delete_many(workspace_match_clause(ws_id_str, is_default))
    del_tasks_res = await tasks_col.delete_many(workspace_match_clause(ws_id_str, is_default))
    del_findings_res = await findings_col.delete_many(workspace_match_clause(ws_id_str, is_default))
    del_sm_res = await source_maps_col.delete_many(workspace_match_clause(ws_id_str, is_default))
    
    # Delete workspace
    await workspaces_col.delete_one({"_id": ObjectId(workspace_id)})
    
    # If the deleted workspace was default, designate another workspace as default
    if is_default:
        next_ws = await workspaces_col.find_one({})
        if next_ws:
            await workspaces_col.update_one({"_id": next_ws["_id"]}, {"$set": {"is_default": True}})
            
    # Resolve active workspace for current user
    new_active_ws = await get_or_create_default_workspace()
    new_active_id = str(new_active_ws["_id"])
    await users_col.update_one({"_id": user["_id"]}, {"$set": {"active_workspace_id": new_active_id}})
    
    await log_audit(
        user["username"], 
        "DELETE_WORKSPACE", 
        f"Deleted workspace: {ws_name} (ID: {workspace_id}). Cascade deleted {del_dom_res.deleted_count} domains, {del_leads_res.deleted_count} leads, {del_tasks_res.deleted_count} tasks, {del_findings_res.deleted_count} findings, {del_sm_res.deleted_count} source maps.",
        request
    )
    
    from fastapi.responses import JSONResponse
    resp = JSONResponse(content={
        "status": "success",
        "message": f"Workspace '{ws_name}' and all associated data deleted",
        "deleted_domains": del_dom_res.deleted_count,
        "deleted_leads": del_leads_res.deleted_count,
        "deleted_tasks": del_tasks_res.deleted_count,
        "deleted_findings": del_findings_res.deleted_count,
        "new_active_workspace_id": new_active_id
    })
    resp.set_cookie(key="active_workspace_id", value=new_active_id, httponly=False, samesite="lax", max_age=86400*30)
    return resp


@app.get("/api/admin/users")
async def get_users(request: Request, page: int = 1, limit: int = 10, q: Optional[str] = None, user: dict = Depends(get_current_user)):
    check_admin(user)
    
    query = {}
    if q:
        query = {"username": {"$regex": re.escape(q), "$options": "i"}}
    
    total = await users_col.count_documents(query)
    cursor = users_col.find(query).skip((page - 1) * limit).limit(limit)
    users = await cursor.to_list(length=limit)
    
    for u in users:
        u["_id"] = str(u["_id"])
        u.pop("hashed_password", None)
        u.pop("totp_secret", None)
        # Migration fallback
        if "role" not in u:
            u["role"] = "admin" if u.get("is_admin") else "viewer"
        
    return {"users": users, "total": total, "page": page, "limit": limit}

@app.get("/api/admin/logs")
async def get_logs(request: Request, page: int = 1, limit: int = 20, q: Optional[str] = None, user: dict = Depends(get_current_user)):
    check_admin(user)
    
    query = {}
    if q:
        safe_q = re.escape(q)
        query = {"$or": [
            {"username": {"$regex": safe_q, "$options": "i"}},
            {"action": {"$regex": safe_q, "$options": "i"}},
            {"details": {"$regex": safe_q, "$options": "i"}}
        ]}
    
    total = await audit_logs_col.count_documents(query)
    cursor = audit_logs_col.find(query).sort("timestamp", -1).skip((page - 1) * limit).limit(limit)
    logs = await cursor.to_list(length=limit)
    
    for l in logs:
        l["_id"] = str(l["_id"])
        
    return {"logs": logs, "total": total, "page": page, "limit": limit}

async def log_audit(username: str, action: str, details: str, request: Request):
    audit_entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "username": username,
        "action": action,
        "details": details,
        "ip_address": request.client.host
    }
    await audit_logs_col.insert_one(audit_entry)

# --- Routes ---

@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
async def root(request: Request, user: Optional[dict] = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, "login.html")

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, username: str = Form(...), password: str = Form(...), totp_code: Optional[str] = Form(None)):
    user = await users_col.find_one({"username": username})
    
    if not user:
        await log_audit(username, "login_failed", "User not found", request)
        return templates.TemplateResponse(request, "login.html", {"error": "Invalid credentials"})
    
    # Check Lockout
    lockout_until = user.get("lockout_until")
    if lockout_until:
        lockout_time = datetime.fromisoformat(lockout_until.replace("Z", "+00:00"))
        if datetime.utcnow().replace(tzinfo=None) < lockout_time.replace(tzinfo=None):
            await log_audit(username, "login_failed", "Account locked", request)
            return templates.TemplateResponse(request, "login.html", {"error": "Account temporarily locked due to multiple failed attempts. Try again later."})

    if user.get("disabled", False):
        await log_audit(username, "login_failed", "Account disabled", request)
        return templates.TemplateResponse(request, "login.html", {"error": "Account disabled. Contact administrator."})

    if not verify_password(password, user["hashed_password"]):
        failed_attempts = user.get("failed_attempts", 0) + 1
        update_data = {"failed_attempts": failed_attempts}
        if failed_attempts >= 5:
            lockout_time = (datetime.utcnow() + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
            update_data["lockout_until"] = lockout_time
            update_data["failed_attempts"] = 0 # Reset but keep locked
            
        await users_col.update_one({"username": username}, {"$set": update_data})
        await log_audit(username, "login_failed", f"Invalid password (Attempt {failed_attempts})", request)
        return templates.TemplateResponse(request, "login.html", {"error": "Invalid credentials"})
    
    if not DISABLE_2FA:
        if not totp_code or not verify_totp(user.get("totp_secret", ""), totp_code):
            await log_audit(username, "login_failed", "Invalid TOTP code", request)
            return templates.TemplateResponse(request, "login.html", {"error": "Invalid TOTP code"})
    
    # Success: Reset attempts and lockout
    await users_col.update_one({"username": username}, {"$set": {"failed_attempts": 0, "lockout_until": None}})
    
    access_token = create_access_token(data={"sub": username})
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    is_secure = request.url.scheme == "https"
    # Set cookie max_age to match ACCESS_TOKEN_EXPIRE_MINUTES (12 hours)
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True, 
        secure=is_secure, 
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    await log_audit(username, "login_success", "User logged in", request)
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    embedded = request.query_params.get("embedded") == "1"
    return await render_page(request, "dashboard.html", {"embedded": embedded}, user)

@app.get("/search")
async def search(request: Request, q: str, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))

    def scoped_query(criterion: dict) -> dict:
        if ws_clause:
            return {"$and": [ws_clause, criterion]}
        return criterion

    # Clean query
    raw_q = q.strip()
    q = raw_q.lower()
    clean_q = re.sub(r'^https?://', '', q).split('/')[0].split(':')[0].strip()
    
    query_variants = list(dict.fromkeys([q, clean_q, raw_q]))

    # 1. Try exact domain match
    domain_data = await domains_col.find_one(scoped_query({"domain": {"$in": query_variants}}))
    
    # 2. Try exact subdomain match across all collections/arrays
    if not domain_data:
        domain_data = await domains_col.find_one(scoped_query({"infrastructure.subdomains.name": {"$in": query_variants}}))
    if not domain_data:
        domain_data = await domains_col.find_one(scoped_query({"systems.target": {"$in": query_variants}}))
    if not domain_data:
        domain_data = await domains_col.find_one(scoped_query({"web_applications.target": {"$in": query_variants}}))
    if not domain_data:
        domain_data = await domains_col.find_one(scoped_query({"subdomains.subdomain": {"$in": query_variants}}))
    if not domain_data:
        domain_data = await domains_col.find_one(scoped_query({"infrastructure.subdomains.ip": {"$in": query_variants}}))
    if not domain_data:
        domain_data = await domains_col.find_one(scoped_query({"systems.ip": {"$in": query_variants}}))
    
    # 3. Fallback to partial match on domain
    if not domain_data:
        domain_data = await domains_col.find_one(scoped_query({"domain": {"$regex": re.escape(clean_q or q), "$options": "i"}}))
    
    if not domain_data:
        return {"error": f"Domain '{raw_q}' not found"}
    
    await log_audit(user["username"], "query", f"Searched for domain: {q}", request)
    
    # Get stats for this domain
    domain_name = domain_data["domain"]
    
    # Collect targets for stats calculation
    if q and q.lower().strip() != domain_name.lower().strip():
        # Scoped specifically to the subdomain being viewed
        sub_ips = [
            sub["ip"] for sub in (domain_data.get("infrastructure", {}).get("subdomains") or [])
            if sub.get("name", "").lower() == q.lower().strip() and sub.get("ip")
        ]
        target_cond = [
            {"target": {"$regex": f"^{re.escape(q.strip())}(?::\\d+)?$", "$options": "i"}},
            {"target": {"$regex": f"^https?://{re.escape(q.strip())}(?::\\d+)?(?:/.*)?$", "$options": "i"}}
        ]
        if sub_ips:
            target_cond.append({"target": {"$in": sub_ips}})
        target_filter = {"$or": target_cond}
        
        stats = {
            "open_alerts": await leads_col.count_documents({"$and": [target_filter, {"status": {"$in": ["new", "in_progress"]}}]}),
            "true_positives": await leads_col.count_documents({"$and": [target_filter, {"status": "true_positive"}]}),
            "false_positives": await leads_col.count_documents({"$and": [target_filter, {"status": "false_positive"}]})
        }
    else:
        # Collect all possible targets for this domain (subdomains and IPs)
        targets = [domain_name]
        if domain_data.get("infrastructure") and domain_data["infrastructure"].get("subdomains"):
            for sub in domain_data["infrastructure"]["subdomains"]:
                if sub.get("name"): targets.append(sub["name"])
                if sub.get("ip"): targets.append(sub["ip"])
        
        stats = {
            "open_alerts": await leads_col.count_documents({"target": {"$in": targets}, "status": {"$in": ["new", "in_progress"]}}),
            "true_positives": await leads_col.count_documents({"target": {"$in": targets}, "status": "true_positive"}),
            "false_positives": await leads_col.count_documents({"target": {"$in": targets}, "status": "false_positive"})
        }
    
    domain_data["_id"] = str(domain_data["_id"])
    domain_data["target_query"] = q
    domain_data["stats"] = stats
    
    # Filter systems and web_applications to only show data for the specific target (q)
    # if the user is looking at a subdomain.
    if q != domain_name:
        # Load subdomain-specific summaries if they exist
        if domain_data.get("subdomain_summaries"):
            sub_key = q.replace('.', '_DOT_')
            sub_analysis = domain_data["subdomain_summaries"].get(sub_key)
            if sub_analysis:
                domain_data["summary"] = sub_analysis.get("summary")
                domain_data["exploit_summary"] = sub_analysis.get("exploit_summary")

        if domain_data.get("systems"):
            # Only show latest and previous scan results for the target
            target_systems = [s for s in domain_data["systems"] if s.get("target") == q]
            domain_data["systems"] = list(reversed(target_systems))[:2]
        if domain_data.get("web_applications"):
            domain_data["web_applications"] = [w for w in domain_data["web_applications"] if w.get("target") == q]

        # Scope WAF and Load Balancer to the specific subdomain being inspected
        sub_obj = None
        for s in (domain_data.get("infrastructure", {}).get("subdomains") or []):
            if s.get("name", "").lower().strip() == q.lower().strip():
                sub_obj = s
                break
        matching_app = next((w for w in (domain_data.get("web_applications") or []) if w.get("target") == q), None)

        if "infrastructure" in domain_data:
            orig_waf = domain_data["infrastructure"].get("waf")
            orig_lb = domain_data["infrastructure"].get("load_balancer")
            domain_data["infrastructure"]["root_waf"] = orig_waf
            domain_data["infrastructure"]["root_load_balancer"] = orig_lb
            domain_data["root_waf"] = orig_waf
            domain_data["root_load_balancer"] = orig_lb

            domain_data["infrastructure"]["waf"] = (
                (sub_obj and sub_obj.get("waf")) or
                (matching_app and matching_app.get("waf")) or
                None
            )
            domain_data["infrastructure"]["load_balancer"] = (
                (sub_obj and sub_obj.get("load_balancer")) or
                (matching_app and matching_app.get("load_balancer")) or
                None
            )
    else:
        # If looking at root domain, only show systems/webapps for the root domain itself
        if domain_data.get("systems"):
            # Only show latest and previous scan results for the root domain
            root_systems = [s for s in domain_data["systems"] if s.get("target") == domain_name]
            domain_data["systems"] = list(reversed(root_systems))[:2]
        if domain_data.get("web_applications"):
            domain_data["web_applications"] = [w for w in domain_data["web_applications"] if w.get("target") == domain_name]

    # Ensure infrastructure and cloud_footprint are populated and properly scoped
    if "infrastructure" not in domain_data or not isinstance(domain_data["infrastructure"], dict):
        domain_data["infrastructure"] = {}

    target_lower = (q or domain_name).lower().strip()
    is_root_view = (target_lower == domain_name.lower().strip())

    cf = domain_data["infrastructure"].get("cloud_footprint") or {}
    
    # If this document has no cloud_footprint (e.g. it's a subdomain doc), try finding parent root domain's cloud_footprint
    has_any_buckets = any(cf.get(k) for k in ["s3_buckets", "azure_blobs", "gcp_buckets", "other_buckets"])
    if not has_any_buckets:
        parent_doc = await domains_col.find_one({"infrastructure.subdomains.name": target_lower}, {"infrastructure.cloud_footprint": 1})
        if not parent_doc and not is_root_view:
            parent_doc = await domains_col.find_one({"domain": domain_name}, {"infrastructure.cloud_footprint": 1})
        if parent_doc and parent_doc.get("infrastructure", {}).get("cloud_footprint"):
            cf = parent_doc["infrastructure"]["cloud_footprint"]

    # Also merge any osint.cloud_assets if present
    osint_assets = domain_data.get("osint", {}).get("cloud_assets") or []
    for asset in osint_assets:
        if isinstance(asset, dict):
            p = asset.get("provider", "AWS S3")
            status = "open" if asset.get("risk") == "Critical" or "open" in asset.get("status", "").lower() else "secured"
            actual_source = (asset.get("source_app") or domain_name).lower().strip()
            b_obj = {
                "name": asset.get("name") or asset.get("url"),
                "raw": asset.get("name") or asset.get("url"),
                "url": asset.get("url"),
                "provider": p,
                "status": status,
                "http_status": 200 if status == "open" else 403,
                "details": f"{p} bucket ({status})",
                "source_app": actual_source,
                "discovered_by": "osint_agent"
            }
            cat = "s3_buckets" if "s3" in p.lower() else ("gcp_buckets" if "google" in p.lower() or "gcp" in p.lower() else "other_buckets")
            if cat not in cf: cf[cat] = []
            cf[cat].append(b_obj)

    scoped_cf = {}
    for bucket_key in ["s3_buckets", "azure_blobs", "gcp_buckets", "other_buckets"]:
        items = cf.get(bucket_key) or []
        seen_urls = set()
        filtered = []
        for b in items:
            if not isinstance(b, dict):
                continue
            src = (b.get("source_app") or domain_name).lower().strip()
            # If viewing root domain: show all buckets in the domain's entire footprint
            # If viewing a specific subdomain: ONLY show buckets explicitly detected on this subdomain
            if not is_root_view:
                if src != target_lower:
                    continue
            url = (b.get("url") or b.get("raw") or b.get("name") or "").strip().lower().rstrip("/")
            if url and url not in seen_urls:
                seen_urls.add(url)
                filtered.append(b)
        scoped_cf[bucket_key] = filtered
    domain_data["infrastructure"]["cloud_footprint"] = scoped_cf

    # Scope OSINT cloud assets when viewing a specific subdomain
    if "osint" in domain_data and isinstance(domain_data["osint"], dict):
        raw_osint_cloud = domain_data["osint"].get("cloud_assets") or []
        if not is_root_view:
            filtered_osint = [
                c for c in raw_osint_cloud
                if isinstance(c, dict) and (c.get("source_app") or domain_name).lower().strip() == target_lower
            ]
            domain_data["osint"]["cloud_assets"] = filtered_osint
            domain_data["osint"]["cloud_assets_count"] = len(filtered_osint)

    # Ensure DNS records, ASN data, API specifications, and History are populated
    if not is_root_view:
        for s in (domain_data.get("infrastructure", {}).get("subdomains") or []):
            if isinstance(s, dict) and s.get("name", "").lower().strip() == target_lower:
                domain_data["current_subdomain"] = s
                break

    # Sort history latest first for timeline rendering
    if domain_data.get("history") and isinstance(domain_data["history"], list):
        all_sorted = sorted(
            domain_data["history"],
            key=lambda x: str(x.get("timestamp", "")),
            reverse=True
        )
        domain_data["perimeter_history"] = all_sorted[:150]
        domain_data["is_subdomain_view"] = not is_root_view

        if not is_root_view:
            sub_ips = set()
            for sub in (domain_data.get("infrastructure", {}).get("subdomains") or []):
                if isinstance(sub, dict) and sub.get("name", "").lower().strip() == target_lower:
                    if sub.get("ip"):
                        if isinstance(sub["ip"], list):
                            for ip in sub["ip"]:
                                if ip:
                                    sub_ips.add(str(ip).lower().strip())
                        else:
                            sub_ips.add(str(sub["ip"]).lower().strip())
                    if sub.get("ips") and isinstance(sub["ips"], list):
                        for ip in sub["ips"]:
                            if ip:
                                sub_ips.add(str(ip).lower().strip())

            def is_sub_match(ev):
                if not isinstance(ev, dict):
                    return False
                ev_target = str(ev.get("target") or "").lower().strip()
                clean_ev = re.sub(r'^https?://', '', ev_target).split('/')[0].split(':')[0].strip()
                return (
                    clean_ev == target_lower or
                    clean_ev == clean_q or
                    ev_target == target_lower or
                    (clean_ev in sub_ips if sub_ips else False) or
                    (ev_target in sub_ips if sub_ips else False)
                )

            domain_data["history"] = [ev for ev in all_sorted if is_sub_match(ev)][:150]
        else:
            domain_data["history"] = all_sorted[:150]
        
    return domain_data

@app.get("/api/suggestions")
async def get_suggestions(request: Request, q: str, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    if len(q) < 2:
        return []
    
    active_ws = await get_active_workspace(user, request)
    ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))
    query = {"domain": {"$regex": re.escape(q), "$options": "i"}}
    if ws_clause:
        query = {"$and": [ws_clause, query]}

    # Find up to 5 domains containing 'q' (case-insensitive)
    cursor = domains_col.find(query, {"domain": 1}).limit(5)
    results = await cursor.to_list(length=5)
    return [r["domain"] for r in results]

import sqlite3
from functools import lru_cache

GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "geoip.sqlite")
_geoip_conn = None

def get_geoip_conn():
    global _geoip_conn
    if _geoip_conn is None and os.path.exists(GEOIP_DB_PATH):
        try:
            _geoip_conn = sqlite3.connect(f"file:{GEOIP_DB_PATH}?mode=ro", uri=True, check_same_thread=False)
        except Exception:
            _geoip_conn = None
    return _geoip_conn

CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

@lru_cache(maxsize=4096)
def get_country_code(ip: str) -> str:
    """Resolve accurate country code for an IP address using local GeoIP database."""
    if not ip or ip == "N/A":
        return "UNKNOWN"
    try:
        ip_clean = str(ip).strip()
        if ":" in ip_clean and not ip_clean.startswith("["):
            ip_clean = ip_clean.split(":")[0]
            
        ip_obj = ipaddress.ip_address(ip_clean)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or (ip_obj in CGNAT_NET):
            return "PRIVATE"
            
        conn = get_geoip_conn()
        if conn and isinstance(ip_obj, ipaddress.IPv4Address):
            num = int(ip_obj)
            res = conn.execute(
                "SELECT country, end_ip FROM geoip WHERE start_ip <= ? ORDER BY start_ip DESC LIMIT 1",
                (num,)
            ).fetchone()
            if res and num <= res[1]:
                return res[0].upper()
    except Exception:
        pass
    return "UNKNOWN"

@app.get("/api/filters/options")
async def get_filter_options(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))
    filter_query = ws_clause if ws_clause else None

    # 1. Distinct technologies
    raw_techs = await domains_col.distinct("web_applications.tech_stack", filter=filter_query)
    techs = sorted(list(set([t.strip() for t in raw_techs if t and isinstance(t, str) and t.strip()])), key=lambda s: s.lower())

    # 2. Distinct WAFs
    wafs_infra = await domains_col.distinct("infrastructure.waf.firewall", filter=filter_query)
    wafs_web = await domains_col.distinct("web_applications.waf.firewall", filter=filter_query)
    all_wafs = sorted(list(set([
        w.strip() for w in (wafs_infra + wafs_web)
        if w and isinstance(w, str) and w.strip().lower() not in ["none", "null", "false"]
    ])), key=lambda s: s.lower())

    # 3. Distinct LB methods
    lbs_infra = await domains_col.distinct("infrastructure.load_balancer.method", filter=filter_query)
    lbs_web = await domains_col.distinct("web_applications.load_balancer.method", filter=filter_query)
    all_lbs = sorted(list(set([
        l.strip() for l in (lbs_infra + lbs_web)
        if l and isinstance(l, str) and l.strip().lower() not in ["none", "null", "false"]
    ])), key=lambda s: s.lower())

    # 4. Distinct Discovered IPs
    ips_systems = await domains_col.distinct("systems.ip", filter=filter_query)
    ips_sub_ip = await domains_col.distinct("infrastructure.subdomains.ip", filter=filter_query)
    ips_sub_ips = await domains_col.distinct("infrastructure.subdomains.ips", filter=filter_query)
    
    all_raw_ips = set()
    for ip_val in (ips_systems + ips_sub_ip + ips_sub_ips):
        if not ip_val:
            continue
        if isinstance(ip_val, list):
            for sub_val in ip_val:
                if sub_val and isinstance(sub_val, str) and sub_val.strip() and sub_val.strip().lower() not in ["n/a", "none", "null"]:
                    all_raw_ips.add(sub_val.strip())
        elif isinstance(ip_val, str) and ip_val.strip() and ip_val.strip().lower() not in ["n/a", "none", "null"]:
            all_raw_ips.add(ip_val.strip())
            
    def parse_ip_sort_key(ip_str):
        try:
            return (0, ipaddress.ip_address(ip_str))
        except ValueError:
            return (1, ip_str)

    sorted_ips = sorted(list(all_raw_ips), key=parse_ip_sort_key)

    return {
        "status": "success",
        "technologies": techs,
        "wafs": all_wafs,
        "load_balancers": all_lbs,
        "ips": sorted_ips
    }

@app.get("/api/subdomains")
async def get_subdomains(
    request: Request,
    page: int = 1,
    limit: int = 20,
    q: Optional[str] = None,
    status_val: Optional[str] = None,
    has_subdomains: Optional[str] = None,
    tech: Optional[str] = None,
    port: Optional[int] = None,
    waf: Optional[str] = None,
    lb: Optional[str] = None,
    ip: Optional[str] = None,
    mutator: Optional[str] = None,
    api_routes: Optional[str] = None,
    cloud_assets: Optional[str] = None,
    secrets: Optional[str] = None,
    jwt: Optional[str] = None,
    base64: Optional[str] = None,
    alive_apps: Optional[str] = None,
    historical: Optional[str] = None,
    takeover: Optional[str] = None,
    hide_parked: Optional[str] = None,
    api_spec: Optional[str] = None,
    drift: Optional[str] = None,
    sort_by: str = "domain",
    sort_dir: str = "asc",
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)

    active_ws = await get_active_workspace(user, request)
    ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))

    root_query = get_query_filters(q, status_val, has_subdomains, tech, None, port, ws_clause=ws_clause)
    pipeline = get_flattened_pipeline(
        root_query,
        q,
        status_val,
        tech,
        port,
        waf,
        lb,
        mutator=mutator,
        ip=ip,
        api_routes=api_routes,
        cloud_assets=cloud_assets,
        secrets=secrets,
        jwt=jwt,
        base64=base64,
        alive_apps=alive_apps,
        historical=historical,
        takeover=takeover,
        hide_parked=hide_parked,
        api_spec=api_spec,
        drift=drift
    )
    
    # Total count (Aggregation)
    count_pipeline = pipeline + [{"$count": "total"}]
    count_result = await domains_col.aggregate(count_pipeline).to_list(length=1)
    total = count_result[0]["total"] if count_result else 0
    
    # Sorting and Pagination
    sort_dir_num = 1 if sort_dir == "asc" else -1
    sort_field = "domain"
    if sort_by == "status":
        sort_field = "scanned_flag"
    
    pipeline.append({"$sort": {sort_field: sort_dir_num}})
    pipeline.append({"$skip": (page - 1) * limit})
    pipeline.append({"$limit": limit})

    try:
        cursor = domains_col.aggregate(pipeline)
        docs = await cursor.to_list(length=limit)
        print(f"DEBUG: assets endpoint returning {len(docs)} assets for query {root_query}")
    except Exception as e:
        print(f"ERROR: Aggregation failed: {e}")
        return {"subdomains": [], "total": 0, "error": str(e)}
    
    results = []
    for d in docs:
        system_info = d.get("system") or {}
        web_app_info = d.get("web_app") or {}
        waf_info = d.get("waf") or {}
        lb_info = d.get("load_balancer") or {}
        target_ips = [t for t in d.get("target_ips", []) if t]
        
        if ip and ip.strip() in target_ips:
            resolved_ip = ip.strip()
        elif q and any(q.strip().lower() in t.lower() for t in target_ips):
            matching_ips = [t for t in target_ips if q.strip().lower() in t.lower()]
            resolved_ip = matching_ips[0]
        elif system_info.get("ip"):
            resolved_ip = system_info.get("ip")
        elif target_ips:
            resolved_ip = target_ips[0]
        else:
            resolved_ip = "N/A"
            
        tech_stack = web_app_info.get("tech_stack", [])
        
        # Determine scanned status: 
        # If we have system info or subdomain_scanned flag, it's scanned. Fallback to root's scanned_flag.
        is_scanned = True if (d.get("system") or d.get("subdomain_scanned")) else (d.get("scanned_flag", False) if d.get("is_root") else False)
        is_permutated = False
        sub_drift_count = int(d.get("subdomain_drift_count", 0))
        latest_drift_time = d.get("latest_subdomain_drift_time")
        
        results.append({
            "id": str(d["_id"]),
            "domain": d["domain"],
            "ip": resolved_ip,
            "scanned": is_scanned,
            "subdomain_count": d.get("subdomain_count", 0) if d.get("is_root") else 0,
            "technologies": tech_stack[:5],
            "tech_str": ", ".join(tech_stack),
            "country_id": get_country_code(resolved_ip),
            "recon_date": d.get("recon_date", "N/A"),
            "last_scanned": system_info.get("last_scanned", "Never"),
            "source": d.get("source"),
            "is_permutated": is_permutated,
            "waf": {
                "detected": waf_info.get("detected", False),
                "firewall": waf_info.get("firewall"),
                "fqdns": waf_info.get("fqdns", [])
            } if waf_info.get("detected") else None,
            "load_balancer": {
                "detected": lb_info.get("detected", False),
                "method": lb_info.get("method"),
                "fqdns": lb_info.get("fqdns", [])
            } if lb_info.get("detected") else None,
            "has_api_routes": bool(d.get("has_api_routes", False)),
            "has_cloud_assets": bool(d.get("has_cloud_assets", False)),
            "has_secrets": bool(d.get("has_secrets", False)),
            "has_jwt": bool(d.get("has_jwt", False)),
            "has_base64": bool(d.get("has_base64", False)),
            "has_alive_web_app": bool(d.get("has_alive_web_app", False)),
            "has_historical_urls": bool(d.get("has_historical_urls", False)),
            "asn": d.get("asn"),
            "as_org": d.get("as_org"),
            "cidr": d.get("cidr"),
            "ptr": d.get("ptr"),
            "dangling_takeover": bool(d.get("dangling_takeover", False)),
            "cname": d.get("cname"),
            "takeover_provider": d.get("takeover_provider"),
            "has_api_specs": bool(d.get("has_api_specs", False)),
            "has_graphql": bool(d.get("has_graphql", False)),
            "subdomain_drift_count": sub_drift_count,
            "latest_subdomain_drift_time": latest_drift_time,
            "has_subdomain_drift": sub_drift_count > 0
        })

    # Calculate total scanned assets for this workspace (root + subdomains)
    scanned_root = {"blacklisted": {"$ne": True}}
    if ws_clause:
        scanned_root = {"$and": [ws_clause, scanned_root]}
    scanned_pipeline = get_flattened_pipeline(scanned_root, status_val="scanned")
    scanned_pipeline.append({"$count": "total"})
    scanned_result = await domains_col.aggregate(scanned_pipeline).to_list(length=1)
    scanned_total = scanned_result[0]["total"] if scanned_result else 0
    
    return {"subdomains": results, "total": total, "scanned_total": scanned_total, "page": page, "limit": limit}

@app.get("/api/subdomains/export")
async def export_subdomains(
    request: Request,
    q: Optional[str] = None,
    status_val: Optional[str] = None,
    has_subdomains: Optional[str] = None,
    tech: Optional[str] = None,
    port: Optional[int] = None,
    waf: Optional[str] = None,
    lb: Optional[str] = None,
    ip: Optional[str] = None,
    mutator: Optional[str] = None,
    api_routes: Optional[str] = None,
    cloud_assets: Optional[str] = None,
    secrets: Optional[str] = None,
    jwt: Optional[str] = None,
    base64: Optional[str] = None,
    alive_apps: Optional[str] = None,
    historical: Optional[str] = None,
    drift: Optional[str] = None,
    sort_by: str = "domain",
    sort_dir: str = "asc",
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))

    root_query = get_query_filters(q, status_val, has_subdomains, tech, None, port, ws_clause=ws_clause)
    pipeline = get_flattened_pipeline(
        root_query,
        q,
        status_val,
        tech,
        port,
        waf,
        lb,
        mutator=mutator,
        ip=ip,
        api_routes=api_routes,
        cloud_assets=cloud_assets,
        secrets=secrets,
        jwt=jwt,
        base64=base64,
        alive_apps=alive_apps,
        historical=historical,
        drift=drift
    )
    
    # Sorting
    sort_dir_num = 1 if sort_dir == "asc" else -1
    sort_field = "domain"
    if sort_by == "status": sort_field = "scanned_flag"
    pipeline.append({"$sort": {sort_field: sort_dir_num}})
    
    cursor = domains_col.aggregate(pipeline)
    docs = await cursor.to_list(length=5000) # Higher limit for export
    
    data = []
    for d in docs:
        system_info = d.get("system") or {}
        web_app_info = d.get("web_app") or {}
        target_ips = [t for t in d.get("target_ips", []) if t]
        
        if ip and ip.strip() in target_ips:
            resolved_ip = ip.strip()
        elif q and any(q.strip().lower() in t.lower() for t in target_ips):
            matching_ips = [t for t in target_ips if q.strip().lower() in t.lower()]
            resolved_ip = matching_ips[0]
        elif system_info.get("ip"):
            resolved_ip = system_info.get("ip")
        elif target_ips:
            resolved_ip = target_ips[0]
        else:
            resolved_ip = "N/A"
            
        tech_stack = web_app_info.get("tech_stack", [])
        is_scanned = True if (d.get("system") or d.get("subdomain_scanned")) else (d.get("scanned_flag", False) if d.get("is_root") else False)
        
        data.append({
            "Domain": d["domain"],
            "Status": "Scanned" if is_scanned else "Pending",
            "IP Address": resolved_ip,
            "Country": get_country_code(resolved_ip),
            "Type": "Root" if d.get("is_root") else "Subdomain",
            "Technologies": ", ".join(tech_stack),
            "Alive Web App": "Yes" if d.get("has_alive_web_app") else "No",
            "API Routes": "Yes" if d.get("has_api_routes") else "No",
            "Cloud Assets": "Yes" if d.get("has_cloud_assets") else "No",
            "Secrets/Tokens": "Yes" if d.get("has_secrets") else "No",
            "JWT Tokens": "Yes" if d.get("has_jwt") else "No",
            "Base64 Strings": "Yes" if d.get("has_base64") else "No",
            "Historical URLs": "Yes" if d.get("has_historical_urls") else "No",
            "Added At": d.get("recon_date", "N/A")
        })
    
    if not data:
        df = pd.DataFrame(columns=["Domain", "Status", "IP Address", "Country", "Type", "Technologies", "Added At"])
    else:
        df = pd.DataFrame(data)
        
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Target Inventory')
    
    output.seek(0)
    
    headers = {
        'Content-Disposition': f'attachment; filename="target_inventory_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx"'
    }
    return StreamingResponse(output, headers=headers, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.get("/api/domains/{domain_id}/archive-urls/export")
async def export_archive_urls(
    domain_id: str,
    category: Optional[str] = None,
    target: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    try:
        domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid domain ID")
        
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    archive_urls = domain_doc.get("archive_urls", {})
    domain = domain_doc.get("domain", "domain")
    
    urls_to_export = []
    if category in ["wordlist", "parameters", "mined_parameters"]:
        target_clean = (target or "").lower().strip()
        wordlist = []
        if target_clean and archive_urls.get("by_subdomain", {}).get(target_clean, {}).get("mined_parameters"):
            wordlist = archive_urls["by_subdomain"][target_clean]["mined_parameters"]
        if not wordlist:
            wordlist = archive_urls.get("mined_parameters", {}).get("wordlist") or domain_doc.get("osint", {}).get("parameter_wordlist") or []
        content_str = "\n".join(sorted(list(set(wordlist))))
        file_prefix = target_clean or domain
        filename = f"{file_prefix}_parameter_wordlist.txt"
        return StreamingResponse(
            io.StringIO(content_str),
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    elif category in ["sensitive", "sensitive_files"]:
        urls_to_export = [item.get("url") for item in archive_urls.get("sensitive_files", []) if item.get("url")]
    elif category in ["api", "api_endpoints"]:
        urls_to_export = [item.get("url") for item in archive_urls.get("api_endpoints", []) if item.get("url")]
    elif category in ["params", "interesting_params"]:
        urls_to_export = [item.get("url") for item in archive_urls.get("interesting_params", []) if item.get("url")]
    elif category in ["docs", "documents"]:
        urls_to_export = [item.get("url") for item in archive_urls.get("documents", []) if item.get("url")]
    elif category in ["other", "other_endpoints"]:
        urls_to_export = [u if isinstance(u, str) else u.get("url") for u in archive_urls.get("other_endpoints", []) if u]
    else:
        for k in ["sensitive_files", "api_endpoints", "interesting_params", "documents"]:
            for item in archive_urls.get(k, []):
                if isinstance(item, dict) and item.get("url"):
                    urls_to_export.append(item.get("url"))
        for u in archive_urls.get("other_endpoints", []):
            if isinstance(u, str):
                urls_to_export.append(u)
            elif isinstance(u, dict) and u.get("url"):
                urls_to_export.append(u.get("url"))
    
    if target:
        target_clean = target.lower().strip()
        filtered = []
        for u in urls_to_export:
            try:
                u_parsed = urllib.parse.urlparse(u if (u.startswith("http://") or u.startswith("https://")) else f"http://{u}")
                if (u_parsed.hostname or "").lower() == target_clean:
                    filtered.append(u)
            except Exception:
                pass
        urls_to_export = filtered
        file_prefix = target_clean
    else:
        file_prefix = domain

    content_str = "\n".join(sorted(list(set(urls_to_export))))
    cat_label = f"_{category}" if category else "_all"
    filename = f"{file_prefix}_archive_urls{cat_label}.txt"
    return StreamingResponse(
        io.StringIO(content_str),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/api/domains/{domain_id}/dynamic-js")
async def get_dynamic_js_results(domain_id: str, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    try:
        domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid domain ID")
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    dynamic_js = domain_doc.get("infrastructure", {}).get("dynamic_js", {})
    return {"status": "success", "data": dynamic_js}

@app.get("/api/ip-lookup")
async def ip_lookup(ip: str, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    # Find all domains where any subdomain has this IP
    cursor = domains_col.find({"infrastructure.subdomains.ip": ip}, {"domain": 1, "infrastructure.subdomains": 1})
    docs = await cursor.to_list(length=100)
    
    matches = []
    for doc in docs:
        for sub in doc.get("infrastructure", {}).get("subdomains", []):
            if sub.get("ip") == ip:
                matches.append({
                    "name": sub["name"],
                    "parent_domain": doc["domain"]
                })
    return matches

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, user: dict = Depends(get_current_user)):
    if not user or user.get("role") != "admin":
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    
    # Just render the template; the tables will be populated via AJAX
    return await render_page(request, "admin.html", {}, user)

@app.post("/admin/create-user")
@limiter.limit("10/minute")
async def create_user(request: Request, new_username: str = Form(...), new_password: str = Form(...), role: str = Form(...), user: dict = Depends(get_current_user)):
    check_admin(user)
    
    if await users_col.find_one({"username": new_username}):
        return templates.TemplateResponse(request, "admin.html", {"user": user, "error": "Username already exists"})
    
    is_valid, error_msg = validate_password(new_password)
    if not is_valid:
        return templates.TemplateResponse(request, "admin.html", {"user": user, "error": error_msg})
    
    # Validate role
    if role not in ["admin", "analyst", "viewer"]:
        role = "viewer"

    totp_secret = generate_totp_secret()
    totp_uri = get_totp_uri(totp_secret, new_username)
    hashed_password = get_password_hash(new_password)
    
    new_user = {
        "username": new_username,
        "hashed_password": hashed_password,
        "totp_secret": totp_secret,
        "role": role,
        "is_admin": True if role == "admin" else False, # Legacy support
        "disabled": False,
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "failed_attempts": 0,
        "lockout_until": None
    }
    await users_col.insert_one(new_user)
    await log_audit(user["username"], "create_user", f"Created user: {new_username} as {role}", request)
    
    return templates.TemplateResponse(request, "admin.html", {
        "user": user, 
        "success": f"User {new_username} created successfully.",
        "new_user_totp_uri": totp_uri
    })

@app.post("/admin/update-user")
async def update_user(
    request: Request, 
    target_username: str = Form(...), 
    new_password: Optional[str] = Form(None), 
    role: str = Form(...), 
    status_val: str = Form(...),
    user: dict = Depends(get_current_user)
):
    check_admin(user)
    
    if role not in ["admin", "analyst", "viewer"]:
        role = "viewer"

    update_data = {
        "role": role,
        "is_admin": True if role == "admin" else False, # Legacy support
        "disabled": True if status_val == "disabled" else False
    }
    
    if new_password and new_password.strip():
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            return templates.TemplateResponse(request, "admin.html", {"user": user, "error": error_msg})
        update_data["hashed_password"] = get_password_hash(new_password)
        # Also reset lockout if password is changed by admin
        update_data["failed_attempts"] = 0
        update_data["lockout_until"] = None
    
    await users_col.update_one({"username": target_username}, {"$set": update_data})
    await log_audit(user["username"], "update_user", f"Updated user: {target_username} to role {role}", request)
    
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/delete-user")
async def delete_user(request: Request, target_username: str = Form(...), user: dict = Depends(get_current_user)):
    check_admin(user)
    
    if target_username == user["username"]:
        return RedirectResponse(url="/admin?error=Cannot+delete+yourself", status_code=status.HTTP_303_SEE_OTHER)
        
    await users_col.delete_one({"username": target_username})
    await log_audit(user["username"], "delete_user", f"Deleted user: {target_username}", request)
    
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


def build_leads_query(status, risk, title, target, status_code, start_date, end_date, source=None, ws_clause=None):
    query = {}
    if ws_clause:
        query.update(ws_clause)
    if status == "all":
        pass # Include everything
    elif status:
        query["status"] = status
    else:
        # Default: exclude false positives, muted, benign, and investigating
        query["status"] = {"$nin": ["false_positive", "muted", "benign", "investigating"]}

    if risk:
        query["risk_level"] = risk
    if title:
        query["title"] = {"$regex": re.escape(title), "$options": "i"}
    if target:
        query["target"] = {"$regex": re.escape(target), "$options": "i"}
    if source:
        query["source"] = source
    
    if status_code:
        query["details"] = {"$regex": rf"\b{re.escape(status_code)}\b", "$options": "i"}
    
    if start_date or end_date:
        query["timestamp"] = {}
        if start_date:
            query["timestamp"]["$gte"] = start_date
        if end_date:
            if len(end_date) == 10:
                query["timestamp"]["$lte"] = f"{end_date}T23:59:59Z"
            else:
                query["timestamp"]["$lte"] = end_date
    return query

@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return await render_page(request, "alerts.html", {}, user)

@app.get("/investigate", response_class=HTMLResponse)
async def investigate_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return await render_page(request, "investigate.html", {}, user)

@app.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return await render_page(request, "findings.html", {}, user)

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return await render_page(request, "settings.html", {}, user)

@app.get("/api/leads")
async def get_leads(
    request: Request,
    status: Optional[str] = None,
    risk: Optional[str] = None,
    title: Optional[str] = None,
    target: Optional[str] = None,
    source: Optional[str] = None,
    status_code: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sort_by: Optional[str] = None,
    order: Optional[str] = "desc",
    limit: Optional[int] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    ws_clause = workspace_match_clause(ws_id, is_def)
    
    query = build_leads_query(status, risk, title, target, status_code, start_date, end_date, source=source, ws_clause=ws_clause)
            
    is_asc = (order == "asc")
    mongo_dir = 1 if is_asc else -1

    cursor = leads_col.find(query)
    if sort_by in ["size", "response_size", "length"]:
        cursor = cursor.sort("response_size", mongo_dir)
    elif sort_by in ["alphabetical", "target"]:
        cursor = cursor.sort("target", mongo_dir)
    elif sort_by == "title":
        cursor = cursor.sort("title", mongo_dir)
    elif sort_by in ["investigating_at", "time_added"]:
        cursor = cursor.sort("investigating_at", mongo_dir)
    else:
        cursor = cursor.sort("timestamp", mongo_dir)

    # Default to fetching all matching leads for the active filters on 1 page (up to 25,000)
    fetch_limit = limit if (limit is not None and limit > 0) else 25000
    leads = await cursor.to_list(length=fetch_limit)
    for lead in leads:
        lead["_id"] = str(lead["_id"])
        lead["response_size"] = int(lead.get("response_size") or 0)
    
    if sort_by:
        SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        is_asc = (order == "asc")
        if sort_by in ["size", "response_size", "length"]:
            leads.sort(key=lambda l: l.get("response_size", 0), reverse=not is_asc)
        elif sort_by in ["severity", "risk"]:
            leads.sort(
                key=lambda l: (
                    SEVERITY_WEIGHTS.get(str(l.get("risk_level", "")).lower(), 0),
                    l.get("response_size", 0),
                    l.get("investigating_at") or l.get("timestamp") or ""
                ),
                reverse=not is_asc
            )
        elif sort_by in ["investigating_at", "time_added"]:
            leads.sort(
                key=lambda l: l.get("investigating_at") or l.get("timestamp") or "",
                reverse=not is_asc
            )
        elif sort_by in ["alphabetical", "target"]:
            leads.sort(key=lambda l: str(l.get("target", "")).lower(), reverse=not is_asc)
        elif sort_by == "title":
            leads.sort(key=lambda l: str(l.get("title", "")).lower(), reverse=not is_asc)
        elif sort_by in ["time", "timestamp"]:
            leads.sort(
                key=lambda l: l.get("timestamp") or "",
                reverse=not is_asc
            )
    
    total_count = await leads_col.count_documents({})
    filtered_count = await leads_col.count_documents(query)
    
    return {
        "leads": leads,
        "total_count": total_count,
        "filtered_count": filtered_count,
        "displayed_count": len(leads)
    }

def is_takeover_lead(lead: dict) -> bool:
    """Return True if the lead is about a potential subdomain or cloud storage takeover."""
    if not lead:
        return False
    title = (lead.get("title") or "").lower()
    alert_type = (lead.get("alert_type") or "").lower()
    return (
        alert_type in ["dangling_dns_takeover", "subdomain_takeover", "takeover", "cloud_storage_takeover"]
        or "takeover" in title
        or "dangling" in title
    )

async def handle_takeover_status_change(lead: dict, new_status: str):
    """
    Synchronize subdomain takeover flags when an alert status changes.
    When marked as false_positive/benign/muted, removes all red takeover indicators.
    When reverted back to active, restores the indicators.
    """
    target = (lead.get("target") or "").strip()
    if not target:
        return
    target_clean = target.lower()

    if new_status in ["false_positive", "benign", "muted"]:
        # 1. Clear takeover flags from infrastructure.subdomains
        await domains_col.update_many(
            {"infrastructure.subdomains.name": target_clean},
            {
                "$set": {
                    "infrastructure.subdomains.$[elem].dangling_takeover": False,
                    "infrastructure.subdomains.$[elem].takeover_provider": None,
                    "infrastructure.subdomains.$[elem].takeover_risk": None,
                    "infrastructure.subdomains.$[elem].takeover_false_positive": True
                }
            },
            array_filters=[{"elem.name": target_clean}]
        )

        # 2. Clear takeover flags from root domain if it was set on domain doc
        await domains_col.update_many(
            {"domain": target_clean},
            {
                "$set": {
                    "dangling_takeover": False,
                    "takeover_provider": None,
                    "takeover_risk": None,
                    "takeover_false_positive": True
                }
            }
        )

        # 3. Pull dangling takeover detection events from domain history
        await domains_col.update_many(
            {},
            {
                "$pull": {
                    "history": {
                        "event_type": "dangling_takeover_detected",
                        "target": target_clean
                    }
                }
            }
        )
        logger.info(f"[Takeover Sync] Cleared all takeover flags and red indicators for {target_clean} (status={new_status})")

    elif new_status in ["new", "investigating", "true_positive"]:
        details = lead.get("details") or {}
        cname = details.get("cname")
        provider = details.get("provider") or "Unknown Service Provider"
        risk = details.get("risk") or lead.get("risk_level") or "high"

        await domains_col.update_many(
            {"infrastructure.subdomains.name": target_clean},
            {
                "$set": {
                    "infrastructure.subdomains.$[elem].dangling_takeover": True,
                    "infrastructure.subdomains.$[elem].cname": cname,
                    "infrastructure.subdomains.$[elem].takeover_provider": provider,
                    "infrastructure.subdomains.$[elem].takeover_risk": risk,
                    "infrastructure.subdomains.$[elem].takeover_false_positive": False
                }
            },
            array_filters=[{"elem.name": target_clean}]
        )

        await domains_col.update_many(
            {"domain": target_clean},
            {
                "$set": {
                    "dangling_takeover": True,
                    "cname": cname,
                    "takeover_provider": provider,
                    "takeover_risk": risk,
                    "takeover_false_positive": False
                }
            }
        )
        logger.info(f"[Takeover Reactivation] Restored takeover flags for {target_clean} (status={new_status})")

async def apply_lead_mute(lead: dict, user: dict, request: Request):
    lead_id = lead["_id"]
    fingerprint = lead.get("fingerprint")
    
    # 1. Mark the lead as muted (or keep current status if called from status update)
    # If the lead already has a terminal status like false_positive, we keep that status
    # but still ensure the fingerprint is suppressed.
    
    # 2. Add to alert_fingerprints as suppressed if fingerprint exists
    if fingerprint:
        from app.database import db
        fingerprints_col = db["alert_fingerprints"]
        await fingerprints_col.update_one(
            {"fingerprint": fingerprint},
            {
                "$set": {
                    "status": "suppressed",
                    "suppressed_at": datetime.utcnow().isoformat(),
                    "suppressed_by": user["username"]
                }
            },
            upsert=True
        )

    # 3. Synchronize takeover indicators if this is a takeover lead
    if is_takeover_lead(lead):
        await handle_takeover_status_change(lead, "muted")
    
    await log_audit(user["username"], "MUTE_LEAD", f"Muted/Suppressed lead: {lead['title']} on {lead['target']}", request)

@app.get("/api/leads/sources")
async def get_lead_sources(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    sources = await leads_col.distinct("source", workspace_match_clause(ws_id, is_def))
    source_list = [s for s in sources if s]
    return sorted(source_list)

@app.post("/api/leads/{lead_id}/mute")
async def mute_lead(lead_id: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    lead = await leads_col.find_one({"_id": ObjectId(lead_id)})
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
        
    await leads_col.update_one({"_id": ObjectId(lead_id)}, {"$set": {"status": "muted"}})
    await apply_lead_mute(lead, user, request)
    return {"status": "success"}

@app.get("/api/leads/export")
async def export_leads(
    request: Request,
    status: Optional[str] = None,
    risk: Optional[str] = None,
    title: Optional[str] = None,
    target: Optional[str] = None,
    source: Optional[str] = None,
    status_code: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sort_by: Optional[str] = None,
    order: Optional[str] = "desc",
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    ws_clause = workspace_match_clause(ws_id, is_def)
    
    query = build_leads_query(status, risk, title, target, status_code, start_date, end_date, source=source, ws_clause=ws_clause)
            
    is_asc = (order == "asc")
    mongo_dir = 1 if is_asc else -1

    cursor = leads_col.find(query)
    if sort_by in ["size", "response_size", "length"]:
        cursor = cursor.sort("response_size", mongo_dir)
    elif sort_by in ["alphabetical", "target"]:
        cursor = cursor.sort("target", mongo_dir)
    elif sort_by == "title":
        cursor = cursor.sort("title", mongo_dir)
    elif sort_by in ["investigating_at", "time_added"]:
        cursor = cursor.sort("investigating_at", mongo_dir)
    else:
        cursor = cursor.sort("timestamp", mongo_dir)

    leads = await cursor.to_list(length=25000) # Full export limit
    for lead in leads:
        lead["response_size"] = int(lead.get("response_size") or 0)
    
    if sort_by:
        SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        is_asc = (order == "asc")
        if sort_by in ["size", "response_size", "length"]:
            leads.sort(key=lambda l: l.get("response_size", 0), reverse=not is_asc)
        elif sort_by in ["severity", "risk"]:
            leads.sort(
                key=lambda l: (
                    SEVERITY_WEIGHTS.get(str(l.get("risk_level", "")).lower(), 0),
                    l.get("response_size", 0),
                    l.get("investigating_at") or l.get("timestamp") or ""
                ),
                reverse=not is_asc
            )
        elif sort_by in ["investigating_at", "time_added"]:
            leads.sort(
                key=lambda l: l.get("investigating_at") or l.get("timestamp") or "",
                reverse=not is_asc
            )
        elif sort_by in ["alphabetical", "target"]:
            leads.sort(key=lambda l: str(l.get("target", "")).lower(), reverse=not is_asc)
        elif sort_by == "title":
            leads.sort(key=lambda l: str(l.get("title", "")).lower(), reverse=not is_asc)
        elif sort_by in ["time", "timestamp"]:
            leads.sort(
                key=lambda l: l.get("timestamp") or "",
                reverse=not is_asc
            )

    data = []
    for l in leads:
        row = {
            "Detected Date": l.get("timestamp"),
            "Time Added to Investigate": l.get("investigating_at") or l.get("timestamp") or "",
            "Status": l.get("status", "new").replace("_", " ").title(),
            "Risk": l.get("risk_level", "low").upper(),
            "Title": l.get("title"),
            "Target": l.get("target"),
            "Response Size (Bytes)": l.get("response_size", 0),
            "Notes": l.get("notes", "")
        }
        if status != "investigating":
            del row["Time Added to Investigate"]
        data.append(row)
    
    if not data:
        # Create empty df with columns if no data
        cols = ["Detected Date", "Status", "Risk", "Title", "Target", "Response Size (Bytes)", "Notes"]
        if status == "investigating":
            cols.insert(1, "Time Added to Investigate")
        df = pd.DataFrame(columns=cols)
    else:
        df = pd.DataFrame(data)
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Hunting Leads')
    
    output.seek(0)
    
    headers = {
        'Content-Disposition': f'attachment; filename="hunting_leads_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx"'
    }
    return StreamingResponse(output, headers=headers, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.post("/api/leads/{lead_id}/status")
async def update_lead_status(lead_id: str, request: Request, status: str = Form(...), notes: Optional[str] = Form(None), user: dict = Depends(get_current_user)):
    check_analyst(user)
    try:
        obj_id = ObjectId(lead_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid lead ID format")

    lead = await leads_col.find_one({"_id": obj_id})
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")

    update_doc = {"status": status}
    if status == "investigating":
        update_doc["investigating_at"] = datetime.utcnow().isoformat()
    if notes is not None:
        update_doc["notes"] = notes
    await leads_col.update_one({"_id": obj_id}, {"$set": update_doc})
    
    # Reactivate fingerprint suppression if returned back to alerts/new
    if status == "new":
        if lead.get("fingerprint"):
            from app.database import db
            fingerprints_col = db["alert_fingerprints"]
            await fingerprints_col.update_one(
                {"fingerprint": lead["fingerprint"]},
                {"$set": {"status": "active"}}
            )
    
    # Auto-mute if status is false_positive or benign
    if status in ["false_positive", "benign"]:
        await apply_lead_mute(lead, user, request)

    # Synchronize subdomain takeover flags (removes all red takeover icons if false_positive)
    if is_takeover_lead(lead):
        await handle_takeover_status_change(lead, status)
            
    return {"status": "success"}

@app.post("/api/leads/{lead_id}/notes")
async def update_lead_notes(lead_id: str, notes: str = Form(""), user: dict = Depends(get_current_user)):
    check_analyst(user)
    try:
        obj_id = ObjectId(lead_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid lead ID format")
    await leads_col.update_one({"_id": obj_id}, {"$set": {"notes": notes}})
    return {"status": "success"}

@app.delete("/api/leads/{lead_id}")
@app.post("/api/leads/{lead_id}/delete")
async def delete_lead(lead_id: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    try:
        obj_id = ObjectId(lead_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid lead ID format")

    lead = await leads_col.find_one({"_id": obj_id})
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")

    result = await leads_col.delete_one({"_id": obj_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Lead not found")

    if is_takeover_lead(lead):
        other_active = await leads_col.count_documents({
            "_id": {"$ne": obj_id},
            "target": lead.get("target"),
            "status": {"$in": ["new", "investigating", "true_positive"]},
            "$or": [
                {"alert_type": "dangling_dns_takeover"},
                {"title": {"$regex": "takeover", "$options": "i"}}
            ]
        })
        if other_active == 0:
            await handle_takeover_status_change(lead, "false_positive")

    await log_audit(user["username"], "DELETE_LEAD", f"Deleted alert {lead_id}", request)
    return {"status": "success", "deleted": True}

@app.post("/api/leads/bulk-delete")
async def bulk_delete_leads(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    data = await request.json()
    
    apply_to_all = data.get("apply_to_all", False)
    if apply_to_all:
        query = build_leads_query(
            data.get("status"), data.get("risk"), data.get("title"),
            data.get("target"), data.get("status_code"), data.get("start_date"), data.get("end_date")
        )
    else:
        ids = [ObjectId(id_str) for id_str in data.get("ids", [])]
        if not ids:
            return {"status": "error", "message": "No IDs provided"}
        query = {"_id": {"$in": ids}}
    
    cursor = leads_col.find(query)
    takeover_targets = set()
    async for lead in cursor:
        if is_takeover_lead(lead) and lead.get("target"):
            takeover_targets.add(lead["target"])

    count = await leads_col.count_documents(query)
    await leads_col.delete_many(query)

    for target_name in takeover_targets:
        remaining = await leads_col.count_documents({
            "target": target_name,
            "status": {"$in": ["new", "investigating", "true_positive"]},
            "$or": [
                {"alert_type": "dangling_dns_takeover"},
                {"title": {"$regex": "takeover", "$options": "i"}}
            ]
        })
        if remaining == 0:
            await handle_takeover_status_change({"target": target_name}, "false_positive")

    await log_audit(user["username"], "BULK_DELETE_LEADS", f"Deleted {count} alerts", request)
    return {"status": "success", "count": count}

@app.post("/api/leads/delete-all")
async def delete_all_leads(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    count = await leads_col.count_documents({})
    await leads_col.delete_many({})
    # Clear all takeover indicators in domains_col
    await domains_col.update_many(
        {"infrastructure.subdomains.dangling_takeover": True},
        {
            "$set": {
                "infrastructure.subdomains.$[elem].dangling_takeover": False,
                "infrastructure.subdomains.$[elem].takeover_provider": None,
                "infrastructure.subdomains.$[elem].takeover_risk": None
            }
        },
        array_filters=[{"elem.dangling_takeover": True}]
    )
    await domains_col.update_many(
        {"dangling_takeover": True},
        {
            "$set": {
                "dangling_takeover": False,
                "takeover_provider": None,
                "takeover_risk": None
            }
        }
    )
    await domains_col.update_many(
        {},
        {"$pull": {"history": {"event_type": "dangling_takeover_detected"}}}
    )
    await log_audit(user["username"], "DELETE_ALL_LEADS", f"Deleted all {count} alerts and cleared takeover indicators", request)
    return {"status": "success"}

@app.post("/api/leads/bulk-status")
async def bulk_status_leads(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    data = await request.json()
    new_status = data.get("status")

    if not new_status:
        return {"status": "error", "message": "Missing status"}

    apply_to_all = data.get("apply_to_all", False)
    if apply_to_all:
        query = build_leads_query(
            data.get("status_filter"), data.get("risk"), data.get("title"),
            data.get("target"), data.get("status_code"), data.get("start_date"), data.get("end_date")
        )
    else:
        ids = [ObjectId(id_str) for id_str in data.get("ids", [])]
        if not ids:
            return {"status": "error", "message": "No IDs provided"}
        query = {"_id": {"$in": ids}}

    # Sync takeover status for all matching leads
    cursor = leads_col.find(query)
    async for lead in cursor:
        if is_takeover_lead(lead):
            await handle_takeover_status_change(lead, new_status)

    count = await leads_col.count_documents(query)
    await leads_col.update_many(query, {"$set": {"status": new_status}})

    # If muting, false_positive, or benign, also update fingerprints for future suppression
    if new_status in ["muted", "false_positive", "benign"]:
        from app.database import db
        fingerprints_col = db["alert_fingerprints"]

        # Get all fingerprints for matching leads
        cursor = leads_col.find(query, {"fingerprint": 1, "title": 1, "target": 1})
        async for lead in cursor:
            fp = lead.get("fingerprint")
            if fp:
                await fingerprints_col.update_one(
                    {"fingerprint": fp},
                    {
                        "$set": {
                            "status": "suppressed",
                            "suppressed_at": datetime.utcnow().isoformat(),
                            "suppressed_by": user["username"]
                        }
                    },
                    upsert=True
                )

    await log_audit(user["username"], "BULK_STATUS_LEADS", f"Updated {count} alerts to {new_status}", request)
    return {"status": "success", "count": count}
@app.get("/api/notifications/count")
async def get_notifications_count(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    query = {"status": "new", "acknowledged": {"$ne": True}}
    query.update(workspace_match_clause(ws_id, is_def))
    count = await leads_col.count_documents(query)
    return {"count": count}

@app.post("/api/notifications/clear")
async def clear_notifications(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    query = {"status": "new", "acknowledged": {"$ne": True}}
    query.update(workspace_match_clause(ws_id, is_def))
    await leads_col.update_many(query, {"$set": {"acknowledged": True}})
    return {"status": "success"}

# --- Findings Management Routes ---

@app.get("/api/findings/stats/summary")
async def get_findings_stats(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    ws_c = workspace_match_clause(ws_id, is_def)

    total = await findings_col.count_documents(ws_c)
    critical = await findings_col.count_documents({"severity": "critical", **ws_c})
    high = await findings_col.count_documents({"severity": "high", **ws_c})
    medium = await findings_col.count_documents({"severity": "medium", **ws_c})
    low = await findings_col.count_documents({"severity": "low", **ws_c})
    info = await findings_col.count_documents({"severity": "info", **ws_c})
    
    confirmed = await findings_col.count_documents({"status": "confirmed", **ws_c})
    in_progress = await findings_col.count_documents({"status": "in_progress", **ws_c})
    remediated = await findings_col.count_documents({"status": "remediated", **ws_c})
    draft = await findings_col.count_documents({"status": "draft", **ws_c})
    
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "confirmed": confirmed,
        "in_progress": in_progress,
        "remediated": remediated,
        "draft": draft
    }

@app.get("/api/findings")
async def get_findings(
    request: Request,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    target: Optional[str] = None,
    root_domain: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = "updated_at",
    order: Optional[str] = "desc",
    limit: Optional[int] = 200,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    query = workspace_match_clause(ws_id, is_def).copy()
    if severity and severity != "all":
        query["severity"] = severity.lower()
    if status and status != "all":
        query["status"] = status.lower()
    if category and category != "all":
        query["category"] = category
    if target:
        query["target"] = {"$regex": re.escape(target.strip()), "$options": "i"}
    if root_domain:
        query["root_domain"] = root_domain.strip().lower()
    if search:
        s = re.escape(search.strip())
        query["$or"] = [
            {"title": {"$regex": s, "$options": "i"}},
            {"target": {"$regex": s, "$options": "i"}},
            {"category": {"$regex": s, "$options": "i"}},
            {"notes": {"$regex": s, "$options": "i"}},
            {"cve_id": {"$regex": s, "$options": "i"}},
            {"cwe_id": {"$regex": s, "$options": "i"}}
        ]

    is_asc = (order == "asc")
    mongo_dir = 1 if is_asc else -1

    cursor = findings_col.find(query)
    if sort_by in ["created_at", "time"]:
        cursor = cursor.sort("created_at", mongo_dir)
    elif sort_by == "title":
        cursor = cursor.sort("title", mongo_dir)
    elif sort_by == "target":
        cursor = cursor.sort("target", mongo_dir)
    else:
        cursor = cursor.sort("updated_at", mongo_dir)

    findings = await cursor.to_list(length=limit or 200)
    for f in findings:
        f["_id"] = str(f["_id"])

    if sort_by == "severity":
        SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        findings.sort(key=lambda x: SEV_ORDER.get(str(x.get("severity", "")).lower(), 0), reverse=not is_asc)

    return findings

@app.get("/api/findings/{finding_id}")
async def get_finding(finding_id: str, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    try:
        oid = ObjectId(finding_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid finding ID")
    finding = await findings_col.find_one({"_id": oid})
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding["_id"] = str(finding["_id"])
    return finding

@app.post("/api/findings")
async def create_finding(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    data = await request.json()
    title = (data.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required")

    target = (data.get("target") or "").strip()
    root_domain = (data.get("root_domain") or "").strip().lower()
    if not root_domain and target:
        m = re.search(r"https?://([^/:]+)", target)
        host = m.group(1) if m else target.split("/")[0].split(":")[0]
        parts = host.split(".")
        if len(parts) >= 2:
            root_domain = ".".join(parts[-2:]).lower()
        else:
            root_domain = host.lower()

    now = datetime.utcnow().isoformat()
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    doc = {
        "title": title,
        "workspace_id": ws_id,
        "severity": (data.get("severity") or "medium").lower(),
        "status": (data.get("status") or "draft").lower(),
        "category": data.get("category") or "General Security",
        "target": target,
        "root_domain": root_domain,
        "cvss_score": data.get("cvss_score"),
        "cve_id": data.get("cve_id"),
        "cwe_id": data.get("cwe_id"),
        "notes": data.get("notes") or "",
        "alert_id": data.get("alert_id"),
        "created_by": user["username"],
        "created_at": now,
        "updated_at": now,
        "updated_by": user["username"]
    }
    res = await findings_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    await log_audit(user["username"], "CREATE_FINDING", f"Created finding: {title} on {target}", request)
    return doc

@app.put("/api/findings/{finding_id}")
async def update_finding(finding_id: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    try:
        oid = ObjectId(finding_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid finding ID")

    data = await request.json()
    now = datetime.utcnow().isoformat()
    update_fields = {"updated_at": now, "updated_by": user["username"]}

    for k in ["title", "severity", "status", "category", "target", "root_domain", "cvss_score", "cve_id", "cwe_id", "notes"]:
        if k in data:
            update_fields[k] = data[k]

    res = await findings_col.update_one({"_id": oid}, {"$set": update_fields})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Finding not found")

    await log_audit(user["username"], "UPDATE_FINDING", f"Updated finding {finding_id}", request)
    updated_doc = await findings_col.find_one({"_id": oid})
    updated_doc["_id"] = str(updated_doc["_id"])
    return updated_doc

@app.delete("/api/findings/{finding_id}")
async def delete_finding(finding_id: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    try:
        oid = ObjectId(finding_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid finding ID")
    res = await findings_col.delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Finding not found")
    await log_audit(user["username"], "DELETE_FINDING", f"Deleted finding {finding_id}", request)
    return {"status": "success", "deleted": True}

@app.post("/api/findings/from-alert/{alert_id}")
async def promote_alert_to_finding(alert_id: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    try:
        oid = ObjectId(alert_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid alert ID")

    lead = await leads_col.find_one({"_id": oid})
    if not lead:
        raise HTTPException(status_code=404, detail="Alert not found")

    # If already promoted, return existing finding
    if lead.get("promoted_to_finding_id"):
        try:
            existing = await findings_col.find_one({"_id": ObjectId(lead["promoted_to_finding_id"])})
            if existing:
                existing["_id"] = str(existing["_id"])
                return {
                    "status": "exists",
                    "finding_id": str(existing["_id"]),
                    "message": "Alert was already promoted to Finding",
                    "finding": existing
                }
        except Exception:
            pass

    # Risk level mapping
    risk = str(lead.get("risk_level", "medium")).lower()
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info"
    }
    severity = severity_map.get(risk, "medium")

    title = lead.get("title") or "Vulnerability Finding"
    target = lead.get("target") or ""
    source = lead.get("source") or "Recon Scanner"
    timestamp = lead.get("timestamp") or datetime.utcnow().isoformat()
    description = lead.get("description") or "Identified during automated reconnaissance."
    exploitation = lead.get("exploitation_suggestions") or ""
    analyst_notes = lead.get("notes") or ""

    # Parse details
    raw_details = lead.get("details")
    if isinstance(raw_details, dict):
        import json
        formatted_details = "```json\n" + json.dumps(raw_details, indent=2) + "\n```"
    elif isinstance(raw_details, str) and raw_details.strip():
        if "HTTP/" in raw_details or "GET " in raw_details or "POST " in raw_details:
            formatted_details = "```http\n" + raw_details.strip() + "\n```"
        elif raw_details.startswith("{") or raw_details.startswith("["):
            formatted_details = "```json\n" + raw_details.strip() + "\n```"
        elif "```" in raw_details:
            formatted_details = raw_details
        else:
            formatted_details = "```http\n" + raw_details.strip() + "\n```"
    else:
        formatted_details = "*(No raw HTTP transaction captured)*"

    # Category inference
    cat = "Web Application Security"
    title_lower = title.lower()
    if "sql" in title_lower:
        cat = "SQL Injection"
    elif "xss" in title_lower:
        cat = "Cross-Site Scripting (XSS)"
    elif "ssrf" in title_lower:
        cat = "Server-Side Request Forgery (SSRF)"
    elif "idor" in title_lower or "access control" in title_lower:
        cat = "Broken Access Control"
    elif "source map" in title_lower or ".map" in title_lower:
        cat = "Source Code Disclosure"
    elif "file" in title_lower or "directory" in title_lower or "sensitive" in title_lower or "exposed" in title_lower:
        cat = "Information Disclosure"
    elif "cors" in title_lower:
        cat = "CORS Misconfiguration"
    elif "rce" in title_lower or "command" in title_lower:
        cat = "Remote Code Execution (RCE)"

    notes_parts = [
        f"## Technical Overview",
        f"- **Target URL / Asset**: `{target}`",
        f"- **Origin Alert**: `{title}` (Source: `{source}`)",
        f"- **Detection Timestamp**: `{timestamp}`",
        f"- **Status**: Confirmed Vulnerability",
        "",
        f"### Description",
        f"{description}",
        "",
        f"### Proof of Concept / Raw Details",
        formatted_details,
    ]

    if exploitation:
        notes_parts.extend([
            "",
            f"### Exploitation & Impact Analysis",
            f"{exploitation}"
        ])

    if analyst_notes:
        notes_parts.extend([
            "",
            f"### Analyst Notes (from Alerts)",
            f"> {analyst_notes}"
        ])

    notes_parts.extend([
        "",
        f"### Remediation Recommendations",
        f"1. Validate input and restrict access to privileged endpoints.",
        f"2. Ensure least-privilege configurations and disable debug artifacts in production.",
        f"3. Verify and re-test patch after deployment."
    ])

    markdown_notes = "\n".join(notes_parts)

    root_domain = lead.get("root_domain") or ""
    if not root_domain and target:
        m = re.search(r"https?://([^/:]+)", target)
        host = m.group(1) if m else target.split("/")[0].split(":")[0]
        parts = host.split(".")
        if len(parts) >= 2:
            root_domain = ".".join(parts[-2:]).lower()
        else:
            root_domain = host.lower()

    now = datetime.utcnow().isoformat()
    active_ws = await get_active_workspace(user, request)
    ws_id = lead.get("workspace_id") or str(active_ws["_id"])
    finding_doc = {
        "title": title,
        "workspace_id": ws_id,
        "severity": severity,
        "status": "confirmed",
        "category": cat,
        "target": target,
        "root_domain": root_domain,
        "cvss_score": None,
        "cve_id": None,
        "cwe_id": None,
        "notes": markdown_notes,
        "alert_id": alert_id,
        "created_by": user["username"],
        "created_at": now,
        "updated_at": now,
        "updated_by": user["username"]
    }

    res = await findings_col.insert_one(finding_doc)
    finding_id = str(res.inserted_id)

    # Link back in leads_col
    await leads_col.update_one(
        {"_id": oid},
        {
            "$set": {
                "promoted_to_finding_id": finding_id,
                "status": "true_positive"
            }
        }
    )

    await log_audit(user["username"], "PROMOTE_ALERT_TO_FINDING", f"Promoted alert {alert_id} ('{title}') to Finding {finding_id}", request)
    return {
        "status": "success",
        "finding_id": finding_id,
        "message": f"Successfully promoted alert to Finding #{finding_id[:8]}"
    }

@app.get("/api/findings/export")
async def export_findings(
    request: Request,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    target: Optional[str] = None,
    root_domain: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)

    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    query = workspace_match_clause(ws_id, is_def).copy()

    if severity and severity != "all":
        query["severity"] = severity.lower()
    if status and status != "all":
        query["status"] = status.lower()
    if category and category != "all":
        query["category"] = category
    if target:
        query["target"] = {"$regex": re.escape(target.strip()), "$options": "i"}
    if root_domain:
        query["root_domain"] = root_domain.strip().lower()

    cursor = findings_col.find(query).sort("updated_at", -1)
    findings = await cursor.to_list(length=10000)

    data = []
    for f in findings:
        data.append({
            "Finding ID": str(f.get("_id")),
            "Title": f.get("title"),
            "Severity": str(f.get("severity", "medium")).upper(),
            "Status": str(f.get("status", "draft")).replace("_", " ").title(),
            "Category": f.get("category", "General Security"),
            "Target": f.get("target"),
            "Root Domain": f.get("root_domain", ""),
            "CVSS": f.get("cvss_score") or "",
            "CVE": f.get("cve_id") or "",
            "CWE": f.get("cwe_id") or "",
            "Created By": f.get("created_by", ""),
            "Created At": f.get("created_at", ""),
            "Updated At": f.get("updated_at", ""),
            "Notes": f.get("notes", "")
        })

    if not data:
        cols = ["Finding ID", "Title", "Severity", "Status", "Category", "Target", "Root Domain", "CVSS", "CVE", "CWE", "Created By", "Created At", "Updated At", "Notes"]
        df = pd.DataFrame(columns=cols)
    else:
        df = pd.DataFrame(data)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Confirmed Findings')

    output.seek(0)
    headers = {
        'Content-Disposition': f'attachment; filename="confirmed_findings_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx"'
    }
    return StreamingResponse(output, headers=headers, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# --- Source Map Recovery Routes ---

@app.get("/api/source-maps")
async def get_source_maps(
    request: Request,
    target: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    
    query = workspace_match_clause(ws_id, is_def).copy()
    if target:
        clean_t = target.lower().strip()
        query["$or"] = [
            {"target": clean_t},
            {"target": {"$regex": re.escape(clean_t), "$options": "i"}}
        ]
    
    cursor = source_maps_col.find(query, {
        "target": 1,
        "source_map_url": 1,
        "map_name": 1,
        "total_files": 1,
        "app_files_count": 1,
        "vendor_files_count": 1,
        "has_embedded_source": 1,
        "languages": 1,
        "recovered_at": 1,
        "zip_size": 1
    }).sort("recovered_at", -1)
    
    maps = await cursor.to_list(length=300)
    for m in maps:
        m["_id"] = str(m["_id"])
    return maps

@app.get("/api/source-maps/{map_id}")
async def get_source_map_details(
    map_id: str,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    sm = None
    try:
        sm = await source_maps_col.find_one({"_id": ObjectId(map_id)})
    except Exception:
        pass
    
    if not sm:
        sm = await source_maps_col.find_one({"$or": [{"source_map_url": map_id}, {"map_name": map_id}]})
    
    if not sm:
        raise HTTPException(status_code=404, detail="Source map not found")
    
    sm["_id"] = str(sm["_id"])
    sm.pop("cached_files", None)
    return sm

@app.get("/api/source-maps/{map_id}/file")
async def get_source_map_file(
    map_id: str,
    path: str,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    sm = None
    try:
        sm = await source_maps_col.find_one({"_id": ObjectId(map_id)})
    except Exception:
        pass
    
    if not sm:
        sm = await source_maps_col.find_one({"$or": [{"source_map_url": map_id}, {"map_name": map_id}]})
    
    if not sm:
        raise HTTPException(status_code=404, detail="Source map not found")
    
    clean_req_path = os.path.normpath(path.lstrip("/")).replace("\\", "/")
    if clean_req_path.startswith("..") or "/../" in clean_req_path:
        raise HTTPException(status_code=400, detail="Invalid path traversal detected")

    content = None
    if "cached_files" in sm and clean_req_path in sm["cached_files"]:
        content = sm["cached_files"][clean_req_path]
    
    if content is None:
        src_dir = sm.get("src_dir") or os.path.join(sm.get("disk_dir", ""), "extracted")
        disk_filepath = os.path.abspath(os.path.join(src_dir, clean_req_path))
        
        if os.path.commonpath([src_dir, disk_filepath]) != os.path.abspath(src_dir):
            raise HTTPException(status_code=403, detail="Access denied")
        
        if os.path.exists(disk_filepath) and os.path.isfile(disk_filepath):
            try:
                with open(disk_filepath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to read file: {e}")
        else:
            raise HTTPException(status_code=404, detail="File not found in extracted source tree")
    
    from tools.source_map_unpacker import detect_language
    lang = detect_language(clean_req_path)
    
    return {
        "path": clean_req_path,
        "language": lang,
        "lines": content.count("\n") + 1,
        "size": len(content.encode("utf-8")),
        "content": content
    }

@app.get("/api/source-maps/{map_id}/download")
async def download_source_map_zip(
    map_id: str,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    sm = None
    try:
        sm = await source_maps_col.find_one({"_id": ObjectId(map_id)})
    except Exception:
        pass
    
    if not sm:
        sm = await source_maps_col.find_one({"$or": [{"source_map_url": map_id}, {"map_name": map_id}]})
    
    if not sm:
        raise HTTPException(status_code=404, detail="Source map not found")
    
    zip_path = sm.get("zip_path")
    if not zip_path or not os.path.exists(zip_path):
        raise HTTPException(status_code=404, detail="ZIP archive not found on disk")
    
    filename = os.path.basename(zip_path)
    return FileResponse(
        path=zip_path,
        filename=filename,
        media_type="application/zip"
    )

@app.post("/api/source-maps/recover")
async def recover_source_map(
    request: Request,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    body = await request.json()
    url = body.get("url")
    target = body.get("target")
    lead_id = body.get("lead_id")
    
    # If URL is not explicitly passed, attempt to resolve it from the lead document
    if not url and lead_id:
        try:
            lead = await leads_col.find_one({"_id": ObjectId(lead_id)})
            if lead:
                if not target:
                    target = lead.get("target")
                
                # Check if this lead is already linked to a recovered map
                existing_map_id = lead.get("recovered_source_map_id")
                if existing_map_id:
                    existing_sm = await source_maps_col.find_one({"_id": ObjectId(existing_map_id)})
                    if existing_sm and existing_sm.get("total_files", 0) > 0:
                        return {
                            "status": "success",
                            "id": str(existing_sm["_id"]),
                            "total_files": existing_sm.get("total_files"),
                            "app_files_count": existing_sm.get("app_files_count"),
                            "languages": existing_sm.get("languages", [])
                        }

                candidate_url = lead.get("source_map_url") or lead.get("url")
                if not candidate_url:
                    text_blob = f"{lead.get('details', '')} {lead.get('description', '')}"
                    m = re.search(r'Source Map URL:\s*(https?://[^\s\r\n]+)', text_blob, re.I)
                    if not m:
                        m = re.search(r'(https?://[^\s\r\n\'\"<>]+\.map[^\s\r\n\'\"<>]*)', text_blob, re.I)
                    if m:
                        candidate_url = m.group(1).rstrip(".,;:)'\"")
                url = candidate_url
        except Exception as e:
            logger.warning(f"Error resolving source map URL for lead {lead_id}: {e}")

    if not url:
        raise HTTPException(status_code=400, detail="Missing source map URL and could not resolve from lead details")
    
    clean_url = url.strip().rstrip(".,;:)'\"")
    from tools.source_map_unpacker import SourceMapUnpacker
    unpacker = SourceMapUnpacker()
    result = await unpacker.unpack_url(clean_url, target=target, lead_id=lead_id)
    if not result:
        reason = unpacker.last_error or "Could not retrieve or parse source map"
        raise HTTPException(status_code=500, detail=f"{reason} (URL: {clean_url})")
    
    return {
        "status": "success",
        "id": str(result["_id"]),
        "total_files": result.get("total_files"),
        "app_files_count": result.get("app_files_count"),
        "languages": result.get("languages", [])
    }

@app.get("/api/source-maps/{map_id}/routes")
async def get_source_map_routes(
    map_id: str,
    category: Optional[str] = None,
    method: Optional[str] = None,
    app_only: Optional[bool] = None,
    q: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    sm = None
    try:
        sm = await source_maps_col.find_one({"_id": ObjectId(map_id)})
    except Exception:
        pass
    if not sm:
        sm = await source_maps_col.find_one({"$or": [{"source_map_url": map_id}, {"map_name": map_id}]})
    if not sm:
        raise HTTPException(status_code=404, detail="Source map not found")

    routes = sm.get("routes_analysis", [])
    
    # If not yet analyzed and files exist, analyze on demand
    if not routes and sm.get("total_files", 0) > 0:
        try:
            from tools.source_code_analyzer import SourceCodeAnalyzer
            analyzer = SourceCodeAnalyzer()
            analysis = await analyzer.analyze_source_map_doc(sm)
            routes = analysis.get("routes", [])
            sm["routes_stats"] = analysis.get("stats")
            sm["routes_count"] = analysis.get("stats", {}).get("total", 0)
        except Exception as e:
            logger.error(f"On-demand route analysis error for {map_id}: {e}")

    # Filter
    filtered = []
    for r in routes:
        if category and r.get("category") != category:
            continue
        if method and r.get("method", "").upper() != method.upper():
            continue
        if app_only is True and not r.get("is_app", False):
            continue
        if q:
            query = q.lower()
            if (query not in r.get("path", "").lower() and
                query not in r.get("snippet", "").lower() and
                query not in r.get("file", "").lower()):
                continue
        filtered.append(r)

    stats = sm.get("routes_stats") or {
        "total": len(routes),
        "api_endpoints": sum(1 for r in routes if r.get("category") == "api_endpoint"),
        "client_routes": sum(1 for r in routes if r.get("category") == "client_route"),
        "external_urls": sum(1 for r in routes if r.get("category") == "external_url"),
        "websocket_endpoints": sum(1 for r in routes if r.get("category") == "websocket"),
        "app_routes_count": sum(1 for r in routes if r.get("is_app"))
    }

    return {
        "map_id": str(sm["_id"]),
        "target": sm.get("target"),
        "stats": stats,
        "filtered_count": len(filtered),
        "routes": filtered
    }

@app.post("/api/source-maps/{map_id}/analyze")
async def analyze_source_map(
    map_id: str,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    sm = None
    try:
        sm = await source_maps_col.find_one({"_id": ObjectId(map_id)})
    except Exception:
        pass
    if not sm:
        sm = await source_maps_col.find_one({"$or": [{"source_map_url": map_id}, {"map_name": map_id}]})
    if not sm:
        raise HTTPException(status_code=404, detail="Source map not found")

    from tools.source_code_analyzer import SourceCodeAnalyzer
    analyzer = SourceCodeAnalyzer()
    analysis = await analyzer.analyze_source_map_doc(sm)

    return {
        "status": "success",
        "map_id": str(sm["_id"]),
        "stats": analysis["stats"],
        "routes_count": analysis["stats"]["total"]
    }

@app.get("/api/source-maps/{map_id}/routes/export")
async def export_source_map_routes(
    map_id: str,
    format: str = "json",
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    sm = None
    try:
        sm = await source_maps_col.find_one({"_id": ObjectId(map_id)})
    except Exception:
        pass
    if not sm:
        sm = await source_maps_col.find_one({"$or": [{"source_map_url": map_id}, {"map_name": map_id}]})
    if not sm:
        raise HTTPException(status_code=404, detail="Source map not found")

    routes = sm.get("routes_analysis", [])
    target = sm.get("target", "target")
    clean_target = re.sub(r'[^a-zA-Z0-9_.-]', '_', target)

    if format.lower() == "csv":
        import io, csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Method", "Path", "Target URL", "File", "Line", "Is Application Code", "Snippet"])
        for r in routes:
            writer.writerow([
                r.get("category", ""),
                r.get("method", ""),
                r.get("path", ""),
                r.get("target_url", ""),
                r.get("file", ""),
                r.get("line", ""),
                "Yes" if r.get("is_app") else "No",
                r.get("snippet", "")
            ])
        from fastapi.responses import Response
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={clean_target}_routes.csv"}
        )
    else:
        from fastapi.responses import Response
        return Response(
            content=json.dumps({"target": target, "total": len(routes), "routes": routes}, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={clean_target}_routes.json"}
        )

@app.get("/api/source-maps/{map_id}/secrets")
async def get_source_map_secrets(
    map_id: str,
    secret_type: Optional[str] = None,
    app_only: Optional[bool] = None,
    q: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)

    sm = None
    try:
        sm = await source_maps_col.find_one({"_id": ObjectId(map_id)})
    except Exception:
        pass
    if not sm:
        sm = await source_maps_col.find_one({"$or": [{"source_map_url": map_id}, {"map_name": map_id}]})
    if not sm:
        raise HTTPException(status_code=404, detail="Source map not found")

    secrets = sm.get("secrets_analysis", [])

    filtered = []
    for s in secrets:
        if secret_type and s.get("type") != secret_type:
            continue
        if app_only is True and not s.get("is_app", False):
            continue
        if q:
            query = q.lower()
            if (query not in s.get("type", "").lower() and
                query not in s.get("value", "").lower() and
                query not in s.get("file", "").lower() and
                query not in s.get("snippet", "").lower()):
                continue
        filtered.append(s)

    stats = sm.get("secrets_stats") or {
        "total": len(secrets),
        "by_type": {},
        "app_secrets_count": sum(1 for s in secrets if s.get("is_app"))
    }

    return {
        "map_id": str(sm["_id"]),
        "target": sm.get("target"),
        "stats": stats,
        "total": len(secrets),
        "secrets_count": len(secrets),
        "filtered_count": len(filtered),
        "secrets": filtered
    }

@app.get("/api/source-maps/{map_id}/search")
async def search_source_map_files(
    map_id: str,
    q: str = "",
    case_sensitive: bool = False,
    regex: bool = False,
    app_only: bool = True,
    limit: int = 300,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    clean_q = (q or "").strip()
    if not clean_q:
        return {"query": "", "total_matches": 0, "total_files": 0, "results": []}

    sm = None
    try:
        sm = await source_maps_col.find_one({"_id": ObjectId(map_id)})
    except Exception:
        pass
    if not sm:
        sm = await source_maps_col.find_one({"$or": [{"source_map_url": map_id}, {"map_name": map_id}]})
    if not sm:
        raise HTTPException(status_code=404, detail="Source map not found")

    src_dir = sm.get("src_dir") or os.path.join(sm.get("disk_dir", ""), "extracted")
    if not os.path.exists(src_dir):
        raise HTTPException(status_code=404, detail="Extracted source files not found on disk")

    from tools.source_map_unpacker import is_application_source, detect_language

    compiled_re = None
    if regex:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            compiled_re = re.compile(clean_q, flags)
        except re.error as e:
            raise HTTPException(status_code=400, detail=f"Invalid regular expression: {e}")
    
    clean_q_lower = clean_q.lower() if not case_sensitive else clean_q

    file_matches = {}
    total_matches = 0

    for root, _, files in os.walk(src_dir):
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, src_dir).replace("\\", "/")

            is_app = is_application_source(rel_path)
            if app_only and not is_app:
                continue

            if f.endswith(('.zip', '.tar', '.gz', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot')):
                continue

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line_num, line in enumerate(fh, 1):
                        matched = False

                        if compiled_re:
                            if compiled_re.search(line):
                                matched = True
                        elif case_sensitive:
                            if clean_q in line:
                                matched = True
                        else:
                            if clean_q_lower in line.lower():
                                matched = True

                        if matched:
                            snippet = line.strip()
                            if rel_path not in file_matches:
                                file_matches[rel_path] = {
                                    "path": rel_path,
                                    "language": detect_language(rel_path),
                                    "is_app": is_app,
                                    "matches": []
                                }
                            file_matches[rel_path]["matches"].append({
                                "line": line_num,
                                "snippet": snippet[:240]
                            })
                            total_matches += 1
                            if total_matches >= limit:
                                break
            except Exception:
                pass

            if total_matches >= limit:
                break

    results = list(file_matches.values())
    results.sort(key=lambda x: (not x["is_app"], -len(x["matches"]), x["path"].lower()))

    return {
        "query": clean_q,
        "case_sensitive": case_sensitive,
        "regex": regex,
        "app_only": app_only,
        "total_matches": total_matches,
        "total_files": len(results),
        "hit_limit": total_matches >= limit,
        "results": results
    }

# --- Domain Management Routes ---

@app.get("/domains", response_class=HTMLResponse)
async def domains_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return await render_page(request, "domains.html", {}, user)

@app.get("/api/domains")
async def get_domains(
    request: Request,
    page: int = 1, 
    limit: int = 10, 
    q: Optional[str] = None,
    status_val: Optional[str] = None,
    blacklisted: Optional[str] = None,
    mutator: Optional[str] = None,
    api_routes: Optional[str] = None,
    cloud_assets: Optional[str] = None,
    secrets: Optional[str] = None,
    jwt: Optional[str] = None,
    base64: Optional[str] = None,
    alive_apps: Optional[str] = None,
    historical: Optional[str] = None,
    takeover: Optional[str] = None,
    hide_parked: Optional[str] = None,
    api_spec: Optional[str] = None,
    drift: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    ws_clause = workspace_match_clause(ws_id, is_def)
    
    root_query = get_query_filters(q, status_val, None, None, blacklisted, ws_clause=ws_clause)
    pipeline = get_flattened_pipeline(
        root_query,
        q,
        status_val,
        mutator=mutator,
        api_routes=api_routes,
        cloud_assets=cloud_assets,
        secrets=secrets,
        jwt=jwt,
        base64=base64,
        alive_apps=alive_apps,
        historical=historical,
        takeover=takeover,
        hide_parked=hide_parked,
        api_spec=api_spec,
        drift=drift
    )
    
    # Total count
    count_pipeline = pipeline + [{"$count": "total"}]
    count_result = await domains_col.aggregate(count_pipeline).to_list(length=1)
    total = count_result[0]["total"] if count_result else 0
    
    pipeline.append({"$sort": {"domain": 1}})
    pipeline.append({"$skip": (page - 1) * limit})
    pipeline.append({"$limit": limit})

    try:
        cursor = domains_col.aggregate(pipeline)
        docs = await cursor.to_list(length=limit)
        print(f"DEBUG: assets endpoint returning {len(docs)} assets for query {root_query}")
    except Exception as e:
        print(f"ERROR: Aggregation failed: {e}")
        return {"subdomains": [], "total": 0, "error": str(e)}
    
    results = []
    for d in docs:
        is_scanned = True if (d.get("system") or d.get("subdomain_scanned")) else (d.get("scanned_flag", False) if d.get("is_root") else False)
        last_scanned = d.get("system", {}).get("last_scanned") if d.get("system") else (d.get("last_scanned") if d.get("is_root") else "Never")
        sub_drift_count = int(d.get("subdomain_drift_count", 0))
        latest_drift_time = d.get("latest_subdomain_drift_time")
        
        results.append({
            "id": str(d["_id"]),
            "domain": d["domain"],
            "scanned": is_scanned,
            "on_hold": d.get("on_hold_flag", False),
            "blacklisted": False, 
            "notes": "", 
            "added_at": d.get("recon_date", "N/A"),
            "last_scanned": last_scanned,
            "is_root": d.get("is_root", False),
            "single_domain_only": d.get("single_domain_only", False),
            "scan_interval": d.get("scan_interval", 720),
            "source": d.get("source"),
            "is_permutated": False,
            "asn": d.get("asn"),
            "as_org": d.get("as_org"),
            "cidr": d.get("cidr"),
            "ptr": d.get("ptr"),
            "dangling_takeover": bool(d.get("dangling_takeover", False)),
            "cname": d.get("cname"),
            "takeover_provider": d.get("takeover_provider"),
            "has_api_specs": bool(d.get("has_api_specs", False)),
            "has_graphql": bool(d.get("has_graphql", False)),
            "subdomain_drift_count": sub_drift_count,
            "latest_subdomain_drift_time": latest_drift_time,
            "has_subdomain_drift": sub_drift_count > 0
        })
    
    return {"domains": results, "total": total, "page": page, "limit": limit}

@app.post("/api/domains/bulk-update-interval")
@limiter.limit("5/minute")
async def bulk_update_interval(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)

    data = await request.json()
    interval = data.get("interval")

    try:
        interval = int(interval)
        if interval < 1:
            raise ValueError()
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid interval. Must be a positive integer (hours).")

    if data.get("apply_to_all"):
        q = data.get("q")
        status_val = data.get("status_val")
        blacklisted = data.get("blacklisted")
        root_query = get_query_filters(q, status_val, None, None, blacklisted)
        pipeline = get_flattened_pipeline(root_query, q, status_val)
        pipeline.append({"$group": {"_id": "$_id"}})
        cursor = domains_col.aggregate(pipeline)
        ids = [doc["_id"] for doc in await cursor.to_list(length=None)]
    else:
        ids = [ObjectId(id_str) for id_str in data.get("ids", [])]

    if not ids:
        return {"status": "success", "message": "No domains to update"}

    await domains_col.update_many(
        {"_id": {"$in": ids}},
        {"$set": {"scan_interval": interval}}
    )

    await log_audit(user["username"], "BULK_UPDATE_INTERVAL", f"Updated scan interval of {len(ids)} domains to {interval} hours", request)
    return {"status": "success"}
def normalize_and_validate_domain(raw: str) -> Optional[str]:
    """Clean and validate raw domain string (strip schemes, paths, ports, wildcards)."""
    if not raw:
        return None
    d = raw.strip().lower()
    if not d:
        return None
    # Strip URL schemes if user pasted full URLs
    if "://" in d:
        d = d.split("://", 1)[1]
    # Strip paths, queries, fragments
    for delim in ["/", "?", "#"]:
        if delim in d:
            d = d.split(delim, 1)[0]
    # Strip port (e.g. host:8080)
    if ":" in d:
        d = d.split(":", 1)[0]
    # Strip wildcard prefix
    if d.startswith("*."):
        d = d[2:]
    d = d.strip(".")
    if re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", d):
        return d
    return None

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp",
    "co.kr", "ne.kr", "re.kr",
    "co.za", "org.za",
    "com.br", "net.br", "org.br",
    "com.mx", "org.mx",
    "com.sg", "edu.sg",
    "co.in", "net.in", "org.in", "gen.in", "ind.in",
    "com.tr", "org.tr",
    "com.tw", "org.tw",
    "com.hk", "org.hk",
    "com.ar", "com.co"
}

def is_subdomain(domain: str) -> bool:
    """Return True if domain is a subdomain (has more labels than the apex/root domain)."""
    if not domain:
        return False
    d = domain.strip().lower().rstrip(".")
    parts = d.split(".")
    if len(parts) < 2:
        return False
    for suffix in MULTI_PART_SUFFIXES:
        if d.endswith(f".{suffix}"):
            suffix_parts = len(suffix.split("."))
            return len(parts) > (suffix_parts + 1)
    return len(parts) > 2

@app.post("/api/domains/add")
async def add_domain(
    request: Request,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            body = {}
    else:
        form = await request.form()
        body = dict(form)

    domain = str(body.get("domain") or "").strip()
    single_domain_only = body.get("single_domain_only", False)
    
    cleaned_domain = normalize_and_validate_domain(domain)
    if not cleaned_domain:
        return {"status": "error", "message": "Invalid domain format"}

    # Automatically enforce single target only for subdomains so all security tools run on it without recursive discovery
    is_sub = is_subdomain(cleaned_domain)
    is_single = (single_domain_only is True or str(single_domain_only).lower() in ["true", "1", "yes"]) or is_sub

    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))

    existing = await domains_col.find_one({"domain": cleaned_domain, **workspace_match_clause(ws_id, is_def)})
    if existing:
        return {"status": "error", "message": "Domain already exists in this workspace"}
    
    # Inherit default scan interval from workspace
    ws_doc = await workspaces_col.find_one({"_id": ObjectId(ws_id)}) if ws_id and len(ws_id) == 24 else None
    dom_scan_interval = ws_doc.get("default_scan_interval", 720) if ws_doc else 720

    now_dt = datetime.utcnow()
    await domains_col.insert_one({
        "domain": cleaned_domain,
        "workspace_id": ws_id,
        "scanned": False,
        "blacklisted": False,
        "single_domain_only": is_single,
        "scan_interval": dom_scan_interval,
        "notes": "",
        "added_at": now_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "initial_scan_completed": False,
        "scan_cycle_count": 0
    })
    
    # Queue initial tasks: for single targets (including subdomains), run alive verification and port scan
    initial_tasks = [
        {"root_domain": cleaned_domain, "target": cleaned_domain, "task_type": "osint", "status": "pending", "created_at": now_dt, "workspace_id": ws_id},
        {"root_domain": cleaned_domain, "target": cleaned_domain, "task_type": "archive_urls", "status": "pending", "created_at": now_dt, "workspace_id": ws_id},
        {"root_domain": cleaned_domain, "target": cleaned_domain, "task_type": "waf_detect", "status": "pending", "created_at": now_dt, "workspace_id": ws_id},
        {"root_domain": cleaned_domain, "target": cleaned_domain, "task_type": "lb_detect", "status": "pending", "created_at": now_dt, "workspace_id": ws_id},
        {"root_domain": cleaned_domain, "target": cleaned_domain, "task_type": "cloud_storage_audit", "status": "pending", "created_at": now_dt, "workspace_id": ws_id}
    ]
    if is_single:
        initial_tasks.insert(0, {"root_domain": cleaned_domain, "target": cleaned_domain, "task_type": "verification", "status": "pending", "created_at": now_dt, "workspace_id": ws_id})
        initial_tasks.insert(1, {"root_domain": cleaned_domain, "target": cleaned_domain, "task_type": "scan", "status": "pending", "created_at": now_dt, "workspace_id": ws_id})
    else:
        initial_tasks.insert(0, {"root_domain": cleaned_domain, "target": cleaned_domain, "task_type": "discovery", "status": "pending", "created_at": now_dt, "workspace_id": ws_id})

    await tasks_col.insert_many(initial_tasks)
    
    await log_audit(user["username"], "ADD_DOMAIN", f"Added domain: {cleaned_domain} to workspace {active_ws.get('name')} (single_domain_only={is_single})", request)
    return {"status": "success"}

@app.post("/api/domains/bulk-add")
async def bulk_add_domains(
    request: Request,
    bulk_domains: Optional[str] = Form(None),
    status: str = Form("pending"),
    single_domain_only: Union[bool, str] = Form(False),
    file: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user)
):
    check_analyst(user)

    # Validate status
    if status not in ["pending", "scanned", "on_hold"]:
        status = "pending"

    scanned_val = True if status == "scanned" else False
    on_hold_val = True if status == "on_hold" else False
    is_single = single_domain_only is True or str(single_domain_only).lower() in ["true", "1", "yes"]

    raw_candidates = []
    
    # 1. Process Bulk Paste
    if bulk_domains:
        for line in bulk_domains.splitlines():
            cleaned = normalize_and_validate_domain(line)
            if cleaned:
                raw_candidates.append(cleaned)
                
    # 2. Process File Upload
    if file:
        filename = file.filename.lower()
        if not (filename.endswith('.txt') or filename.endswith('.csv')):
            raise HTTPException(status_code=400, detail="Security Violation: Only .txt and .csv files allowed.")
        
        # Read content (allow up to 10MB)
        content = await file.read(10 * 1024 * 1024)
        if await file.read(1):
            raise HTTPException(status_code=400, detail="File too large. Maximum size is 10MB.")
            
        try:
            text_content = content.decode('utf-8', errors='ignore')
            for line in text_content.splitlines():
                line_str = line.strip()
                if ',' in line_str and filename.endswith('.csv'):
                    line_str = line_str.split(',')[0].strip()
                cleaned = normalize_and_validate_domain(line_str)
                if cleaned:
                    raw_candidates.append(cleaned)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error reading uploaded file: {str(e)}")

    if not raw_candidates:
        return {"status": "error", "message": "No valid domains found in input. Please check the domain format."}

    # Deduplicate while preserving insertion order
    unique_candidates = []
    seen_candidates = set()
    for d in raw_candidates:
        if d not in seen_candidates:
            seen_candidates.add(d)
            unique_candidates.append(d)

    # High-performance Batch Check & Bulk Insert
    now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))

    now_dt = datetime.utcnow()
    
    # Check all existing domains in ONE database query for this workspace
    existing_docs = await domains_col.find(
        {"domain": {"$in": unique_candidates}, **workspace_match_clause(ws_id, is_def)},
        {"domain": 1}
    ).to_list(length=None)
    existing_set = {doc["domain"] for doc in existing_docs}
    
    domains_to_insert = []
    tasks_to_insert = []
    added_count = 0
    skipped_count = 0
    
    for domain in unique_candidates:
        if domain in existing_set:
            skipped_count += 1
            continue
            
        # Inherit default scan interval from workspace
        ws_doc = await workspaces_col.find_one({"_id": ObjectId(ws_id)}) if ws_id and len(ws_id) == 24 else None
        bulk_scan_interval = ws_doc.get("default_scan_interval", 720) if ws_doc else 720

        added_count += 1
        domain_is_single = is_single or is_subdomain(domain)
        domains_to_insert.append({
            "domain": domain,
            "workspace_id": ws_id,
            "scanned": scanned_val,
            "on_hold": on_hold_val,
            "blacklisted": False,
            "single_domain_only": domain_is_single,
            "scan_interval": bulk_scan_interval,
            "notes": "",
            "added_at": now_str,
            "initial_scan_completed": True if scanned_val else False,
            "scan_cycle_count": 1 if scanned_val else 0
        })
        
        if not scanned_val and not on_hold_val:
            initial_tasks = [
                {"root_domain": domain, "target": domain, "task_type": "osint", "status": "pending", "created_at": now_dt, "workspace_id": ws_id},
                {"root_domain": domain, "target": domain, "task_type": "archive_urls", "status": "pending", "created_at": now_dt, "workspace_id": ws_id},
                {"root_domain": domain, "target": domain, "task_type": "waf_detect", "status": "pending", "created_at": now_dt, "workspace_id": ws_id},
                {"root_domain": domain, "target": domain, "task_type": "lb_detect", "status": "pending", "created_at": now_dt, "workspace_id": ws_id},
                {"root_domain": domain, "target": domain, "task_type": "cloud_storage_audit", "status": "pending", "created_at": now_dt, "workspace_id": ws_id}
            ]
            if domain_is_single:
                initial_tasks.insert(0, {"root_domain": domain, "target": domain, "task_type": "verification", "status": "pending", "created_at": now_dt, "workspace_id": ws_id})
                initial_tasks.insert(1, {"root_domain": domain, "target": domain, "task_type": "scan", "status": "pending", "created_at": now_dt, "workspace_id": ws_id})
            else:
                initial_tasks.insert(0, {"root_domain": domain, "target": domain, "task_type": "discovery", "status": "pending", "created_at": now_dt, "workspace_id": ws_id})
            tasks_to_insert.extend(initial_tasks)

    # Bulk insert domains in chunks of 1000
    if domains_to_insert:
        for i in range(0, len(domains_to_insert), 1000):
            await domains_col.insert_many(domains_to_insert[i:i+1000], ordered=False)

    # Bulk insert tasks in chunks of 1000
    if tasks_to_insert:
        for i in range(0, len(tasks_to_insert), 1000):
            await tasks_col.insert_many(tasks_to_insert[i:i+1000], ordered=False)

    await log_audit(user["username"], "BULK_ADD_DOMAINS", f"Added {added_count} domains, skipped {skipped_count} (Total unique: {len(unique_candidates)}, single_domain_only={is_single})", request)
    
    return {
        "status": "success", 
        "added": added_count, 
        "skipped": skipped_count, 
        "total_valid": len(unique_candidates)
    }

@app.post("/api/domains/{domain_id}/blacklist")
async def toggle_blacklist(domain_id: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    new_status = not domain_doc.get("blacklisted", False)
    await domains_col.update_one({"_id": ObjectId(domain_id)}, {"$set": {"blacklisted": new_status}})
    
    await log_audit(user["username"], "BLACKLIST_DOMAIN", f"{'Blacklisted' if new_status else 'Unblacklisted'} domain: {domain_doc['domain']}", request)
    return {"status": "success", "blacklisted": new_status}

@app.post("/api/domains/{domain_id}/delete")
async def delete_domain(domain_id: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    domain_name = domain_doc['domain']
    await domains_col.delete_one({"_id": ObjectId(domain_id)})
    await tasks_col.delete_many({"root_domain": domain_name})
    await leads_col.delete_many({"target": {"$regex": re.escape(domain_name)}})
    
    await log_audit(user["username"], "DELETE_DOMAIN", f"Deleted domain: {domain_name}", request)
    return {"status": "success"}

@app.post("/api/domains/{domain_id}/webapps/delete-finding")
async def delete_webapp_finding(
    domain_id: str,
    request: Request,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    data = await request.json()
    target = data.get("target")
    category = data.get("category")
    finding = data.get("finding")
    
    if not all([target, category, finding]):
        raise HTTPException(status_code=400, detail="Missing required fields")
        
    result = await domains_col.update_one(
        {"_id": ObjectId(domain_id), "web_applications.target": target},
        {"$pull": {f"web_applications.$.{category}": finding}}
    )
    
    if result.modified_count == 0:
        # If exact match fails, try matching by key fields if it's a known category
        # This adds robustness against minor serialization differences
        pull_query = {}
        if category == "sensitive_files":
            pull_query = {"path": finding.get("path")}
        elif category == "js_findings":
            pull_query = {"value": finding.get("value"), "source": finding.get("source")}
        elif category == "403_bypasses":
            pull_query = {"payload": finding.get("payload"), "url": finding.get("url")}
        
        if pull_query:
            result = await domains_col.update_one(
                {"_id": ObjectId(domain_id), "web_applications.target": target},
                {"$pull": {f"web_applications.$.{category}": pull_query}}
            )

    # Log counts for debugging
    print(f"DEBUG: Single Delete - Matched: {result.matched_count}, Modified: {result.modified_count} for {target}")

    await log_audit(user["username"], "DELETE_FINDING", f"Deleted finding in {category} for {target} (Domain ID: {domain_id})", request)
    return {"status": "success", "count": result.modified_count}

@app.post("/api/domains/{domain_id}/webapps/bulk-delete-findings")
async def bulk_delete_webapp_findings(
    domain_id: str,
    request: Request,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    data = await request.json()
    target = data.get("target")
    category = data.get("category")
    findings = data.get("findings")
    status_code = data.get("status_code")
    length = data.get("length")
    prune_duplicates = data.get("prune_duplicates", False)
    
    if not all([target, category]):
        raise HTTPException(status_code=400, detail="Missing required fields (target or category)")

    # 1. Automated pruning of duplicate response lengths / soft-404 false positives
    if prune_duplicates:
        domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
        if not domain_doc:
            raise HTTPException(status_code=404, detail="Domain not found")
        web_apps = domain_doc.get("web_applications", [])
        modified_count = 0
        for app in web_apps:
            if app.get("target") == target:
                items = app.get(category, [])
                from collections import Counter
                # Group by non-zero length
                lens = Counter(it.get("length") for it in items if it.get("length") is not None and it.get("length") > 0)
                dupe_lens = {l for l, c in lens.items() if c >= 2}

                # Also handle legacy items where length is None but target has hundreds of identical status 200/redirects
                status_counts = Counter(it.get("status") for it in items if it.get("length") is None)
                dupe_statuses = {s for s, c in status_counts.items() if c > 10 and s in [200, 301, 302]}

                kept = []
                for it in items:
                    it_len = it.get("length")
                    it_status = it.get("status")
                    if it_len is not None and it_len in dupe_lens:
                        modified_count += 1
                    elif it_len is None and it_status in dupe_statuses:
                        modified_count += 1
                    else:
                        kept.append(it)

                app[category] = kept
                await domains_col.update_one(
                    {"_id": ObjectId(domain_id), "web_applications.target": target},
                    {"$set": {f"web_applications.$.{category}": kept}}
                )
                await log_audit(user["username"], "PRUNE_DUPE_FINDINGS", f"Pruned {modified_count} duplicate length findings in {category} for {target} (Domain ID: {domain_id})", request)
                return {"status": "success", "count": modified_count}

        return {"status": "success", "count": 0}

    pull_filter = None
    
    if length is not None:
        try:
            ln = int(length)
            pull_filter = {"length": ln}
            if status_code is not None:
                pull_filter["status"] = int(status_code)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid length format")
    elif status_code is not None:
        try:
            sc = int(status_code)
            pull_filter = {"status": sc}
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid status code format")
    elif findings:
        # Build a pull query that matches any of the provided findings by their key fields
        or_filters = []
        for f in findings:
            if category == "sensitive_files":
                or_filters.append({"path": f.get("path")})
            elif category == "js_findings":
                or_filters.append({"value": f.get("value"), "source": f.get("source")})
            elif category == "403_bypasses":
                or_filters.append({"payload": f.get("payload"), "url": f.get("url")})
            else:
                or_filters.append(f)
        
        if or_filters:
            pull_filter = {"$or": or_filters}
    
    if not pull_filter:
        return {"status": "success", "count": 0}

    result = await domains_col.update_one(
        {"_id": ObjectId(domain_id), "web_applications.target": target},
        {"$pull": {f"web_applications.$.{category}": pull_filter}}
    )
    
    # Log counts for debugging
    print(f"DEBUG: Bulk Delete - Matched: {result.matched_count}, Modified: {result.modified_count} for {target}")

    await log_audit(user["username"], "BULK_DELETE_FINDINGS", f"Bulk deleted findings in {category} for {target} (Domain ID: {domain_id})", request)
    return {"status": "success", "count": result.modified_count}

@app.post("/api/domains/{domain_id}/notes")
async def update_domain_notes(domain_id: str, request: Request, notes: str = Form(""), user: dict = Depends(get_current_user)):
    check_analyst(user)
    try:
        obj_id = ObjectId(domain_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid domain ID format")
    await domains_col.update_one({"_id": obj_id}, {"$set": {"notes": notes}})
    return {"status": "success"}

@app.post("/api/domains/{domain_id}/scan-now")
async def scan_now(domain_id: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    root_domain = domain_doc["domain"]
    is_single = domain_doc.get("single_domain_only", False)
    
    # 1. Reset scanned flag, on_hold flag, osint_complete, archive_hunter_complete, and all subdomains
    prev_scanned = domain_doc.get("last_scanned")
    last_cycle = prev_scanned if prev_scanned and prev_scanned != "Never" else domain_doc.get("last_cycle_completed")
    update_data = {
        "scanned": False,
        "on_hold": False,
        "osint_complete": False,
        "archive_hunter_complete": False,
        "last_scanned": "Never"
    }
    if last_cycle:
        update_data["last_cycle_completed"] = last_cycle

    await domains_col.update_one(
        {"_id": ObjectId(domain_id)},
        {"$set": update_data}
    )
    await domains_col.update_one(
        {"_id": ObjectId(domain_id), "infrastructure.subdomains": {"$exists": True, "$type": "array", "$ne": []}},
        {"$set": {
            "infrastructure.subdomains.$[].scanned": False
        }}
    )
    
    # 2. Clear ALL old/stuck tasks for this domain to allow a clean re-entry
    await tasks_col.delete_many({"root_domain": root_domain})
    
    # 3. Create fresh tasks based on domain scope
    fresh_tasks = [
        {"root_domain": root_domain, "target": root_domain, "task_type": "osint", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "archive_urls", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "waf_detect", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "lb_detect", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "cloud_storage_audit", "status": "pending", "created_at": datetime.utcnow()}
    ]
    if is_single:
        fresh_tasks.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "verification", "status": "pending", "created_at": datetime.utcnow()})
        fresh_tasks.insert(1, {"root_domain": root_domain, "target": root_domain, "task_type": "scan", "status": "pending", "created_at": datetime.utcnow()})
    else:
        fresh_tasks.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "discovery", "status": "pending", "created_at": datetime.utcnow()})
        
    # Queue verification for all existing subdomains so they are tested and scanned
    subs = (domain_doc.get("infrastructure") or {}).get("subdomains", [])
    for sub in subs:
        sub_name = sub.get("name") if isinstance(sub, dict) else sub
        if sub_name and sub_name != root_domain:
            fresh_tasks.append({
                "root_domain": root_domain,
                "target": sub_name,
                "task_type": "verification",
                "status": "pending",
                "created_at": datetime.utcnow()
            })
            
    await tasks_col.insert_many(fresh_tasks)
    
    await log_audit(user["username"], "SCAN_NOW", f"Triggered immediate scan for domain: {root_domain} (single={is_single})", request)
    return {"status": "success"}

@app.post("/api/domains/{domain_id}/scan-single")
async def scan_single_domain(domain_id: str, request: Request, user: dict = Depends(get_current_user)):
    """Trigger an immediate scan strictly for this single domain (no subdomain discovery)."""
    check_analyst(user)
    
    domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    root_domain = domain_doc["domain"]
    
    # 1. Reset scan status flags
    prev_scanned = domain_doc.get("last_scanned")
    last_cycle = prev_scanned if prev_scanned and prev_scanned != "Never" else domain_doc.get("last_cycle_completed")
    update_data = {
        "scanned": False,
        "on_hold": False,
        "osint_complete": False,
        "archive_hunter_complete": False,
        "last_scanned": "Never"
    }
    if last_cycle:
        update_data["last_cycle_completed"] = last_cycle

    await domains_col.update_one(
        {"_id": ObjectId(domain_id)},
        {"$set": update_data}
    )
    
    # 2. Clear old tasks for this domain
    await tasks_col.delete_many({"root_domain": root_domain})
    
    # 3. Immediately queue ONLY single-domain tasks (verification, scan, osint, archive_urls, waf_detect, lb_detect, cloud_storage_audit)
    await tasks_col.insert_many([
        {"root_domain": root_domain, "target": root_domain, "task_type": "verification", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "scan", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "osint", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "archive_urls", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "waf_detect", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "lb_detect", "status": "pending", "created_at": datetime.utcnow()},
        {"root_domain": root_domain, "target": root_domain, "task_type": "cloud_storage_audit", "status": "pending", "created_at": datetime.utcnow()}
    ])
    
    await log_audit(user["username"], "SCAN_SINGLE_DOMAIN", f"Triggered single-target scan for {root_domain} (subdomain discovery bypassed)", request)
    return {"status": "success"}

@app.post("/api/domains/bulk-scan-now")
async def bulk_scan_now(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    data = await request.json()
    if data.get("apply_to_all"):
        q = data.get("q")
        status_val_filter = data.get("status_val")
        blacklisted = data.get("blacklisted")
        root_query = get_query_filters(q, status_val_filter, None, None, blacklisted)
        pipeline = get_flattened_pipeline(root_query, q, status_val_filter)
        pipeline.append({"$group": {"_id": "$_id"}})
        cursor = domains_col.aggregate(pipeline)
        ids = [doc["_id"] for doc in await cursor.to_list(length=None)]
    else:
        ids = [ObjectId(id_str) for id_str in data.get("ids", [])]
    
    ids = list(set(ids))
    if not ids:
        return {"status": "error", "message": "No domains selected"}
    
    # Process each domain
    for d_id in ids:
        domain_doc = await domains_col.find_one({"_id": d_id})
        if not domain_doc:
            continue
            
        root_domain = domain_doc["domain"]
        is_single = domain_doc.get("single_domain_only", False)
        
        # 1. Reset flags and subdomains
        prev_scanned = domain_doc.get("last_scanned")
        last_cycle = prev_scanned if prev_scanned and prev_scanned != "Never" else domain_doc.get("last_cycle_completed")
        update_data = {
            "scanned": False,
            "on_hold": False,
            "osint_complete": False,
            "archive_hunter_complete": False,
            "last_scanned": "Never"
        }
        if last_cycle:
            update_data["last_cycle_completed"] = last_cycle

        await domains_col.update_one(
            {"_id": d_id},
            {"$set": update_data}
        )
        await domains_col.update_one(
            {"_id": d_id, "infrastructure.subdomains": {"$exists": True, "$type": "array", "$ne": []}},
            {"$set": {
                "infrastructure.subdomains.$[].scanned": False
            }}
        )
        
        # 2. Clear ALL old/stuck tasks
        await tasks_col.delete_many({"root_domain": root_domain})
        
        # 3. Create fresh tasks based on scope
        tasks_to_insert = [
            {"root_domain": root_domain, "target": root_domain, "task_type": "osint", "status": "pending", "created_at": datetime.utcnow()},
            {"root_domain": root_domain, "target": root_domain, "task_type": "archive_urls", "status": "pending", "created_at": datetime.utcnow()},
            {"root_domain": root_domain, "target": root_domain, "task_type": "waf_detect", "status": "pending", "created_at": datetime.utcnow()},
            {"root_domain": root_domain, "target": root_domain, "task_type": "lb_detect", "status": "pending", "created_at": datetime.utcnow()},
            {"root_domain": root_domain, "target": root_domain, "task_type": "cloud_storage_audit", "status": "pending", "created_at": datetime.utcnow()}
        ]
        if is_single:
            tasks_to_insert.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "verification", "status": "pending", "created_at": datetime.utcnow()})
            tasks_to_insert.insert(1, {"root_domain": root_domain, "target": root_domain, "task_type": "scan", "status": "pending", "created_at": datetime.utcnow()})
        else:
            tasks_to_insert.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "discovery", "status": "pending", "created_at": datetime.utcnow()})
            
        subs = (domain_doc.get("infrastructure") or {}).get("subdomains", [])
        for sub in subs:
            sub_name = sub.get("name") if isinstance(sub, dict) else sub
            if sub_name and sub_name != root_domain:
                tasks_to_insert.append({
                    "root_domain": root_domain,
                    "target": sub_name,
                    "task_type": "verification",
                    "status": "pending",
                    "created_at": datetime.utcnow()
                })

        await tasks_col.insert_many(tasks_to_insert)
            
    await log_audit(user["username"], "BULK_SCAN_NOW", f"Triggered immediate scan for {len(ids)} domains", request)
    return {"status": "success"}

@app.post("/api/domains/rescan-all")
async def rescan_all(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    active_ws = await get_active_workspace(user, request)
    ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))
    domains_query = {"blacklisted": {"$ne": True}}
    if ws_clause:
        domains_query = {"$and": [ws_clause, domains_query]}

    domains = await domains_col.find(domains_query).to_list(length=None)
    if not domains:
        return {"status": "error", "message": "No active domains found in this workspace to scan"}
        
    now = datetime.utcnow()
    ws_id_str = str(active_ws["_id"])
    
    # 1. Reset all root domains and all subdomains safely in this workspace
    for d in domains:
        prev_scanned = d.get("last_scanned")
        last_cycle = prev_scanned if prev_scanned and prev_scanned != "Never" else d.get("last_cycle_completed")
        update_data = {
            "scanned": False,
            "on_hold": False,
            "osint_complete": False,
            "archive_hunter_complete": False,
            "last_scanned": "Never"
        }
        if last_cycle:
            update_data["last_cycle_completed"] = last_cycle
        await domains_col.update_one(
            {"_id": d["_id"]},
            {"$set": update_data}
        )

    sub_query = {"blacklisted": {"$ne": True}, "infrastructure.subdomains": {"$exists": True, "$type": "array", "$ne": []}}
    if ws_clause:
        sub_query = {"$and": [ws_clause, sub_query]}
    await domains_col.update_many(
        sub_query,
        {"$set": {
            "infrastructure.subdomains.$[].scanned": False
        }}
    )
    
    # 2. Clear existing tasks in this workspace
    task_del_query = ws_clause if ws_clause else {}
    await tasks_col.delete_many(task_del_query)
    
    # 3. Queue fresh tasks for all root domains + all existing subdomains
    all_tasks = []
    for d in domains:
        root_domain = d["domain"]
        is_single = d.get("single_domain_only", False)
        domain_ws_id = str(d.get("workspace_id", ws_id_str))
        
        domain_tasks = [
            {"root_domain": root_domain, "target": root_domain, "task_type": "osint", "status": "pending", "created_at": now, "workspace_id": domain_ws_id},
            {"root_domain": root_domain, "target": root_domain, "task_type": "archive_urls", "status": "pending", "created_at": now, "workspace_id": domain_ws_id},
            {"root_domain": root_domain, "target": root_domain, "task_type": "waf_detect", "status": "pending", "created_at": now, "workspace_id": domain_ws_id},
            {"root_domain": root_domain, "target": root_domain, "task_type": "lb_detect", "status": "pending", "created_at": now, "workspace_id": domain_ws_id},
            {"root_domain": root_domain, "target": root_domain, "task_type": "cloud_storage_audit", "status": "pending", "created_at": now, "workspace_id": domain_ws_id}
        ]
        if is_single:
            domain_tasks.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "verification", "status": "pending", "created_at": now, "workspace_id": domain_ws_id})
            domain_tasks.insert(1, {"root_domain": root_domain, "target": root_domain, "task_type": "scan", "status": "pending", "created_at": now, "workspace_id": domain_ws_id})
        else:
            domain_tasks.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "discovery", "status": "pending", "created_at": now, "workspace_id": domain_ws_id})
            
        subs = (d.get("infrastructure") or {}).get("subdomains", [])
        for sub in subs:
            sub_name = sub.get("name") if isinstance(sub, dict) else sub
            if sub_name and sub_name != root_domain:
                domain_tasks.append({
                    "root_domain": root_domain,
                    "target": sub_name,
                    "task_type": "verification",
                    "status": "pending",
                    "created_at": now,
                    "workspace_id": domain_ws_id
                })
                
        all_tasks.extend(domain_tasks)
        
    if all_tasks:
        await tasks_col.insert_many(all_tasks)
        
    await log_audit(user["username"], "RESCAN_ALL", f"Initiated workspace rescan across {len(domains)} domains with {len(all_tasks)} tasks queued", request)
    return {
        "status": "success",
        "message": f"Workspace rescan initiated! Reset {len(domains)} domains and queued {len(all_tasks)} tasks.",
        "domains_count": len(domains),
        "tasks_count": len(all_tasks)
    }

# --- Bulk Actions Endpoints ---

@app.post("/api/domains/bulk-update-status")
@limiter.limit("5/minute")
async def bulk_update_status(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    data = await request.json()
    status_val = data.get("status")
    
    if status_val not in ["pending", "scanned", "on_hold"]:
        raise HTTPException(status_code=400, detail="Invalid status")
        
    scanned_flag = True if status_val == "scanned" else False
    on_hold_flag = True if status_val == "on_hold" else False

    if data.get("apply_to_all"):
        active_ws = await get_active_workspace(user, request)
        ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))
        q = data.get("q")
        status_val_filter = data.get("status_val")
        blacklisted = data.get("blacklisted")
        root_query = get_query_filters(q, status_val_filter, None, None, blacklisted, ws_clause=ws_clause)
        pipeline = get_flattened_pipeline(root_query, q, status_val_filter)
        pipeline.append({"$group": {"_id": "$_id"}})
        cursor = domains_col.aggregate(pipeline)
        ids = [doc["_id"] for doc in await cursor.to_list(length=None)]
    else:
        ids = [ObjectId(id_str) for id_str in data.get("ids", [])]

    if not ids:
        return {"status": "success", "message": "No domains to update"}
    
    await domains_col.update_many(
        {"_id": {"$in": ids}},
        {"$set": {"scanned": scanned_flag, "on_hold": on_hold_flag}}
    )
    
    await log_audit(user["username"], "BULK_UPDATE_STATUS", f"Updated status of {len(ids)} domains to {status_val}", request)
    return {"status": "success"}

@app.post("/api/domains/bulk-delete")
@limiter.limit("5/minute")
async def bulk_delete_domains(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
        
    data = await request.json()
    
    if data.get("apply_to_all"):
        active_ws = await get_active_workspace(user, request)
        ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))
        q = data.get("q")
        status_val_filter = data.get("status_val")
        blacklisted = data.get("blacklisted")
        root_query = get_query_filters(q, status_val_filter, None, None, blacklisted, ws_clause=ws_clause)
        pipeline = get_flattened_pipeline(root_query, q, status_val_filter)
        pipeline.append({"$group": {"_id": "$_id"}})
        cursor = domains_col.aggregate(pipeline)
        ids = [doc["_id"] for doc in await cursor.to_list(length=None)]
    else:
        ids = [ObjectId(id_str) for id_str in data.get("ids", [])]

    if not ids:
        return {"status": "success", "message": "No domains to delete"}

    docs = await domains_col.find({"_id": {"$in": ids}}, {"domain": 1}).to_list(length=None)
    domain_names = [d["domain"] for d in docs if "domain" in d]

    await domains_col.delete_many({"_id": {"$in": ids}})
    if domain_names:
        await tasks_col.delete_many({"root_domain": {"$in": domain_names}})
        for dname in domain_names:
            await leads_col.delete_many({"target": {"$regex": re.escape(dname)}})
    
    await log_audit(user["username"], "BULK_DELETE_DOMAINS", f"Deleted {len(ids)} domains", request)
    return {"status": "success"}

@app.post("/api/domains/bulk-blacklist")
async def bulk_blacklist_domains(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
        
    data = await request.json()
    
    if data.get("apply_to_all"):
        active_ws = await get_active_workspace(user, request)
        ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))
        q = data.get("q")
        status_val_filter = data.get("status_val")
        blacklisted = data.get("blacklisted")
        root_query = get_query_filters(q, status_val_filter, None, None, blacklisted, ws_clause=ws_clause)
        pipeline = get_flattened_pipeline(root_query, q, status_val_filter)
        pipeline.append({"$group": {"_id": "$_id"}})
        cursor = domains_col.aggregate(pipeline)
        ids = [doc["_id"] for doc in await cursor.to_list(length=None)]
    else:
        ids = [ObjectId(id_str) for id_str in data.get("ids", [])]

    if not ids:
        return {"status": "success", "message": "No domains to blacklist"}

    await domains_col.update_many(
        {"_id": {"$in": ids}},
        {"$set": {"blacklisted": True, "scanned": False, "on_hold": False}}
    )
    
    await log_audit(user["username"], "BULK_BLACKLIST_DOMAINS", f"Blacklisted {len(ids)} domains", request)
    return {"status": "success"}

# --- Statistics Routes ---

@app.get("/statistics", response_class=HTMLResponse)
async def statistics_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return await render_page(request, "statistics.html", {}, user)

@app.get("/system-resources", response_class=HTMLResponse)
async def system_resources_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return await render_page(request, "resources.html", {}, user)

@app.get("/api/system/resources")
async def get_system_resources_api(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    vitals_raw = read_system_vitals()
    vitals = {
        "status": vitals_raw.get("status", "Normal"),
        "is_warning": vitals_raw.get("is_warning", False),
        "is_critical": vitals_raw.get("is_critical", False),
        "circuit_breaker_threshold": 92.0,
        "cpu": {
            "percent": vitals_raw.get("cpu_percent", 0.0),
            "cores": os.cpu_count() or 1,
            "loadavg": vitals_raw.get("load_average", [0.0, 0.0, 0.0])
        },
        "memory": vitals_raw.get("memory", {}),
        "disk": vitals_raw.get("disk", {}),
        "network": {
            "tcp_established": vitals_raw.get("open_sockets", 0)
        }
    }
    
    # 1. Fetch scanner container heartbeat and RSS memory stats from scanners_col
    containers = []
    async for s in scanners_col.find({}).sort("name", 1):
        hb = s.get("last_heartbeat")
        containers.append({
            "key": s.get("key"),
            "name": s.get("name"),
            "engine": s.get("key"),
            "status": s.get("status", "running"),
            "rss_mb": s.get("rss_mb", 0.0),
            "pid": s.get("pid"),
            "updated_at": hb.strftime("%Y-%m-%d %H:%M:%S UTC") if hb else "Just now"
        })
        
    # 2. Per-workspace resource allocation
    workspaces_load = []
    total_active = 0
    total_pending = 0
    circuit_breaker_active = False
    cb_reason = ""
    
    async for w in workspaces_col.find({}).sort("name", 1):
        w_id = str(w["_id"])
        is_paused = bool(w.get("scan_paused", False))
        pause_reason = w.get("pause_reason", "")
        if is_paused:
            circuit_breaker_active = True
            cb_reason = f"Scanning paused on '{w.get('name')}': {pause_reason}"
        
        processing_count = await tasks_col.count_documents({"workspace_id": w_id, "status": "processing"})
        pending_count = await tasks_col.count_documents({"workspace_id": w_id, "status": "pending"})
        total_active += processing_count
        total_pending += pending_count
        
        est_cpu_share = round(processing_count * 15.0, 1)
        est_ram_mb = round(processing_count * 350.0)
        
        workspaces_load.append({
            "workspace_id": w_id,
            "id": w_id,
            "workspace_name": w.get("name", "Unnamed"),
            "name": w.get("name", "Unnamed"),
            "is_default": bool(w.get("is_default")),
            "scan_paused": is_paused,
            "pause_reason": pause_reason,
            "default_scan_interval": w.get("default_scan_interval", 720),
            "active_tasks": processing_count,
            "processing_tasks": processing_count,
            "pending_tasks": pending_count,
            "est_cpu_pct": est_cpu_share,
            "est_cpu_share": est_cpu_share,
            "est_ram_mb": est_ram_mb
        })
        
    return {
        "vitals": vitals,
        "containers": containers,
        "scanners": containers,
        "workspaces": workspaces_load,
        "total_active_tasks": total_active,
        "total_pending_tasks": total_pending,
        "circuit_breaker_triggered": circuit_breaker_active or vitals_raw.get("is_critical", False),
        "circuit_breaker_reason": cb_reason if cb_reason else ("System vitals reached capacity limits (>=92%)." if vitals_raw.get("is_critical") else ""),
        "timestamp": vitals_raw.get("timestamp")
    }

@app.post("/api/workspaces/{workspace_id}/estimate-resources")
async def estimate_workspace_resources_api(
    workspace_id: str,
    request: Request,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    ws_query = {"_id": ObjectId(workspace_id)} if len(workspace_id) == 24 else {"_id": workspace_id}
    ws = await workspaces_col.find_one(ws_query)
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
        
    w_is_def = bool(ws.get("is_default"))
    dom_clause = workspace_match_clause(str(ws["_id"]), w_is_def)
    dom_count = await domains_col.count_documents(dom_clause)
    
    footprint = estimate_pipeline_footprint(domain_count=max(1, dom_count))
    footprint["workspace_name"] = ws.get("name")
    footprint["domain_count"] = dom_count
    return footprint

@app.post("/api/workspaces/{workspace_id}/pause")
async def pause_workspace_endpoint(
    workspace_id: str,
    request: Request,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    ws_query = {"_id": ObjectId(workspace_id)} if len(workspace_id) == 24 else {"_id": workspace_id}
    ws = await workspaces_col.find_one(ws_query)
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
        
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    reason = body.get("reason", f"Manually paused by {user.get('username', 'user')}")
    
    await workspaces_col.update_one(
        ws_query,
        {"$set": {
            "scan_paused": True,
            "pause_reason": reason,
            "paused_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        }}
    )
    # Reset active processing tasks to pending so workers immediately yield
    reset_res = await tasks_col.update_many(
        {"workspace_id": str(ws["_id"]), "status": "processing"},
        {"$set": {"status": "pending", "paused": True}}
    )
    await log_audit(user["username"], "PAUSE_WORKSPACE", f"Paused scanning on workspace: {ws.get('name')}", request)
    return {"status": "success", "workspace_id": str(ws["_id"]), "scan_paused": True, "reset_tasks": reset_res.modified_count}

@app.post("/api/workspaces/{workspace_id}/resume")
async def resume_workspace_endpoint(
    workspace_id: str,
    request: Request,
    user: dict = Depends(get_current_user)
):
    check_analyst(user)
    ws_query = {"_id": ObjectId(workspace_id)} if len(workspace_id) == 24 else {"_id": workspace_id}
    ws = await workspaces_col.find_one(ws_query)
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
        
    await workspaces_col.update_one(
        ws_query,
        {"$set": {
            "scan_paused": False,
            "pause_reason": "",
            "resumed_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        }}
    )
    await log_audit(user["username"], "RESUME_WORKSPACE", f"Resumed scanning on workspace: {ws.get('name')}", request)
    return {"status": "success", "workspace_id": str(ws["_id"]), "scan_paused": False}

@app.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return await render_page(request, "tools.html", {}, user)

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return await render_page(request, "logs.html", {}, user)

TASK_TOOL_NAMES = {
    "scan": "Port Scanner",
    "port_scan": "Port Scanner",
    "port_scanner": "Port Scanner",
    "verification": "Alive Check",
    "alive_check": "Alive Check",
    "discovery": "Subdomain Discovery",
    "subdomain_discovery": "Subdomain Discovery",
    "tech_fingerprint": "Tech Fingerprinter",
    "tech_detect": "Tech Fingerprinter",
    "tech_fingerprinter": "Tech Fingerprinter",
    "dynamic_js_extract": "Dynamic JS Collector",
    "dynamic_js_collector": "Dynamic JS Collector",
    "cloud_storage_audit": "Cloud Storage Auditor",
    "cloud_storage_auditor": "Cloud Storage Auditor",
    "waf_detect": "WAF Detector",
    "waf_detector": "WAF Detector",
    "lb_detect": "Load Balancer Detector",
    "lb_detector": "Load Balancer Detector",
    "osint": "OSINT Collector",
    "osint_collector": "OSINT Collector",
    "archive_urls": "Archive Hunter",
    "archive_hunter": "Archive Hunter",
    "directory_hunt": "Directory Hunter",
    "directory_hunter": "Directory Hunter",
    "bypass_403": "403 Bypasser",
    "dns_scan": "DNS Scanner",
    "screenshot": "Screenshot Agent",
    "screenshot_agent": "Screenshot Agent",
    "whois": "WHOIS Lookup",
    "whois_lookup": "WHOIS Lookup",
    "source_map_unpacker": "Source Map Recovery",
    "source_code_analyzer": "Source Code Analyzer",
}

@app.get("/api/tasks")
async def get_tasks(
    request: Request,
    task_type: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    task_ws_filter = await task_workspace_match_clause(ws_id, is_def)
    query = task_ws_filter.copy()
    if task_type and task_type != "all":
        query["task_type"] = task_type
    if status and status != "all":
        query["status"] = status
        
    total = await tasks_col.count_documents(query)
    cursor = tasks_col.find(query).sort("created_at", -1).skip((page - 1) * limit).limit(limit)
    tasks = await cursor.to_list(length=limit)
    
    for t in tasks:
        t["_id"] = str(t["_id"])
        raw_type = t.get("task_type") or t.get("tool") or ""
        t["tool_name"] = t.get("tool_name") or TASK_TOOL_NAMES.get(raw_type) or (raw_type.replace("_", " ").title() if raw_type else "Task")
        for field in ["created_at", "started_at", "completed_at"]:
            if t.get(field) and isinstance(t[field], datetime):
                t[field] = t[field].isoformat()
    
    return {"tasks": tasks, "total": total, "page": page, "limit": limit}

@app.get("/api/tasks/stats")
async def get_tasks_stats(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
        
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    ws_c = workspace_match_clause(ws_id, is_def)
    task_ws_filter = await task_workspace_match_clause(ws_id, is_def)

    # 1. Task counts by status
    task_pipeline = [
        {"$match": task_ws_filter},
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]
    task_agg = await tasks_col.aggregate(task_pipeline).to_list(length=20)
    task_counts = {item["_id"]: item["count"] for item in task_agg if item.get("_id")}
    
    completed_tasks = task_counts.get("completed", 0)
    processing_tasks = task_counts.get("processing", 0)
    pending_tasks = task_counts.get("pending", 0)
    failed_tasks = task_counts.get("failed", 0)
    remaining_tasks = pending_tasks + processing_tasks
    total_tasks = completed_tasks + remaining_tasks + failed_tasks
    task_percent = round((completed_tasks / total_tasks * 100), 1) if total_tasks > 0 else 100.0

    # 2. (Sub)domains counts
    root_total = await domains_col.count_documents({"blacklisted": {"$ne": True}, **ws_c})
    root_completed = await domains_col.count_documents({"blacklisted": {"$ne": True}, "scanned": True, **ws_c})
    root_remaining = max(0, root_total - root_completed)
    
    sub_total = 0
    sub_completed = 0
    
    cursor = domains_col.find(
        {"blacklisted": {"$ne": True}, **ws_c},
        {"infrastructure.subdomains": 1, "systems.target": 1}
    )
    async for d in cursor:
        subs = (d.get("infrastructure") or {}).get("subdomains", []) or []
        sub_total += len(subs)
        system_targets = {s.get("target") for s in d.get("systems", []) or []}
        for s in subs:
            s_name = s.get("name") if isinstance(s, dict) else s
            if (isinstance(s, dict) and s.get("scanned")) or s_name in system_targets:
                sub_completed += 1
                
    sub_remaining = max(0, sub_total - sub_completed)
    combined_total = root_total + sub_total
    combined_completed = root_completed + sub_completed
    combined_remaining = max(0, combined_total - combined_completed)
    combined_percent = round((combined_completed / combined_total * 100), 1) if combined_total > 0 else 100.0

    return {
        "tasks": {
            "total": total_tasks,
            "completed": completed_tasks,
            "remaining": remaining_tasks,
            "processing": processing_tasks,
            "pending": pending_tasks,
            "failed": failed_tasks,
            "percent": task_percent
        },
        "domains": {
            "total": combined_total,
            "completed": combined_completed,
            "remaining": combined_remaining,
            "percent": combined_percent,
            "breakdown": {
                "roots": {
                    "total": root_total,
                    "completed": root_completed,
                    "remaining": root_remaining
                },
                "subdomains": {
                    "total": sub_total,
                    "completed": sub_completed,
                    "remaining": sub_remaining
                }
            }
        }
    }

@app.delete("/api/tasks/clear")
async def clear_all_tasks(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    # Only clear completed, failed or very old tasks to avoid killing active ones
    # But user asked to "delete all logs", so we'll delete everything except 'processing'
    # to be safe, or just everything if they really mean EVERYTHING.
    # Let's delete EVERYTHING but log it.
    result = await tasks_col.delete_many({})
    await log_audit(user["username"], "CLEAR_LOGS", f"Deleted {result.deleted_count} task logs", request)
    return {"status": "success", "deleted_count": result.deleted_count}

async def cleanup_old_tasks():
    """Background task to keep only 2 days of logs."""
    while True:
        try:
            retention_limit = datetime.utcnow() - timedelta(days=2)
            # Delete tasks older than 2 days
            result = await tasks_col.delete_many({
                "created_at": {"$lt": retention_limit},
                "status": {"$ne": "processing"} # Don't delete active tasks even if old
            })
            if result.deleted_count > 0:
                print(f"Cleanup: Deleted {result.deleted_count} tasks older than 2 days.")
        except Exception as e:
            print(f"Cleanup Error: {e}")
        await asyncio.sleep(3600) # Run every hour

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_old_tasks())
    try:
        from tools.sync_cloud_footprint import sync_all_cloud_storage
        asyncio.create_task(sync_all_cloud_storage())
    except Exception as e:
        print(f"Failed to start cloud storage sync task: {e}")

    try:
        await domains_col.update_many(
            {
                "$or": [
                    {"scanned": True},
                    {"last_scanned": {"$exists": True, "$nin": ["Never", None, ""]}},
                    {"last_cycle_completed": {"$exists": True, "$nin": [None, ""]}}
                ],
                "initial_scan_completed": {"$exists": False}
            },
            {"$set": {"initial_scan_completed": True, "scan_cycle_count": 1}}
        )
    except Exception as e:
        print(f"Failed to initialize initial_scan_completed for existing domains: {e}")

@app.get("/api/tools")
async def get_tools(user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    tools = await scanners_col.find({}).to_list(length=100)
    now = datetime.utcnow()
    
    results = []
    for t in tools:
        t["_id"] = str(t["_id"])
        last_hb = t.get("last_heartbeat")
        status = t.get("status", "Stopped")
        
        if last_hb:
            if isinstance(last_hb, datetime):
                last_hb_dt = last_hb
            else:
                last_hb_dt = datetime.utcfromtimestamp(last_hb / 1000.0)
            
            if (now - last_hb_dt).total_seconds() > 120:
                # Only mark as stopped if it wasn't already explicitly stopped
                if status != "Stopped":
                    status = "Stopped"
        else:
            status = "Stopped"
            
        t["status"] = status
        results.append(t)
    results.sort(key=lambda x: (x.get("name") or x.get("key") or "").lower())
    return results

@app.get("/api/domains/search-simple")
async def search_simple_domains(request: Request, q: Optional[str] = None, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))

    query = {"blacklisted": {"$ne": True}}
    search_term = (q or "").strip().lower()
    
    if search_term:
        escaped_q = re.escape(search_term)
        query["$or"] = [
            {"domain": {"$regex": escaped_q, "$options": "i"}},
            {"subdomains.subdomain": {"$regex": escaped_q, "$options": "i"}},
            {"infrastructure.subdomains.name": {"$regex": escaped_q, "$options": "i"}},
            {"systems.target": {"$regex": escaped_q, "$options": "i"}},
            {"web_applications.target": {"$regex": escaped_q, "$options": "i"}}
        ]
    
    if ws_clause:
        query = {"$and": [ws_clause, query]}
    
    cursor = domains_col.find(
        query,
        {
            "domain": 1,
            "single_domain_only": 1,
            "subdomains": 1,
            "infrastructure.subdomains": 1,
            "systems.target": 1,
            "web_applications.target": 1,
            "created_at": 1
        }
    ).sort([("domain", 1)]).limit(50)
    
    docs = await cursor.to_list(length=50)
    root_summaries = []
    results = []
    seen_results_targets = set()
    
    for d in docs:
        doc_id = str(d["_id"])
        root_domain = d.get("domain", "").strip()
        is_single = d.get("single_domain_only", False)
        
        # Collect all unique targets/subdomains for this root
        targets_set = set()
        
        # 1. infrastructure.subdomains
        infra = d.get("infrastructure", {})
        if isinstance(infra, dict):
            for s in infra.get("subdomains", []):
                if isinstance(s, dict) and s.get("name"):
                    targets_set.add(s["name"].strip())
                elif isinstance(s, str) and s.strip():
                    targets_set.add(s.strip())
                    
        # 2. systems
        for s in d.get("systems", []):
            if isinstance(s, dict) and s.get("target"):
                targets_set.add(s["target"].strip())
                
        # 3. web_applications
        for w in d.get("web_applications", []):
            if isinstance(w, dict) and w.get("target"):
                targets_set.add(w["target"].strip())
                
        # 4. subdomains
        for s in d.get("subdomains", []):
            if isinstance(s, dict) and s.get("subdomain"):
                targets_set.add(s["subdomain"].strip())
            elif isinstance(s, str) and s.strip():
                targets_set.add(s.strip())
                
        targets_set.discard(root_domain)
        all_subdomains = sorted(list(targets_set))
        
        root_summaries.append({
            "id": doc_id,
            "domain": root_domain,
            "single_domain_only": is_single,
            "subdomains_count": len(all_subdomains),
            "subdomains": all_subdomains[:50]
        })
        
        if search_term:
            # If root domain matches search term, include root item
            if search_term in root_domain.lower() and root_domain.lower() not in seen_results_targets:
                seen_results_targets.add(root_domain.lower())
                results.append({
                    "id": doc_id,
                    "root_domain": root_domain,
                    "target": root_domain,
                    "is_subdomain": False,
                    "single_domain_only": is_single,
                    "subdomains_count": len(all_subdomains)
                })
            
            # Check matching subdomains
            for sub in all_subdomains:
                sub_clean = sub.lower()
                if search_term in sub_clean and sub_clean not in seen_results_targets:
                    seen_results_targets.add(sub_clean)
                    results.append({
                        "id": doc_id,
                        "root_domain": root_domain,
                        "target": sub,
                        "is_subdomain": True,
                        "single_domain_only": is_single,
                        "subdomains_count": len(all_subdomains)
                    })
                    if len(results) >= 60:
                        break
        else:
            # Default: include root domain
            if root_domain.lower() not in seen_results_targets:
                seen_results_targets.add(root_domain.lower())
                results.append({
                    "id": doc_id,
                    "root_domain": root_domain,
                    "target": root_domain,
                    "is_subdomain": False,
                    "single_domain_only": is_single,
                    "subdomains_count": len(all_subdomains)
                })
            
        if len(results) >= 60:
            break
            
    active_domains_count = await domains_col.count_documents({"blacklisted": {"$ne": True}, "on_hold": {"$ne": True}})
    return {"results": results[:60], "root_domains": root_summaries, "active_domains_count": active_domains_count}

def build_tool_tasks(tool_key: str, domain_doc: dict, target: str, priority_val: int, created_at_val: datetime, is_run_all: bool = False) -> list:
    root_domain = domain_doc["domain"]
    target = (target or root_domain).strip()
    is_single = domain_doc.get("single_domain_only", False)
    
    tasks = []
    
    if tool_key == "subdomain_discovery":
        if is_single:
            if is_run_all:
                return []
            raise HTTPException(status_code=400, detail=f"'{root_domain}' is configured as a single-domain target. Subdomain discovery cannot be run on it.")
        tasks.append({
            "root_domain": root_domain,
            "target": root_domain,
            "task_type": "discovery",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key in ["alive_check", "subdomain_alive_check"]:
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "task_type": "verification",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key == "port_scanner":
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "task_type": "scan",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key in ["osint_collector", "osint_agent"]:
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "task_type": "osint",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key == "archive_hunter":
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "task_type": "archive_urls",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key == "waf_detector":
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "task_type": "waf_detect",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key == "lb_detector":
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "task_type": "lb_detect",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key == "tech_fingerprinter":
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "protocol": "https",
            "port": 443,
            "task_type": "tech_fingerprint",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "protocol": "http",
            "port": 80,
            "task_type": "tech_fingerprint",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key == "directory_hunter":
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "protocol": "https",
            "port": 443,
            "task_type": "directory_hunt",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key == "screenshot_agent":
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "protocol": "https",
            "port": 443,
            "task_type": "screenshot",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key == "bypass_403":
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "task_type": "bypass_403",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key in ["js_miner", "dynamic_js_collector", "dynamic_js_recon"]:
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "url": f"https://{target}",
            "task_type": "dynamic_js_extract",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key in ["cloud_storage_auditor", "cloud_storage_audit", "cloud_hunter"]:
        tasks.append({
            "root_domain": root_domain,
            "target": target,
            "task_type": "cloud_storage_audit",
            "status": "pending",
            "priority": priority_val,
            "created_at": created_at_val
        })
        
    elif tool_key in ["whois_lookup", "loop_orchestrator"]:
        pass
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported tool key: {tool_key}")
        
    return tasks

@app.post("/api/tools/{tool_key}/run")
async def run_tool_on_domain(tool_key: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    try:
        body = await request.json()
    except Exception:
        body = {}
        
    domain_id = body.get("domain_id")
    target = body.get("target")
    active_ws = await get_active_workspace(user, request)
    ws_clause = workspace_match_clause(active_ws["_id"], active_ws.get("is_default", False))
    ws_id_str = str(active_ws["_id"])

    top_of_queue = bool(body.get("top_of_queue", False))
    run_all = bool(body.get("run_all", False)) or domain_id == "all"
    
    priority_val = 10 if top_of_queue else 0
    created_at_val = datetime.utcnow() - timedelta(days=365) if top_of_queue else datetime.utcnow()
    priority_txt = " (Top of Queue)" if top_of_queue else ""
    
    # -------------------------------------------------------------
    # CASE A: Run tool across ALL active domains in current workspace
    # -------------------------------------------------------------
    if run_all:
        query = {"blacklisted": {"$ne": True}, "on_hold": {"$ne": True}}
        if ws_clause:
            query = {"$and": [ws_clause, query]}
        cursor = domains_col.find(query)
        eligible_domains = await cursor.to_list(length=None)
        
        if not eligible_domains:
            return {
                "status": "warning",
                "message": "No active domains found in this workspace to run this tool on (all domains on hold or blacklisted).",
                "tasks_queued": 0,
                "domains_count": 0,
                "tool_key": tool_key,
                "top_of_queue": top_of_queue
            }
            
        if tool_key == "whois_lookup":
            await domains_col.update_many(
                query,
                {"$set": {"whois_complete": False}}
            )
            msg = f"Reset WHOIS status for {len(eligible_domains)} active domain(s) to trigger immediate lookup"
            if top_of_queue:
                msg += " (Priority flag noted)"
            await log_audit(user["username"], "RUN_TOOL", f"Triggered WHOIS lookup on all active domains ({len(eligible_domains)} domains){priority_txt}", request)
            return {
                "status": "success",
                "message": msg,
                "tasks_queued": len(eligible_domains),
                "domains_count": len(eligible_domains),
                "tool_key": tool_key,
                "top_of_queue": top_of_queue
            }
            
        elif tool_key == "loop_orchestrator":
            tasks_to_create = []
            for d_doc in eligible_domains:
                r_domain = d_doc["domain"]
                is_single = d_doc.get("single_domain_only", False)
                doc_ws_id = str(d_doc.get("workspace_id", ws_id_str))
                await domains_col.update_one(
                    {"_id": d_doc["_id"]},
                    {"$set": {"scanned": False, "on_hold": False, "last_scanned": "Never"}}
                )
                if is_single:
                    await tasks_col.delete_many({"root_domain": r_domain})
                    tasks_to_create.extend([
                        {"root_domain": r_domain, "target": r_domain, "task_type": "scan", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                        {"root_domain": r_domain, "target": r_domain, "task_type": "osint", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                        {"root_domain": r_domain, "target": r_domain, "task_type": "archive_urls", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                        {"root_domain": r_domain, "target": r_domain, "task_type": "waf_detect", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                        {"root_domain": r_domain, "target": r_domain, "task_type": "lb_detect", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                        {"root_domain": r_domain, "target": r_domain, "task_type": "cloud_storage_audit", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id}
                    ])
                else:
                    tasks_to_create.append({
                        "root_domain": r_domain,
                        "target": r_domain,
                        "task_type": "discovery",
                        "status": "pending",
                        "priority": priority_val,
                        "created_at": created_at_val,
                        "workspace_id": doc_ws_id
                    })
            if tasks_to_create:
                await tasks_col.insert_many(tasks_to_create)
            await log_audit(user["username"], "RUN_TOOL", f"Triggered full loop scan across all active domains ({len(eligible_domains)} domains){priority_txt}", request)
            return {
                "status": "success",
                "message": f"Successfully queued {len(tasks_to_create)} task(s) to restart scan loop across {len(eligible_domains)} active domain(s){priority_txt}",
                "tasks_queued": len(tasks_to_create),
                "domains_count": len(eligible_domains),
                "tool_key": tool_key,
                "top_of_queue": top_of_queue
            }
            
        else:
            tasks_to_create = []
            targeted_domains_count = 0
            for d_doc in eligible_domains:
                r_domain = d_doc["domain"]
                doc_ws_id = str(d_doc.get("workspace_id", ws_id_str))
                t_list = build_tool_tasks(tool_key, d_doc, r_domain, priority_val, created_at_val, is_run_all=True)
                if t_list:
                    for t in t_list:
                        t["workspace_id"] = doc_ws_id
                    tasks_to_create.extend(t_list)
                    targeted_domains_count += 1
                    
            if tasks_to_create:
                await tasks_col.insert_many(tasks_to_create)
                
            await log_audit(user["username"], "RUN_TOOL", f"Triggered {tool_key} on all active domains ({targeted_domains_count} domains, {len(tasks_to_create)} tasks){priority_txt}", request)
            return {
                "status": "success",
                "message": f"Successfully queued {len(tasks_to_create)} task(s) across {targeted_domains_count} active domain(s){priority_txt}",
                "tasks_queued": len(tasks_to_create),
                "domains_count": targeted_domains_count,
                "tool_key": tool_key,
                "top_of_queue": top_of_queue
            }

    # -------------------------------------------------------------
    # CASE B: Run tool on a SINGLE chosen domain / subdomain
    # -------------------------------------------------------------
    if not domain_id:
        raise HTTPException(status_code=400, detail="domain_id is required")
        
    try:
        domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    except Exception:
        domain_doc = await domains_col.find_one({"domain": domain_id})
        
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    root_domain = domain_doc["domain"]
    target = (target or root_domain).strip()
    is_single = domain_doc.get("single_domain_only", False)
    doc_ws_id = str(domain_doc.get("workspace_id", ws_id_str))
    
    if tool_key == "whois_lookup":
        await domains_col.update_one(
            {"_id": domain_doc["_id"]},
            {"$set": {"whois_complete": False}}
        )
        msg = f"Reset WHOIS status for {root_domain} to trigger immediate lookup"
        if top_of_queue:
            msg += " (Priority flag noted)"
        await log_audit(user["username"], "RUN_TOOL", f"Triggered WHOIS lookup on {root_domain}", request)
        return {"status": "success", "message": msg, "tasks_queued": 1, "tool_key": tool_key, "target": target}
        
    elif tool_key == "loop_orchestrator":
        await domains_col.update_one(
            {"_id": domain_doc["_id"]},
            {"$set": {"scanned": False, "on_hold": False, "last_scanned": "Never"}}
        )
        if is_single:
            await tasks_col.delete_many({"root_domain": root_domain})
            tasks_to_create = [
                {"root_domain": root_domain, "target": root_domain, "task_type": "scan", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                {"root_domain": root_domain, "target": root_domain, "task_type": "osint", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                {"root_domain": root_domain, "target": root_domain, "task_type": "archive_urls", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                {"root_domain": root_domain, "target": root_domain, "task_type": "waf_detect", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                {"root_domain": root_domain, "target": root_domain, "task_type": "lb_detect", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id},
                {"root_domain": root_domain, "target": root_domain, "task_type": "cloud_storage_audit", "status": "pending", "priority": priority_val, "created_at": created_at_val, "workspace_id": doc_ws_id}
            ]
        else:
            tasks_to_create = [{
                "root_domain": root_domain,
                "target": root_domain,
                "task_type": "discovery",
                "status": "pending",
                "priority": priority_val,
                "created_at": created_at_val,
                "workspace_id": doc_ws_id
            }]
    else:
        tasks_to_create = build_tool_tasks(tool_key, domain_doc, target, priority_val, created_at_val, is_run_all=False)
        for t in tasks_to_create:
            t["workspace_id"] = doc_ws_id

    if tasks_to_create:
        await tasks_col.insert_many(tasks_to_create)
        
    await log_audit(user["username"], "RUN_TOOL", f"Triggered {tool_key} on {target} [{root_domain}]{priority_txt}", request)
    
    return {
        "status": "success",
        "message": f"Successfully queued {len(tasks_to_create)} task(s) for {target}{priority_txt}",
        "tasks_queued": len(tasks_to_create),
        "tool_key": tool_key,
        "target": target,
        "top_of_queue": top_of_queue
    }


DEFAULT_ALERT_SETTINGS = {
    # Directory & File Hunter
    "sensitive_files_critical": True,
    "sensitive_files_high": True,
    "sensitive_files_diagnostic": True,
    "favicon_fingerprint": True,
    "well_known_mobile_apps": True,
    "well_known_internal_app": True,
    "well_known_openid_configuration": True,
    "http_method_trace_xst": True,
    "http_method_webdav_enabled": True,
    "http_method_arbitrary_write": True,

    # Dynamic JS Collector & API Discovery
    "js_hardcoded_secrets": True,
    "js_cloud_storage_leaks": True,
    "js_cloud_storage_takeover": True,
    "js_source_maps": True,
    "js_jwt_tokens": True,
    "sensitive_comment_leak": True,
    "api_spec_discovered": True,
    "graphql_introspection_enabled": True,
    "graphql_ide_exposed": True,
    "js_hydration_payload_leak": True,
    "js_client_framework_routes": True,
    "js_third_party_tracker_pivots": True,

    # Cloud Storage Auditor
    "cloud_storage_writable": True,
    "cloud_storage_listable": True,

    # 403 Forbidden Bypass
    "bypass_403_success": True,

    # Perimeter & Port Scanner / TLS
    "port_scanner_changes": True,
    "cloud_devops_port_exposed": True,
    "unauthenticated_service_exposed": True,
    "tls_cert_expired": True,
    "tls_cert_expiry": True,
    "tls_internal_domain_leak": True,
    "tls_cert_self_signed": True,

    # OSINT & Mail Security
    "osint_email_spoofing": True,
    "osint_public_buckets": True,
    "weak_dkim_key": True,
    "dnssec_nsec_zone_walk": True,

    # WHOIS & Corporate Entity Correlation
    "whois_sister_domains": True,

    # Historical Archive Hunter
    "archive_historical_leaks": True,
    "historical_subdomain_discovery": True,

    # Tech Fingerprinter & Vulnerability Intel
    "tech_stack_changes": True,
    "security_header_regressions": True,
    "known_vulnerability_detected": True,
    "insecure_cookie_configuration": True,

    # WAF & Edge Infrastructure
    "waf_protection_gap": True,
    "waf_origin_bypass": True,

    # DNS & Origin Uncloaking
    "dual_stack_origin_exposure": True,
    "origin_ip_exposed": True,
    "dangling_dns_takeover": True
}

DEFAULT_SCANNING_SETTINGS = {
    "auto_file_search": True,
    "auto_unpack_sourcemaps": True,
    "rate_delay_ms": 0
}

DEFAULT_API_KEY_SETTINGS = {
    "shodan_api_key": "",
    "nvd_api_key": ""
}

@app.get("/api/settings")
async def get_settings(user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    settings = await settings_col.find_one({"key": "global_settings"})
    if not settings:
        settings = {
            "key": "global_settings",
            "scan_pause": False,
            "theme": "dark",
            "alerts": DEFAULT_ALERT_SETTINGS.copy(),
            "scanning": DEFAULT_SCANNING_SETTINGS.copy(),
            "api_keys": DEFAULT_API_KEY_SETTINGS.copy()
        }
        await settings_col.insert_one(settings)
    else:
        # Ensure all alert default keys exist
        if "alerts" not in settings or not isinstance(settings["alerts"], dict):
            settings["alerts"] = DEFAULT_ALERT_SETTINGS.copy()
        else:
            for k, v in DEFAULT_ALERT_SETTINGS.items():
                if k not in settings["alerts"]:
                    settings["alerts"][k] = v

        if "scanning" not in settings or not isinstance(settings["scanning"], dict):
            settings["scanning"] = DEFAULT_SCANNING_SETTINGS.copy()
        else:
            for k, v in DEFAULT_SCANNING_SETTINGS.items():
                if k not in settings["scanning"]:
                    settings["scanning"][k] = v

        if "api_keys" not in settings or not isinstance(settings["api_keys"], dict):
            settings["api_keys"] = DEFAULT_API_KEY_SETTINGS.copy()
        else:
            for k, v in DEFAULT_API_KEY_SETTINGS.items():
                if k not in settings["api_keys"]:
                    settings["api_keys"][k] = v

        if "theme" not in settings:
            settings["theme"] = "dark"

    # Fetch stats for maintenance cards
    from app.database import db
    fingerprints_col = db["alert_fingerprints"]
    suppressed_count = await fingerprints_col.count_documents({"status": "suppressed"})
    processing_tasks_count = await tasks_col.count_documents({"status": "processing"})
    pending_tasks_count = await tasks_col.count_documents({"status": "pending"})

    settings["_id"] = str(settings["_id"])
    settings["suppressed_fingerprints_count"] = suppressed_count
    settings["processing_tasks_count"] = processing_tasks_count
    settings["pending_tasks_count"] = pending_tasks_count
    return settings

@app.put("/api/settings")
async def update_settings(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    data = await request.json()
    update_doc = {}

    if "alerts" in data and isinstance(data["alerts"], dict):
        update_doc["alerts"] = data["alerts"]

    if "scanning" in data and isinstance(data["scanning"], dict):
        update_doc["scanning"] = data["scanning"]

    if "api_keys" in data and isinstance(data["api_keys"], dict):
        curr_settings = await settings_col.find_one({"key": "global_settings"})
        existing_keys = (curr_settings.get("api_keys", {}) if curr_settings else {}) or {}
        new_keys = {}
        for k in ["shodan_api_key", "nvd_api_key"]:
            val = data["api_keys"].get(k)
            if val is not None:
                val_str = str(val).strip()
                if val_str.startswith("••••") or val_str.startswith("****"):
                    new_keys[k] = existing_keys.get(k, "")
                else:
                    new_keys[k] = val_str
            else:
                new_keys[k] = existing_keys.get(k, "")
        update_doc["api_keys"] = new_keys

    if "theme" in data:
        update_doc["theme"] = "dark" if data["theme"] == "dark" else "light"

    if "scan_pause" in data:
        update_doc["scan_pause"] = bool(data["scan_pause"])

    if update_doc:
        await settings_col.update_one(
            {"key": "global_settings"},
            {"$set": update_doc},
            upsert=True
        )
        await log_audit(user["username"], "UPDATE_SETTINGS", "Updated global system settings", request)

    return {"status": "success", "settings": update_doc}

@app.post("/api/settings/test-shodan")
async def test_shodan_key_endpoint(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    data = await request.json()
    key = data.get("api_key", "").strip()
    if not key or key.startswith("••••") or key.startswith("****"):
        settings = await settings_col.find_one({"key": "global_settings"})
        key = (settings.get("api_keys", {}).get("shodan_api_key") if settings else "") or ""
    if not key:
        return {"valid": False, "error": "No Shodan API key provided or configured."}

    import urllib.request
    import urllib.error
    url = f"https://api.shodan.io/api-info?key={key}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": COMMON_USER_AGENT})
        loop = asyncio.get_event_loop()
        def _fetch():
            with urllib.request.urlopen(req, timeout=10) as resp:
                import json
                return resp.getcode(), json.loads(resp.read().decode())
        code, body = await loop.run_in_executor(None, _fetch)
        if code == 200:
            return {
                "valid": True,
                "plan": body.get("plan", "Standard"),
                "query_credits": body.get("query_credits", 0),
                "scan_credits": body.get("scan_credits", 0)
            }
        return {"valid": False, "error": f"Shodan API returned status {code}"}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"valid": False, "error": "Invalid Shodan API key (Authentication failed / 401 Unauthorized)."}
        return {"valid": False, "error": f"Shodan API error (HTTP {e.code})"}
    except Exception as e:
        return {"valid": False, "error": f"Connection error: {str(e)}"}

@app.post("/api/settings/test-nvd")
async def test_nvd_key_endpoint(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    data = await request.json()
    key = data.get("api_key", "").strip()
    if not key or key.startswith("••••") or key.startswith("****"):
        settings = await settings_col.find_one({"key": "global_settings"})
        key = (settings.get("api_keys", {}).get("nvd_api_key") if settings else "") or ""
    if not key:
        return {"valid": False, "error": "No NIST NVD API key provided or configured."}

    import urllib.request
    import urllib.error
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
    try:
        req = urllib.request.Request(url, headers={"apiKey": key, "User-Agent": COMMON_USER_AGENT})
        loop = asyncio.get_event_loop()
        def _fetch():
            with urllib.request.urlopen(req, timeout=10) as resp:
                import json
                return resp.getcode(), json.loads(resp.read().decode())
        code, body = await loop.run_in_executor(None, _fetch)
        if code == 200:
            return {"valid": True, "message": "NIST NVD API key validated successfully. Rate limit bumped to 50 req/30s."}
        return {"valid": False, "error": f"NVD API returned status {code}"}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"valid": False, "error": "Invalid NIST NVD API key (403 Forbidden). Ensure your key is activated."}
        elif e.code == 429:
            return {"valid": False, "error": "Rate limit exceeded on NIST NVD API."}
        return {"valid": False, "error": f"NVD API error (HTTP {e.code})"}
    except Exception as e:
        return {"valid": False, "error": f"Connection error: {str(e)}"}

@app.post("/api/settings/reset-alerts")
async def reset_alerts_settings(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    await settings_col.update_one(
        {"key": "global_settings"},
        {"$set": {"alerts": DEFAULT_ALERT_SETTINGS.copy()}},
        upsert=True
    )
    await log_audit(user["username"], "RESET_ALERT_SETTINGS", "Reset all alert settings to defaults", request)
    return {"status": "success", "alerts": DEFAULT_ALERT_SETTINGS}

@app.post("/api/settings/unmute-all-fingerprints")
async def unmute_all_fingerprints(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    from app.database import db
    fingerprints_col = db["alert_fingerprints"]
    res = await fingerprints_col.delete_many({"status": "suppressed"})
    await log_audit(user["username"], "UNMUTE_ALL_FINGERPRINTS", f"Unmuted {res.deleted_count} suppressed alert fingerprints", request)
    return {"status": "success", "unmuted_count": res.deleted_count}

@app.post("/api/settings/recover-stuck-tasks")
async def recover_stuck_tasks(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    res = await tasks_col.update_many(
        {"status": "processing"},
        {"$set": {"status": "pending", "recovered_at": datetime.utcnow()}}
    )
    await log_audit(user["username"], "RECOVER_STUCK_TASKS", f"Recovered {res.modified_count} stuck tasks to pending", request)
    return {"status": "success", "recovered_count": res.modified_count}

@app.post("/api/settings/toggle-pause")
async def toggle_scan_pause(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    settings = await settings_col.find_one({"key": "global_settings"})
    current_state = settings.get("scan_pause", False) if settings else False
    new_state = not current_state
    
    await settings_col.update_one(
        {"key": "global_settings"},
        {"$set": {"scan_pause": new_state}},
        upsert=True
    )
    
    await log_audit(user["username"], "TOGGLE_SCAN_PAUSE", f"{'Paused' if new_state else 'Resumed'} all scanning activity", request)
    return {"status": "success", "scan_pause": new_state}

@app.post("/api/settings/pause-scanning")
async def pause_scanning(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    await settings_col.update_one(
        {"key": "global_settings"},
        {"$set": {"scan_pause": True}},
        upsert=True
    )
    
    await log_audit(user["username"], "PAUSE_SCANNING", "Stopped all scanning activity", request)
    return {"status": "success", "scan_pause": True}

@app.post("/api/settings/continue-scanning")
async def continue_scanning(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)

    # 1. Unpause global scanning if paused
    await settings_col.update_one(
        {"key": "global_settings"},
        {"$set": {"scan_pause": False}},
        upsert=True
    )

    # 2. Recover any tasks stuck in processing (e.g. from standby / sleep) back to pending
    proc_reset = await tasks_col.update_many(
        {"status": "processing"},
        {"$set": {"status": "pending", "recovered_at": datetime.utcnow()}}
    )

    # 3. Check count of pending tasks
    pending_count = await tasks_col.count_documents({"status": "pending"})

    restarted_domains = []
    # 4. If queue is completely idle (0 pending), restart scan cycle for all active domains
    if pending_count == 0:
        cursor = domains_col.find({
            "blacklisted": {"$ne": True},
            "on_hold": {"$ne": True}
        })
        async for domain in cursor:
            root_domain = domain["domain"]
            is_single = domain.get("single_domain_only", False)

            # Reset completion flags
            await domains_col.update_one(
                {"_id": domain["_id"]},
                {"$set": {
                    "scanned": False,
                    "osint_complete": False,
                    "archive_hunter_complete": False,
                    "last_cycle_completed": domain.get("last_scanned")
                }}
            )

            # Clean stale tasks and queue fresh initial cycle tasks
            await tasks_col.delete_many({"root_domain": root_domain})
            cycle_tasks = [
                {"root_domain": root_domain, "target": root_domain, "task_type": "osint", "status": "pending", "created_at": datetime.utcnow()},
                {"root_domain": root_domain, "target": root_domain, "task_type": "archive_urls", "status": "pending", "created_at": datetime.utcnow()},
                {"root_domain": root_domain, "target": root_domain, "task_type": "waf_detect", "status": "pending", "created_at": datetime.utcnow()},
                {"root_domain": root_domain, "target": root_domain, "task_type": "lb_detect", "status": "pending", "created_at": datetime.utcnow()}
            ]
            if is_single:
                cycle_tasks.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "scan", "status": "pending", "created_at": datetime.utcnow()})
            else:
                cycle_tasks.insert(0, {"root_domain": root_domain, "target": root_domain, "task_type": "discovery", "status": "pending", "created_at": datetime.utcnow()})

            await tasks_col.insert_many(cycle_tasks)
            restarted_domains.append(root_domain)
            pending_count += len(cycle_tasks)

    msg = f"Continued scanning: {pending_count} pending tasks active across {len(restarted_domains)} domain(s)."
    await log_audit(user["username"], "CONTINUE_SCANNING", msg, request)
    return {
        "status": "success",
        "scan_pause": False,
        "recovered_processing": proc_reset.modified_count,
        "pending_tasks": pending_count,
        "restarted_domains": restarted_domains,
        "message": msg
    }

@app.get("/api/stats/dashboard")
async def get_stats_dashboard(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    active_ws = await get_active_workspace(user, request)
    ws_id = str(active_ws["_id"])
    is_def = bool(active_ws.get("is_default"))
    ws_clause = workspace_match_clause(ws_id, is_def)

    # 1. Domain Status Distribution (Using flattened pipeline to count all assets)
    all_assets_pipeline = get_flattened_pipeline({"blacklisted": {"$ne": True}, **ws_clause})
    all_assets_pipeline.append({"$count": "total"})
    all_assets_result = await domains_col.aggregate(all_assets_pipeline).to_list(length=1)
    total_assets = all_assets_result[0]["total"] if all_assets_result else 0
    
    scanned_pipeline = get_flattened_pipeline({"blacklisted": {"$ne": True}, **ws_clause}, status_val="scanned")
    scanned_pipeline.append({"$count": "total"})
    scanned_result = await domains_col.aggregate(scanned_pipeline).to_list(length=1)
    scanned_count = scanned_result[0]["total"] if scanned_result else 0
    
    pending_pipeline = get_flattened_pipeline({"blacklisted": {"$ne": True}, **ws_clause}, status_val="pending")
    pending_pipeline.append({"$count": "total"})
    pending_result = await domains_col.aggregate(pending_pipeline).to_list(length=1)
    pending_count = pending_result[0]["total"] if pending_result else 0

    on_hold_count = await domains_col.count_documents({"on_hold": True, **ws_clause})
    blacklisted_count = await domains_col.count_documents({"blacklisted": True, **ws_clause})
    
    # 2. Risk Distribution (Leads)
    risk_agg = await leads_col.aggregate([
        {"$match": ws_clause},
        {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]).to_list(length=20)
    risk_data = {r["_id"]: r["count"] for r in risk_agg}
    
    # 3. Top Technologies & Headers (Separated)
    all_tech_agg = await domains_col.aggregate([
        {"$match": {"web_applications": {"$exists": True, "$not": {"$size": 0}, "$ne": None}, **ws_clause}},
        {"$unwind": "$web_applications"},
        {"$unwind": "$web_applications.tech_stack"},
        {"$group": {"_id": "$web_applications.tech_stack", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]).to_list(length=100)
    
    # Heuristic for headers: starts with x-, starts with X-, or in known list
    header_keywords = [
        "httpserver", "via-proxy", "redirectlocation", "uncommonheaders", "cookies",
        "via", "server", "alt-svc", "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-xss-protection", "x-content-type-options", "access-control-allow-origin",
        "country", "script", "html5"
    ]
    
    tech_list = []
    header_list = []
    
    for item in all_tech_agg:
        name = item["_id"].strip().rstrip("]")
        name_lower = name.lower()
        
        is_header = (
            name_lower.startswith("x-") or 
            any(k in name_lower for k in header_keywords) or
            "-" in name # Most headers have hyphens, few technologies do
        )
        
        # Exceptions (technologies that have hyphens or match keywords)
        if name_lower in ["html5", "node-js", "next-js", "react-router"]:
            is_header = False

        if is_header:
            header_list.append({"name": name, "count": item["count"]})
        else:
            tech_list.append({"name": name, "count": item["count"]})
            
    # 4. Recent Activity (Last 14 days)
    now = datetime.utcnow()
    activity = []
    for i in range(14):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        count = await leads_col.count_documents({"timestamp": {"$regex": f"^{day}"}, **ws_clause})
        activity.append({"date": day, "count": count})
    activity.reverse()
    
    # 5. Geographic (MOCK/SAMPLE derived from IPs)
    geo_agg = await domains_col.aggregate([
        {"$match": {"systems": {"$exists": True, "$not": {"$size": 0}, "$ne": None}, **ws_clause}},
        {"$project": {"ip": {"$arrayElemAt": ["$systems.ip", 0]}}},
        {"$limit": 2000}
    ]).to_list(length=2000)
    
    geo_counts = {}
    for g in geo_agg:
        ip = g.get("ip")
        if ip:
            code = get_country_code(ip)
            geo_counts[code] = geo_counts.get(code, 0) + 1
    
    top_countries = sorted(geo_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # 6. WAF/CDN Providers
    waf_agg = await domains_col.aggregate([
        {"$match": {"infrastructure.waf_cdn.provider": {"$exists": True, "$ne": ""}}},
        {"$group": {"_id": "$infrastructure.waf_cdn.provider", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]).to_list(length=10)

    # 7. Top Ports
    ports_agg = await domains_col.aggregate([
        {"$match": {"systems": {"$exists": True, "$not": {"$size": 0}, "$ne": None}}},
        {"$unwind": "$systems"},
        {"$unwind": "$systems.services"},
        {"$group": {"_id": "$systems.services.port", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]).to_list(length=10)

    # 8. Software Distribution
    software_agg = await domains_col.aggregate([
        {"$match": {"systems": {"$exists": True, "$not": {"$size": 0}, "$ne": None}}},
        {"$unwind": "$systems"},
        {"$unwind": "$systems.services"},
        {"$match": {"systems.services.software": {"$exists": True, "$ne": ""}}},
        {"$group": {"_id": "$systems.services.software", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]).to_list(length=10)

    # 9. Top TLDs
    tld_agg = await domains_col.aggregate([
        {"$project": {
            "tld": {"$arrayElemAt": [{"$split": ["$domain", "."]}, -1]}
        }},
        {"$group": {"_id": "$tld", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]).to_list(length=10)

    # 10. Top Domains by Subdomain Count
    subdomain_counts = await domains_col.aggregate([
        {"$project": {
            "domain": 1,
            "subdomain_count": {
                "$cond": {
                    "if": {"$isArray": "$infrastructure.subdomains"},
                    "then": {"$size": "$infrastructure.subdomains"},
                    "else": 0
                }
            }
        }},
        {"$sort": {"subdomain_count": -1}},
        {"$limit": 10}
    ]).to_list(length=10)

    return {
        "inventory": {
            "total": total_assets,
            "scanned": scanned_count,
            "pending": pending_count,
            "on_hold": on_hold_count,
            "blacklisted": blacklisted_count
        },
        "risk": risk_data,
        "tech": tech_list[:15],
        "headers": header_list[:15],
        "activity": activity,
        "geo": [{"code": c[0], "count": c[1]} for c in top_countries],
        "waf": [{"name": w["_id"], "count": w["count"]} for w in waf_agg],
        "ports": [{"port": str(p["_id"]), "count": p["count"]} for p in ports_agg],
        "software": [{"name": s["_id"], "count": s["count"]} for s in software_agg],
        "tlds": [{"name": t["_id"], "count": t["count"]} for t in tld_agg],
        "subdomain_counts": [{"name": s["domain"], "count": s["subdomain_count"]} for s in subdomain_counts]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
