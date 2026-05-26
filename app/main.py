from bson import ObjectId
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Optional, List
import os
import io
import pandas as pd
import asyncio

from datetime import datetime, timedelta
import re

from app.database import domains_col, users_col, audit_logs_col, leads_col, scanners_col, settings_col, tasks_col
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
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from jose import jwt, JWTError

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

templates = Jinja2Templates(directory="templates")

# Security Middleware for Headers
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data: https://flagcdn.com; font-src 'self' data:; frame-ancestors 'none';"
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

def get_flattened_pipeline(root_query: dict, q: Optional[str] = None, status_val: Optional[str] = None, tech: Optional[str] = None, port: Optional[int] = None):
    pipeline = [
        {"$match": root_query},
        {
            "$project": {
                "targets": {
                    "$reduce": {
                        "input": {
                            "$concatArrays": [
                                [{"name": "$domain", "is_root": True, "added_at": "$added_at"}],
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
                "systems": {"$ifNull": ["$systems", []]},
                "web_applications": {"$ifNull": ["$web_applications", []]},
                "scanned": 1,
                "blacklisted": 1,
                "on_hold": 1,
                "added_at": 1,
                "scan_interval": 1
            }
        },
        {"$unwind": "$targets"},
        {
            "$project": {
                "domain": "$targets.name",
                "root_domain": "$domain",
                "is_root": {"$ifNull": ["$targets.is_root", False]},
                "scanned_flag": "$scanned",
                "on_hold_flag": "$on_hold",
                "scan_interval": {"$ifNull": ["$scan_interval", 24]},
                "subdomain_count": 1,
                "recon_date": {"$ifNull": ["$targets.added_at", "$added_at"]},
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
                }
            }
        }
    ]
    
    # Apply filters after flattening
    match_stage = {}
    if q:
        safe_q = re.escape(q)
        match_stage["$or"] = [
            {"domain": {"$regex": safe_q, "$options": "i"}},
            {"system.services.software": {"$regex": safe_q, "$options": "i"}},
            {"system.services.service": {"$regex": safe_q, "$options": "i"}}
        ]
    
    if tech:
        match_stage["web_app.tech_stack"] = {"$regex": re.escape(tech), "$options": "i"}
        
    if port:
        match_stage["system.services.port"] = port

    if status_val:
        if status_val == "scanned":
            # Consider an asset scanned if it has system data OR is a root marked as scanned
            pipeline.append({"$match": {"$or": [
                {"system": {"$ne": None}},
                {"$and": [{"is_root": True}, {"scanned_flag": True}]}
            ]}})
        elif status_val == "pending":
            pipeline.append({"$match": {"$and": [
                {"system": None},
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

def get_query_filters(q: Optional[str], status_val: Optional[str], has_subdomains: Optional[str], tech: Optional[str], blacklisted: Optional[str], port: Optional[int] = None):
    query = {}
    
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
async def root(request: Request, user: Optional[dict] = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, "login.html")

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, username: str = Form(...), password: str = Form(...), totp_code: str = Form(...)):
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
    
    if not verify_totp(user["totp_secret"], totp_code):
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
    return templates.TemplateResponse(request, "dashboard.html", {"user": user})

@app.get("/search")
async def search(request: Request, q: str, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    # Clean query
    q = q.strip().lower()
    
    # 1. Try exact domain match
    domain_data = await domains_col.find_one({"domain": q})
    
    # 2. Try exact subdomain match if no direct domain match
    if not domain_data:
        domain_data = await domains_col.find_one({"infrastructure.subdomains.name": q})
    
    # 3. Fallback to partial match on domain
    if not domain_data:
        domain_data = await domains_col.find_one({"domain": {"$regex": re.escape(q), "$options": "i"}})
    
    if not domain_data:
        return {"error": "Domain not found"}
    
    await log_audit(user["username"], "query", f"Searched for domain: {q}", request)
    
    # Get stats for this domain
    domain_name = domain_data["domain"]
    
    # Collect all possible targets for this domain (subdomains and IPs)
    targets = [domain_name]
    if domain_data.get("infrastructure") and domain_data["infrastructure"].get("subdomains"):
        for sub in domain_data["infrastructure"]["subdomains"]:
            if sub.get("name"): targets.append(sub["name"])
            if sub.get("ip"): targets.append(sub["ip"])
    
    # Limit targets list size to avoid MongoDB query limits if necessary, 
    # but for now we'll try $in.
    # Statuses: ['false_positive', 'in_progress', 'new', 'true_positive']
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
        if domain_data.get("systems"):
            domain_data["systems"] = [s for s in domain_data["systems"] if s.get("target") == q]
        if domain_data.get("web_applications"):
            domain_data["web_applications"] = [w for w in domain_data["web_applications"] if w.get("target") == q]
    else:
        # If looking at root domain, only show systems/webapps for the root domain itself
        if domain_data.get("systems"):
            domain_data["systems"] = [s for s in domain_data["systems"] if s.get("target") == domain_name]
        if domain_data.get("web_applications"):
            domain_data["web_applications"] = [w for w in domain_data["web_applications"] if w.get("target") == domain_name]
            
    return domain_data

@app.get("/api/suggestions")
async def get_suggestions(q: str, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    if len(q) < 2:
        return []
    
    # Find up to 5 domains containing 'q' (case-insensitive)
    cursor = domains_col.find({"domain": {"$regex": re.escape(q), "$options": "i"}}, {"domain": 1}).limit(5)
    results = await cursor.to_list(length=5)
    return [r["domain"] for r in results]

from functools import lru_cache

@lru_cache(maxsize=1024)
def get_country_code(ip: str) -> str:
    """Very basic mock/heuristic for country code since we lack a GeoIP lib."""
    if not ip or ip == "N/A" or ip.startswith("10.") or ip.startswith("192.168."):
        return "US" # Default
    # In a real app, we'd use geoip2 or an API. 
    # For now, let's just rotate some codes based on the last digit of the IP for variety in the demo.
    try:
        last_digit = int(ip.split(".")[-1])
        codes = ["GB", "US", "RU", "DE", "FR", "CN", "JP", "IN", "BR", "CA"]
        return codes[last_digit % len(codes)]
    except:
        return "US"

@app.get("/api/subdomains")
async def get_subdomains(
    page: int = 1,
    limit: int = 20,
    q: Optional[str] = None,
    status_val: Optional[str] = None,
    has_subdomains: Optional[str] = None,
    tech: Optional[str] = None,
    port: Optional[int] = None,
    sort_by: str = "domain",
    sort_dir: str = "asc",
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)

    root_query = get_query_filters(q, status_val, has_subdomains, tech, None, port)
    pipeline = get_flattened_pipeline(root_query, q, status_val, tech, port)
    
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
        
        ip = system_info.get("ip", "N/A")
        tech_stack = web_app_info.get("tech_stack", [])
        
        # Determine scanned status: 
        # If we have system info, it's definitely scanned. Fallback to root's scanned_flag.
        is_scanned = True if d.get("system") else (d.get("scanned_flag", False) if d.get("is_root") else False)
        
        results.append({
            "id": str(d["_id"]),
            "domain": d["domain"],
            "ip": ip,
            "scanned": is_scanned,
            "subdomain_count": d.get("subdomain_count", 0) if d.get("is_root") else 0,
            "technologies": tech_stack[:5],
            "tech_str": ", ".join(tech_stack),
            "country_id": get_country_code(ip),
            "recon_date": d.get("recon_date", "N/A"),
            "last_scanned": system_info.get("last_scanned", "Never")
        })

    # Calculate total scanned assets globally (root + subdomains)
    scanned_pipeline = get_flattened_pipeline({"blacklisted": {"$ne": True}}, status_val="scanned")
    scanned_pipeline.append({"$count": "total"})
    scanned_result = await domains_col.aggregate(scanned_pipeline).to_list(length=1)
    scanned_total = scanned_result[0]["total"] if scanned_result else 0
    
    return {"subdomains": results, "total": total, "scanned_total": scanned_total, "page": page, "limit": limit}

@app.get("/api/subdomains/export")
async def export_subdomains(
    q: Optional[str] = None,
    status_val: Optional[str] = None,
    has_subdomains: Optional[str] = None,
    tech: Optional[str] = None,
    sort_by: str = "domain",
    sort_dir: str = "asc",
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    root_query = get_query_filters(q, status_val, has_subdomains, tech, None)
    pipeline = get_flattened_pipeline(root_query, q, status_val, tech)
    
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
        
        ip = system_info.get("ip", "N/A")
        tech_stack = web_app_info.get("tech_stack", [])
        is_scanned = True if d.get("system") else (d.get("scanned_flag", False) if d.get("is_root") else False)
        
        data.append({
            "Domain": d["domain"],
            "Status": "Scanned" if is_scanned else "Pending",
            "IP Address": ip,
            "Country": get_country_code(ip),
            "Type": "Root" if d.get("is_root") else "Subdomain",
            "Technologies": ", ".join(tech_stack),
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
    return templates.TemplateResponse(request, "admin.html", {"user": user})

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


def build_leads_query(status, risk, title, target, status_code, start_date, end_date, source=None):
    query = {}
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
    return templates.TemplateResponse(request, "alerts.html", {"user": user})

@app.get("/investigate", response_class=HTMLResponse)
async def investigate_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, "investigate.html", {"user": user})

@app.get("/api/leads")
async def get_leads(
    status: Optional[str] = None,
    risk: Optional[str] = None,
    title: Optional[str] = None,
    target: Optional[str] = None,
    source: Optional[str] = None,
    status_code: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    query = build_leads_query(status, risk, title, target, status_code, start_date, end_date, source=source)
            
    cursor = leads_col.find(query).sort("timestamp", -1)
    leads = await cursor.to_list(length=100)
    for lead in leads:
        lead["_id"] = str(lead["_id"])
    
    total_count = await leads_col.count_documents({})
    filtered_count = await leads_col.count_documents(query)
    
    return {
        "leads": leads,
        "total_count": total_count,
        "filtered_count": filtered_count
    }

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
    
    await log_audit(user["username"], "MUTE_LEAD", f"Muted/Suppressed lead: {lead['title']} on {lead['target']}", request)

@app.get("/api/leads/sources")
async def get_lead_sources(user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    sources = await leads_col.distinct("source")
    # Filter out None and empty strings
    return [s for s in sources if s]

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
    status: Optional[str] = None,
    risk: Optional[str] = None,
    title: Optional[str] = None,
    target: Optional[str] = None,
    source: Optional[str] = None,
    status_code: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    query = build_leads_query(status, risk, title, target, status_code, start_date, end_date, source=source)
            
    cursor = leads_col.find(query).sort("timestamp", -1)
    leads = await cursor.to_list(length=1000) # Increased limit for export
    
    data = []
    for l in leads:
        data.append({
            "Detected Date": l.get("timestamp"),
            "Status": l.get("status", "new").replace("_", " ").title(),
            "Risk": l.get("risk_level", "low").upper(),
            "Title": l.get("title"),
            "Target": l.get("target"),
            "Notes": l.get("notes", "")
        })
    
    if not data:
        # Create empty df with columns if no data
        df = pd.DataFrame(columns=["Detected Date", "Status", "Risk", "Title", "Target", "Notes"])
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
async def update_lead_status(lead_id: str, request: Request, status: str = Form(...), user: dict = Depends(get_current_user)):
    check_analyst(user)
    await leads_col.update_one({"_id": ObjectId(lead_id)}, {"$set": {"status": status}})
    
    # Auto-mute if status is false_positive or benign
    if status in ["false_positive", "benign"]:
        lead = await leads_col.find_one({"_id": ObjectId(lead_id)})
        if lead:
            await apply_lead_mute(lead, user, request)
            
    return {"status": "success"}

@app.post("/api/leads/{lead_id}/notes")
async def update_lead_notes(lead_id: str, notes: str = Form(...), user: dict = Depends(get_current_user)):
    check_analyst(user)
    await leads_col.update_one({"_id": ObjectId(lead_id)}, {"$set": {"notes": notes}})
    return {"status": "success"}

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
    
    count = await leads_col.count_documents(query)
    await leads_col.delete_many(query)
    await log_audit(user["username"], "BULK_DELETE_LEADS", f"Deleted {count} alerts", request)
    return {"status": "success", "count": count}

@app.post("/api/leads/delete-all")
async def delete_all_leads(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    count = await leads_col.count_documents({})
    await leads_col.delete_many({})
    await log_audit(user["username"], "DELETE_ALL_LEADS", f"Deleted all {count} alerts", request)
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
async def get_notifications_count(user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    # Count leads where status is "new" and acknowledged is either False or missing
    count = await leads_col.count_documents({"status": "new", "acknowledged": {"$ne": True}})
    return {"count": count}

@app.post("/api/notifications/clear")
async def clear_notifications(user: dict = Depends(get_current_user)):
    check_analyst(user)
    # Mark 'new' leads as acknowledged
    await leads_col.update_many({"status": "new", "acknowledged": {"$ne": True}}, {"$set": {"acknowledged": True}})
    return {"status": "success"}

# --- Domain Management Routes ---

@app.get("/domains", response_class=HTMLResponse)
async def domains_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, "domains.html", {"user": user})

@app.get("/api/domains")
async def get_domains(
    page: int = 1, 
    limit: int = 10, 
    q: Optional[str] = None,
    status_val: Optional[str] = None,
    blacklisted: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    root_query = get_query_filters(q, status_val, None, None, blacklisted)
    pipeline = get_flattened_pipeline(root_query, q, status_val)
    
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
        is_scanned = True if d.get("system") else (d.get("scanned_flag", False) if d.get("is_root") else False)
        last_scanned = d.get("system", {}).get("last_scanned") if d.get("system") else (d.get("last_scanned") if d.get("is_root") else "Never")
        
        # Get scan_interval from root domain data if it's a flattened subdomain doc
        # In flattened view, we might need a separate lookup or projected field.
        # For now, we'll try to find it in the projection if possible, but the current project doesn't have it.
        # Let's assume we'll update the pipeline project stage to include it.
        
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
            "scan_interval": d.get("scan_interval", 24) # Default to 24 if not set
        })
    
    return {"domains": results, "total": total, "page": page, "limit": limit}

@app.post("/api/domains/bulk-update-interval")
@limiter.limit("5/minute")
async def bulk_update_interval(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    data = await request.json()
    ids = [ObjectId(id_str) for id_str in data.get("ids", [])]
    interval = data.get("interval")
    
    try:
        interval = int(interval)
        if interval < 1:
            raise ValueError()
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid interval. Must be a positive integer (hours).")
        
    await domains_col.update_many(
        {"_id": {"$in": ids}},
        {"$set": {"scan_interval": interval}}
    )
    
    await log_audit(user["username"], "BULK_UPDATE_INTERVAL", f"Updated scan interval of {len(ids)} domains to {interval} hours", request)
    return {"status": "success"}

@app.post("/api/domains/add")
async def add_domain(request: Request, domain: str = Form(...), user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    # Basic domain validation
    domain = domain.strip().lower()
    if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", domain):
        return {"status": "error", "message": "Invalid domain format"}

    existing = await domains_col.find_one({"domain": domain})
    if existing:
        return {"status": "error", "message": "Domain already exists"}
    
    await domains_col.insert_one({
        "domain": domain,
        "scanned": False,
        "blacklisted": False,
        "notes": "",
        "added_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    })
    
    await log_audit(user["username"], "ADD_DOMAIN", f"Added domain: {domain}", request)
    return {"status": "success"}

@app.post("/api/domains/bulk-add")
async def bulk_add_domains(
    request: Request,
    bulk_domains: Optional[str] = Form(None),
    status: str = Form("pending"),
    file: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user)
):
    check_analyst(user)

    # Validate status
    if status not in ["pending", "scanned", "on_hold"]:
        status = "pending"

    scanned_val = True if status == "scanned" else False
    on_hold_val = True if status == "on_hold" else False

    domains_to_add = set()
    
    # 1. Process Bulk Paste
    if bulk_domains:
        for line in bulk_domains.splitlines():
            d = line.strip().lower()
            if d:
                domains_to_add.add(d)
                
    # 2. Process File Upload (Strict Security)
    if file:
        # Strict Extension Check
        filename = file.filename.lower()
        if not (filename.endswith('.txt') or filename.endswith('.csv')):
            raise HTTPException(status_code=400, detail="Security Violation: Only .txt and .csv files allowed.")
        
        # Read content (Limit to 2MB)
        content = await file.read(2097152) # 2MB limit
        if await file.read(1): # Check if there's more
            raise HTTPException(status_code=400, detail="File too large. Maximum size is 2MB.")
            
        try:
            text_content = content.decode('utf-8')
            for line in text_content.splitlines():
                d = line.strip().lower()
                # If CSV, take the first column
                if ',' in d and filename.endswith('.csv'):
                    d = d.split(',')[0].strip()
                if d:
                    domains_to_add.add(d)
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Invalid file encoding. Please use UTF-8.")

    if not domains_to_add:
        return {"status": "error", "message": "No valid domains found."}

    # Strict Domain Regex
    domain_regex = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
    
    valid_domains = []
    for d in domains_to_add:
        if domain_regex.match(d):
            valid_domains.append(d)

    if not valid_domains:
        return {"status": "error", "message": "None of the provided domains were in a valid format."}

    # Batch Check & Insert
    added_count = 0
    skipped_count = 0
    
    for domain in valid_domains:
        existing = await domains_col.find_one({"domain": domain})
        if not existing:
            await domains_col.insert_one({
                "domain": domain,
                "scanned": scanned_val,
                "on_hold": on_hold_val,
                "blacklisted": False,
                "notes": "",
                "added_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            })
            added_count += 1
        else:
            skipped_count += 1

    await log_audit(user["username"], "BULK_ADD_DOMAINS", f"Added {added_count} domains, skipped {skipped_count} (Total attempted: {len(domains_to_add)})", request)
    
    return {
        "status": "success", 
        "added": added_count, 
        "skipped": skipped_count, 
        "total_valid": len(valid_domains)
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
    
    await domains_col.delete_one({"_id": ObjectId(domain_id)})
    
    await log_audit(user["username"], "DELETE_DOMAIN", f"Deleted domain: {domain_doc['domain']}", request)
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
    
    if not all([target, category]):
        raise HTTPException(status_code=400, detail="Missing required fields (target or category)")
    
    pull_filter = None
    
    if status_code is not None:
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
async def update_domain_notes(domain_id: str, request: Request, notes: str = Form(...), user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    await domains_col.update_one({"_id": ObjectId(domain_id)}, {"$set": {"notes": notes}})
    return {"status": "success"}

@app.post("/api/domains/{domain_id}/scan-now")
async def scan_now(domain_id: str, request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    root_domain = domain_doc["domain"]
    
    # 1. Reset scanned flag and on_hold flag
    await domains_col.update_one(
        {"_id": ObjectId(domain_id)},
        {"$set": {"scanned": False, "on_hold": False, "last_scanned": "Never"}}
    )
    
    # 2. Clear old tasks for this domain to allow re-entry
    await tasks_col.delete_many({
        "root_domain": root_domain,
        "task_type": {"$in": ["discovery", "verification", "scan", "tech_fingerprint", "directory_hunt", "js_mine", "bypass_403"]},
        "status": {"$in": ["completed", "failed"]}
    })
    
    # 3. Create a fresh discovery task for the root domain
    # This is what triggers the whole pipeline
    exists = await tasks_col.find_one({
        "root_domain": root_domain,
        "target": root_domain,
        "task_type": "discovery"
    })
    if not exists:
        await tasks_col.insert_one({
            "root_domain": root_domain,
            "target": root_domain,
            "task_type": "discovery",
            "status": "pending",
            "created_at": datetime.utcnow()
        })
    
    await log_audit(user["username"], "SCAN_NOW", f"Triggered immediate scan for domain: {root_domain}", request)
    return {"status": "success"}

@app.post("/api/domains/bulk-scan-now")
async def bulk_scan_now(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    data = await request.json()
    ids = [ObjectId(id_str) for id_str in data.get("ids", [])]
    
    if not ids:
        return {"status": "error", "message": "No domains selected"}
    
    # Process each domain
    for d_id in ids:
        domain_doc = await domains_col.find_one({"_id": d_id})
        if not domain_doc:
            continue
            
        root_domain = domain_doc["domain"]
        
        # 1. Reset flags
        await domains_col.update_one(
            {"_id": d_id},
            {"$set": {"scanned": False, "on_hold": False, "last_scanned": "Never"}}
        )
        
        # 2. Clear old tasks
        await tasks_col.delete_many({
            "root_domain": root_domain,
            "task_type": {"$in": ["discovery", "verification", "scan", "tech_fingerprint", "directory_hunt", "js_mine", "bypass_403"]},
            "status": {"$in": ["completed", "failed"]}
        })
        
        # 3. Create fresh discovery task
        exists = await tasks_col.find_one({
            "root_domain": root_domain,
            "target": root_domain,
            "task_type": "discovery"
        })
        if not exists:
            await tasks_col.insert_one({
                "root_domain": root_domain,
                "target": root_domain,
                "task_type": "discovery",
                "status": "pending",
                "created_at": datetime.utcnow()
            })
            
    await log_audit(user["username"], "BULK_SCAN_NOW", f"Triggered immediate scan for {len(ids)} domains", request)
    return {"status": "success"}

# --- Bulk Actions Endpoints ---

@app.post("/api/domains/bulk-update-status")
@limiter.limit("5/minute")
async def bulk_update_status(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
    
    data = await request.json()
    ids = [ObjectId(id_str) for id_str in data.get("ids", [])]
    status_val = data.get("status")
    
    if status_val not in ["pending", "scanned", "on_hold"]:
        raise HTTPException(status_code=400, detail="Invalid status")
        
    scanned_flag = True if status_val == "scanned" else False
    on_hold_flag = True if status_val == "on_hold" else False
    
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
    ids = [ObjectId(id_str) for id_str in data.get("ids", [])]
    
    await domains_col.delete_many({"_id": {"$in": ids}})
    
    await log_audit(user["username"], "BULK_DELETE_DOMAINS", f"Deleted {len(ids)} domains", request)
    return {"status": "success"}

@app.post("/api/domains/bulk-blacklist")
async def bulk_blacklist_domains(request: Request, user: dict = Depends(get_current_user)):
    check_analyst(user)
        
    data = await request.json()
    ids = [ObjectId(id_str) for id_str in data.get("ids", [])]
    
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
    return templates.TemplateResponse(request, "statistics.html", {"user": user})

@app.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, "tools.html", {"user": user})

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, "logs.html", {"user": user})

@app.get("/api/tasks")
async def get_tasks(
    task_type: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    query = {}
    if task_type and task_type != "all":
        query["task_type"] = task_type
    if status and status != "all":
        query["status"] = status
        
    total = await tasks_col.count_documents(query)
    cursor = tasks_col.find(query).sort("created_at", -1).skip((page - 1) * limit).limit(limit)
    tasks = await cursor.to_list(length=limit)
    
    for t in tasks:
        t["_id"] = str(t["_id"])
        for field in ["created_at", "started_at", "completed_at"]:
            if t.get(field) and isinstance(t[field], datetime):
                t[field] = t[field].isoformat()
    
    return {"tasks": tasks, "total": total, "page": page, "limit": limit}

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
    return results

@app.get("/api/settings")
async def get_settings(user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    settings = await settings_col.find_one({"key": "global_settings"})
    if not settings:
        # Default settings
        settings = {"key": "global_settings", "scan_pause": False}
        await settings_col.insert_one(settings)
    
    settings["_id"] = str(settings["_id"])
    return settings

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

@app.get("/api/stats/dashboard")
async def get_stats_dashboard(user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    # 1. Domain Status Distribution (Using flattened pipeline to count all assets)
    all_assets_pipeline = get_flattened_pipeline({"blacklisted": {"$ne": True}})
    all_assets_pipeline.append({"$count": "total"})
    all_assets_result = await domains_col.aggregate(all_assets_pipeline).to_list(length=1)
    total_assets = all_assets_result[0]["total"] if all_assets_result else 0
    
    scanned_pipeline = get_flattened_pipeline({"blacklisted": {"$ne": True}}, status_val="scanned")
    scanned_pipeline.append({"$count": "total"})
    scanned_result = await domains_col.aggregate(scanned_pipeline).to_list(length=1)
    scanned_count = scanned_result[0]["total"] if scanned_result else 0
    
    pending_pipeline = get_flattened_pipeline({"blacklisted": {"$ne": True}}, status_val="pending")
    pending_pipeline.append({"$count": "total"})
    pending_result = await domains_col.aggregate(pending_pipeline).to_list(length=1)
    pending_count = pending_result[0]["total"] if pending_result else 0

    on_hold_count = await domains_col.count_documents({"on_hold": True})
    blacklisted_count = await domains_col.count_documents({"blacklisted": True})
    
    # 2. Risk Distribution (Leads)
    risk_agg = await leads_col.aggregate([
        {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]).to_list(length=20)
    risk_data = {r["_id"]: r["count"] for r in risk_agg}
    
    # 3. Top Technologies & Headers (Separated)
    all_tech_agg = await domains_col.aggregate([
        {"$match": {"web_applications": {"$exists": True, "$not": {"$size": 0}, "$ne": None}}},
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
        count = await leads_col.count_documents({"timestamp": {"$regex": f"^{day}"}})
        activity.append({"date": day, "count": count})
    activity.reverse()
    
    # 5. Geographic (MOCK/SAMPLE derived from IPs)
    geo_agg = await domains_col.aggregate([
        {"$match": {"systems": {"$exists": True, "$not": {"$size": 0}, "$ne": None}}},
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
