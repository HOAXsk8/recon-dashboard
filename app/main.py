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

from datetime import datetime, timedelta
import re

from app.database import domains_col, users_col, audit_logs_col, leads_col
from app.security import (
    verify_password, 
    create_access_token, 
    verify_totp, 
    get_password_hash, 
    get_totp_uri, 
    generate_totp_secret,
    SECRET_KEY,
    ALGORITHM
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
        response.headers["Content-Security-Policy"] = "default-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; img-src 'self' data: https://flagcdn.com; font-src 'self' data:; frame-ancestors 'none';"
        return response

app.add_middleware(SecurityHeadersMiddleware)


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
        return user
    except JWTError:
        return None

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

def validate_password(password: str):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search("[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search("[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search("[0-9]", password):
        return False, "Password must contain at least one number"
    return True, ""

@app.get("/api/admin/users")
async def get_users(request: Request, page: int = 1, limit: int = 10, q: Optional[str] = None, user: dict = Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    
    query = {}
    if q:
        query = {"username": {"$regex": q, "$options": "i"}}
    
    total = await users_col.count_documents(query)
    cursor = users_col.find(query).skip((page - 1) * limit).limit(limit)
    users = await cursor.to_list(length=limit)
    
    for u in users:
        u["_id"] = str(u["_id"])
        u.pop("hashed_password", None)
        u.pop("totp_secret", None)
        
    return {"users": users, "total": total, "page": page, "limit": limit}

@app.get("/api/admin/logs")
async def get_logs(request: Request, page: int = 1, limit: int = 20, q: Optional[str] = None, user: dict = Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    
    query = {}
    if q:
        query = {"$or": [
            {"username": {"$regex": q, "$options": "i"}},
            {"action": {"$regex": q, "$options": "i"}},
            {"details": {"$regex": q, "$options": "i"}}
        ]}
    
    total = await audit_logs_col.count_documents(query)
    cursor = audit_logs_col.find(query).sort("timestamp", -1).skip((page - 1) * limit).limit(limit)
    logs = await cursor.to_list(length=limit)
    
    for l in logs:
        l["_id"] = str(l["_id"])
        
    return {"logs": logs, "total": total, "page": page, "limit": limit}

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
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=is_secure, samesite="strict")
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

import socket
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
    sort_by: str = "domain",
    sort_dir: str = "asc",
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    query = {}
    if q:
        query["domain"] = {"$regex": re.escape(q), "$options": "i"}
    
    if status_val:
        if status_val == "scanned":
            query["scanned"] = True
        elif status_val == "pending":
            query["scanned"] = False
            
    if has_subdomains == "true":
        query["infrastructure.subdomains.0"] = {"$exists": True}
    elif has_subdomains == "false":
        query["$or"] = [
            {"infrastructure.subdomains": {"$size": 0}},
            {"infrastructure.subdomains": {"$exists": False}}
        ]
        
    if tech:
        query["web_applications.tech_stack"] = {"$regex": re.escape(tech), "$options": "i"}
    
    total = await domains_col.count_documents(query)
    scanned_count = await domains_col.count_documents({"scanned": True})
    
    # Sorting logic
    sort_field = "domain"
    if sort_by == "status":
        sort_field = "scanned"
    elif sort_by == "subdomains":
        # Note: Sorting by array length in MongoDB is complex without an aggregation pipeline or a stored count.
        # For now, we'll use infrastructure.subdomains as a fallback or domain.
        sort_field = "infrastructure.subdomains"
        
    direction = 1 if sort_dir == "asc" else -1
    
    cursor = domains_col.find(query).sort(sort_field, direction).skip((page - 1) * limit).limit(limit)
    docs = await cursor.to_list(length=limit)
    
    results = []
    for d in docs:
        # Extract IP from systems if possible
        ip = "N/A"
        if d.get("systems") and len(d["systems"]) > 0:
            ip = d["systems"][0].get("ip", "N/A")
        
        # Count subdomains
        sub_count = 0
        if d.get("infrastructure") and d["infrastructure"].get("subdomains"):
            sub_count = len(d["infrastructure"]["subdomains"])
        
        # Collect technologies
        techs = []
        if d.get("web_applications"):
            for app_info in d["web_applications"]:
                techs.extend(app_info.get("tech_stack", []))
        techs = list(set(techs))[:5] # Limit to top 5
        
        results.append({
            "id": str(d["_id"]),
            "domain": d.get("domain"),
            "ip": ip,
            "scanned": d.get("scanned", False),
            "subdomain_count": sub_count,
            "technologies": techs,
            "country_id": get_country_code(ip)
        })
        
    return {"subdomains": results, "total": total, "scanned_total": scanned_count, "page": page, "limit": limit}

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
    
    query = {}
    if q:
        query["domain"] = {"$regex": re.escape(q), "$options": "i"}
    
    if status_val:
        if status_val == "scanned":
            query["scanned"] = True
        elif status_val == "pending":
            query["scanned"] = False
            
    if has_subdomains == "true":
        query["infrastructure.subdomains.0"] = {"$exists": True}
    elif has_subdomains == "false":
        query["$or"] = [
            {"infrastructure.subdomains": {"$size": 0}},
            {"infrastructure.subdomains": {"$exists": False}}
        ]
        
    if tech:
        query["web_applications.tech_stack"] = {"$regex": re.escape(tech), "$options": "i"}
    
    # Sorting logic
    sort_field = "domain"
    if sort_by == "status":
        sort_field = "scanned"
    elif sort_by == "subdomains":
        sort_field = "infrastructure.subdomains"
        
    direction = 1 if sort_dir == "asc" else -1
    
    cursor = domains_col.find(query).sort(sort_field, direction)
    docs = await cursor.to_list(length=2000)
    
    data = []
    for d in docs:
        ip = "N/A"
        if d.get("systems") and len(d["systems"]) > 0:
            ip = d["systems"][0].get("ip", "N/A")
        
        sub_count = 0
        if d.get("infrastructure") and d["infrastructure"].get("subdomains"):
            sub_count = len(d["infrastructure"]["subdomains"])
        
        techs = []
        if d.get("web_applications"):
            for app_info in d["web_applications"]:
                techs.extend(app_info.get("tech_stack", []))
        tech_str = ", ".join(list(set(techs)))
        
        data.append({
            "Domain": d.get("domain"),
            "Status": "Scanned" if d.get("scanned") else "Pending",
            "IP Address": ip,
            "Country": get_country_code(ip),
            "Subdomains Count": sub_count,
            "Technologies": tech_str,
            "Recon Date": d.get("recon_date", "N/A")
        })
    
    if not data:
        df = pd.DataFrame(columns=["Domain", "Status", "IP Address", "Country", "Subdomains Count", "Technologies", "Recon Date"])
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
    if not user or not user.get("is_admin"):
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    
    # Just render the template; the tables will be populated via AJAX
    return templates.TemplateResponse(request, "admin.html", {"user": user})

@app.post("/admin/create-user")
async def create_user(request: Request, new_username: str = Form(...), new_password: str = Form(...), role: str = Form(...), user: dict = Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    
    if await users_col.find_one({"username": new_username}):
        return templates.TemplateResponse(request, "admin.html", {"user": user, "error": "Username already exists"})
    
    is_valid, error_msg = validate_password(new_password)
    if not is_valid:
        return templates.TemplateResponse(request, "admin.html", {"user": user, "error": error_msg})
    
    totp_secret = generate_totp_secret()
    totp_uri = get_totp_uri(totp_secret, new_username)
    hashed_password = get_password_hash(new_password)
    
    new_user = {
        "username": new_username,
        "hashed_password": hashed_password,
        "totp_secret": totp_secret,
        "is_admin": True if role == "admin" else False,
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
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    
    update_data = {
        "is_admin": True if role == "admin" else False,
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
    await log_audit(user["username"], "update_user", f"Updated user: {target_username}", request)
    
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/delete-user")
async def delete_user(request: Request, target_username: str = Form(...), user: dict = Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    
    if target_username == user["username"]:
        return RedirectResponse(url="/admin?error=Cannot+delete+yourself", status_code=status.HTTP_303_SEE_OTHER)
        
    await users_col.delete_one({"username": target_username})
    await log_audit(user["username"], "delete_user", f"Deleted user: {target_username}", request)
    
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, "alerts.html", {"user": user})

@app.get("/api/leads")
async def get_leads(
    status: Optional[str] = None,
    risk: Optional[str] = None,
    title: Optional[str] = None,
    target: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    query = {}
    if status:
        query["status"] = status
    if risk:
        query["risk_level"] = risk
    if title:
        query["title"] = {"$regex": re.escape(title), "$options": "i"}
    if target:
        query["target"] = {"$regex": re.escape(target), "$options": "i"}
    
    if start_date or end_date:
        query["timestamp"] = {}
        if start_date:
            query["timestamp"]["$gte"] = start_date
        if end_date:
            # End of day for the end_date if it's just a date
            if len(end_date) == 10:
                query["timestamp"]["$lte"] = f"{end_date}T23:59:59Z"
            else:
                query["timestamp"]["$lte"] = end_date
            
    cursor = leads_col.find(query).sort("timestamp", -1)
    leads = await cursor.to_list(length=100)
    for lead in leads:
        lead["_id"] = str(lead["_id"])
    return leads

@app.get("/api/leads/export")
async def export_leads(
    status: Optional[str] = None,
    risk: Optional[str] = None,
    title: Optional[str] = None,
    target: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    query = {}
    if status:
        query["status"] = status
    if risk:
        query["risk_level"] = risk
    if title:
        query["title"] = {"$regex": re.escape(title), "$options": "i"}
    if target:
        query["target"] = {"$regex": re.escape(target), "$options": "i"}
    
    if start_date or end_date:
        query["timestamp"] = {}
        if start_date:
            query["timestamp"]["$gte"] = start_date
        if end_date:
            if len(end_date) == 10:
                query["timestamp"]["$lte"] = f"{end_date}T23:59:59Z"
            else:
                query["timestamp"]["$lte"] = end_date
            
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
async def update_lead_status(lead_id: str, status: str = Form(...), user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    await leads_col.update_one({"_id": ObjectId(lead_id)}, {"$set": {"status": status}})
    return {"status": "success"}

@app.post("/api/leads/{lead_id}/notes")
async def update_lead_notes(lead_id: str, notes: str = Form(...), user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    await leads_col.update_one({"_id": ObjectId(lead_id)}, {"$set": {"notes": notes}})
    return {"status": "success"}

@app.get("/api/notifications/count")
async def get_notifications_count(user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    # Count leads where acknowledged is either False or missing
    count = await leads_col.count_documents({"acknowledged": {"$ne": True}})
    return {"count": count}

@app.post("/api/notifications/clear")
async def clear_notifications(user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    # Mark all leads as acknowledged
    await leads_col.update_many({"acknowledged": {"$ne": True}}, {"$set": {"acknowledged": True}})
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
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)
    
    query = {}
    if q:
        query["domain"] = {"$regex": re.escape(q), "$options": "i"}
    
    total = await domains_col.count_documents(query)
    cursor = domains_col.find(query).sort("domain", 1).skip((page - 1) * limit).limit(limit)
    docs = await cursor.to_list(length=limit)
    
    results = []
    for d in docs:
        results.append({
            "id": str(d["_id"]),
            "domain": d.get("domain"),
            "scanned": d.get("scanned", False),
            "blacklisted": d.get("blacklisted", False),
            "notes": d.get("notes", ""),
            "added_at": d.get("added_at", "N/A")
        })
    
    return {"domains": results, "total": total, "page": page, "limit": limit}

@app.post("/api/domains/add")
async def add_domain(request: Request, domain: str = Form(...), user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
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
    file: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401)

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
                "scanned": False,
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
    if not user:
        raise HTTPException(status_code=401)
    
    domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    new_status = not domain_doc.get("blacklisted", False)
    await domains_col.update_one({"_id": ObjectId(domain_id)}, {"$set": {"blacklisted": new_status}})
    
    await log_audit(user["username"], "BLACKLIST_DOMAIN", f"{'Blacklisted' if new_status else 'Unblacklisted'} domain: {domain_doc['domain']}", request)
    return {"status": "success", "blacklisted": new_status}

@app.post("/api/domains/{domain_id}/delete")
async def delete_domain(domain_id: str, request: Request, user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    domain_doc = await domains_col.find_one({"_id": ObjectId(domain_id)})
    if not domain_doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    await domains_col.delete_one({"_id": ObjectId(domain_id)})
    
    await log_audit(user["username"], "DELETE_DOMAIN", f"Deleted domain: {domain_doc['domain']}", request)
    return {"status": "success"}

@app.post("/api/domains/{domain_id}/notes")
async def update_domain_notes(domain_id: str, request: Request, notes: str = Form(...), user: dict = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    
    await domains_col.update_one({"_id": ObjectId(domain_id)}, {"$set": {"notes": notes}})
    return {"status": "success"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
