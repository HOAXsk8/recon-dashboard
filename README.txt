================================================================================
RECON DASHBOARD - ADVANCED EXTERNAL ATTACK SURFACE MANAGEMENT
================================================================================

OVERVIEW
--------
Recon Dashboard is a comprehensive, centralized platform for continuous 
reconnaissance, asset discovery, and automated vulnerability hunting. It provides 
security analysts and red teams with a real-time view of an organization's 
external attack surface by aggregating data from various specialized scanning 
agents into a modern, interactive web interface.

The tool is designed to move beyond static snapshots, offering a "living" 
inventory of infrastructure, web applications, and potential entry points.

CORE ARCHITECTURE
-----------------
- BACKEND: FastAPI (Python 3.11) with Asynchronous IOMotor for MongoDB.
- FRONTEND: Responsive HTML5/CSS3 using Tailwind CSS and Jinja2 templating.
- DATABASE: MongoDB (for flexible, high-performance asset and lead storage).
- ORCHESTRATION: Docker Compose for a microservices-based agent architecture.
- AGENTS: Independent Python-based scanners running in parallel.

KEY FEATURES
------------

1. TARGET & ASSET MANAGEMENT
   - Unified inventory of Root Domains, Subdomains, and IP Addresses.
   - Intelligent status tracking (Pending vs. Scanned vs. On Hold).
   - Bulk addition of targets via text paste or file upload (.txt/.csv).
   - Global search and filtering capabilities.

2. AUTOMATED SCANNING PIPELINE
   - SUBDOMAIN DISCOVERY: Automated enumeration using projectdiscovery's Subfinder.
   - ALIVE CHECKING: Validation of active targets.
   - PORT SCANNING: Optimized Nmap scanning for the top 1000 ports with 
     service versioning.
   - TECH FINGERPRINTING: Real-time technology stack identification and 
     security header analysis using httpx.
   - DIRECTORY HUNTING: Recursive directory and file mapping using ffuf.

3. ADVANCED HUNTING LEADS (ALERTS)
   - Risk-based alert categorization (High, Medium, Low).
   - CENTRALIZED DEDUPLICATION: Fingerprint-based hashing prevents repeat 
     alerts for the same finding across different scans.
   - ALERT MUTING: Ability to "Tune Out" specific findings. Once muted, the 
     scanners will recognize the finding but suppress all future alerts, 
     keeping the dashboard focused on new discoveries.
   - ADVANCED FILTERING: Search by Status, Risk, Title, Target, or HTTP Status Code.
   - EXPORT: Export findings to Excel for reporting.

4. SPECIALIZED EXPLOITATION AGENTS
   - JS MINER: Automatically crawls discovered Javascript files for hardcoded 
     secrets, API keys, and hidden internal URLs.
   - 403 BYPASSER: Attempts multiple header and path-based manipulation 
     techniques to bypass "403 Forbidden" restrictions on sensitive paths.
   - PORT CHANGE DETECTION: Alerts when new ports are opened or existing 
     services are removed.

5. ENTERPRISE-GRADE SECURITY & ADMINISTRATION
   - RBAC: Role-Based Access Control (Admin, Analyst, Viewer).
   - AUTHENTICATION: Secure password hashing with MFA (TOTP/Google Authenticator).
   - AUDIT LOGGING: Every action (login, query, scan trigger, mute) is 
     logged with user, IP, and timestamp.
   - SECURITY HEADERS: Hardened CSP, HSTS, X-Frame-Options, and more.

INSTALLATION & DEPLOYMENT
-------------------------
The project is fully containerized for easy deployment.

1. Ensure Docker and Docker Compose are installed.
2. Configure the environment variables in `.env`:
   - MONGO_ROOT_PASSWORD
   - SECRET_KEY (for JWT)
3. Run the deployment command:
   sudo docker compose up -d --build

ACCESS
------
Once deployed, the dashboard is accessible via:
- HTTP: http://localhost
- HTTPS: https://localhost (Caddy handles automated SSL/Self-signed certs)

CREDITS
-------
Developed as a unified solution for modern reconnaissance workflows, 
integrating industry-standard tools like Nmap, FFUF, Subfinder, and httpx 
into a cohesive analyst-centric dashboard.
