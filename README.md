# RDash - Advanced External Attack Surface Management

## Overview
RDash is a comprehensive, centralized platform for continuous reconnaissance, asset discovery, and automated vulnerability hunting. It provides security analysts and red teams with a real-time view of an organization's external attack surface by aggregating data from various specialized scanning agents into a modern, interactive web interface.

The tool is designed to move beyond static snapshots, offering a "living" inventory of infrastructure, web applications, and potential entry points.

## Core Architecture
- **Backend**: FastAPI (Python 3.11) with Asynchronous IOMotor for MongoDB.
- **Frontend**: Responsive HTML5/CSS3 using Tailwind CSS and Jinja2 templating.
- **Database**: MongoDB (for flexible, high-performance asset and lead storage).
- **Orchestration**: Docker Compose for a microservices-based agent architecture.
- **Agents**: Independent Python-based scanners running in parallel.

## Key Features

### 1. Specialized Discovery Agents
- **JS Miner & URL Validator**:
    - Crawls discovered JavaScript files for secrets, API keys, and hidden internal URLs.
    - **Proactive Validation**: Automatically verifies discovered URLs via HTTP requests; dead links (404s) are filtered out before reaching the dashboard.
- **403 Bypasser**: Attempts multiple header and path-based manipulation techniques to bypass "403 Forbidden" restrictions on sensitive paths.
- **Directory & File Hunter**: Recursive directory and file mapping using `ffuf` with intelligent Phase 1 (Directory) and Phase 2 (File) discovery.
- **Tech Fingerprinter**: Real-time technology stack identification, security header analysis, and AI-synthesized technology profiles.

### 2. Target & Asset Management
- **Unified Inventory**: Root Domains, Subdomains, and IP Addresses.
- **Intelligent Tracking**: Real-time status (Pending vs. Scanned vs. On Hold).
- **Bulk Import**: Quickly add targets via text paste or file upload (.txt/.csv).
- **Interactive UI**: Web Application URLs and discovered "Hidden URLs" are clickable and open in new tabs for efficient verification.

### 3. Advanced Hunting Leads (Alerts)
- **Risk-Based Categorization**: Critical, High, Medium, and Low risk levels.
- **Smart Deduplication**: Fingerprint-based hashing prevents repeat alerts for the same finding across different scans.
- **Alert Muting**: Suppress specific findings to keep the focus on new discoveries.
- **Reporting**: Export findings to Excel for stakeholder communication.

### 4. Security & Administration
- **MFA Protection**: Secure login with TOTP (Google Authenticator/Authy).
- **Audit Logging**: Comprehensive logging of all user actions and system events.
- **Hardened Security**: Robust security headers (CSP, HSTS, X-Frame-Options).

## Installation & Deployment

1. **Prerequisites**: Ensure Docker and Docker Compose are installed.
2. **Configuration**: Set up your environment variables in `.env`:
   - `MONGO_ROOT_PASSWORD`: Root password for MongoDB.
   - `SECRET_KEY`: Secret key for JWT authentication.
3. **Deploy**:
   ```bash
   sudo docker compose up -d --build
   ```

## Access
- **HTTP**: `http://localhost`
- **HTTPS**: `https://localhost` (Caddy handles automated SSL management)
- **Initial Setup**: Run `python3 init_admin.py` (inside the container) to create your first administrative account.

## Credits
Integrating industry-standard tools like **Nmap**, **FFUF**, **Subfinder**, and **httpx** into a cohesive, analyst-centric workflow.
