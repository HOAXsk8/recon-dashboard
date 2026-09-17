# RDash — External Attack Surface Management & Threat Hunting Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11">
  <img src="https://img.shields.io/badge/FastAPI-0.109+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/MongoDB-6.0+-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker Compose">
  <img src="https://img.shields.io/badge/Tailwind_CSS-3.4-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind CSS">
  <img src="https://img.shields.io/badge/Security-Hardened-E11D48?style=for-the-badge&logo=shield&logoColor=white" alt="Security Hardened">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License MIT">
</p>

---

## Table of Contents
1. [Overview](#overview)
2. [Core Architecture & Data Flow](#core-architecture--data-flow)
3. [Key Platform Features](#key-platform-features)
   - [Unified Search & Asset Inventory](#1-unified-search--asset-inventory)
   - [Hunting Leads & Alerting Engine](#2-hunting-leads--alerting-engine)
   - [Findings & PoC Documentation Studio](#3-findings--poc-documentation-studio)
   - [Tools Monitoring & Scanner Control](#4-tools-monitoring--scanner-control)
   - [Granular Settings & Trigger Controls](#5-granular-settings--trigger-controls)
   - [Dual Theme System (Cyber Dark & Daylight Light)](#6-dual-theme-system-cyber-dark--daylight-light)
   - [Enterprise Access Control & MFA](#7-enterprise-access-control--mfa)
4. [Reconnaissance Engines & Tools Catalog](#reconnaissance-engines--tools-catalog)
   - [Subdomain & Asset Discovery](#subdomain--asset-discovery)
   - [Network, Port & Service Profiling](#network-port--service-profiling)
   - [Directory & Sensitive File Hunter](#directory--sensitive-file-hunter)
   - [Client-Side, JavaScript & Source Map Intelligence](#client-side-javascript--source-map-intelligence)
   - [Access Control & 403 Bypass Testing](#access-control--403-bypass-testing)
   - [Cloud Storage & Bucket Auditor](#cloud-storage--bucket-auditor)
   - [Historical Archive & Endpoint Mining](#historical-archive--endpoint-mining)
   - [OSINT & Infrastructure Fingerprinting](#osint--infrastructure-fingerprinting)
5. [Installation & Deployment](#installation--deployment)
   - [Prerequisites & System Requirements](#prerequisites--system-requirements)
   - [Docker Deployment (Recommended)](#docker-deployment-recommended)
   - [Initial Admin Login & 2FA Setup](#initial-admin-login--2fa-setup)
6. [Manual / Local Development Setup](#manual--local-development-setup)
7. [Operational Workflows](#operational-workflows)
8. [Configuration Reference (`.env`)](#configuration-reference-env)
9. [Extending RDash: Writing Custom Agents](#extending-rdash-writing-custom-agents)
10. [Legal & Ethical Usage](#legal--ethical-usage)

---

## Overview

**RDash** is an enterprise-grade, self-hosted **External Attack Surface Management (EASM)** and automated threat hunting platform. Built for red teams, penetration testers, security operation centers (SOC), and bug bounty researchers, RDash moves beyond static snapshot scans by continuously maintaining a **living, correlated inventory** of an organization's perimeter.

Rather than relying on isolated command-line tools, RDash orchestrates a modular fleet of specialized reconnaissance micro-agents into a unified, high-performance web dashboard. Discovered assets, exposed secrets, vulnerable endpoints, and cloud storage misconfigurations are automatically analyzed, fingerprinted, deduplicated, and presented in real time.

```
       ┌─────────────────────────────────────────────────────────────┐
       │                       TARGET DOMAINS                        │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
   [Passive Recon & OSINT]                        [Active Scanning Engines]
   • Subfinder & crt.sh                           • Nmap Port & Service Scanner
   • Wayback & Common Crawl                       • FFUF Phase 1 (Dirs) & Phase 2 (Files)
   • DNS / SPF / DMARC OSINT                      • 403 Forbidden Header Bypasser
   • Subdomain Permutations                       • Headless JS Crawler & Endpoint Miner
                                                  • Webpack Source Map Unpacker
                                                  • S3 / GCS / Azure Bucket Auditor
              │                                               │
              └───────────────────────┬───────────────────────┘
                                      │
                                      ▼
             ┌─────────────────────────────────────────────────┐
             │       RDash Core Orchestration Engine           │
             │  • Scope Enforcement & Deduplication            │
             │  • Risk-Tiered Alert Classification             │
             │  • Automated Secret Entropy Analysis            │
             │  • Real-Time MongoDB State Store                │
             └────────────────────────┬────────────────────────┘
                                      │
                                      ▼
             ┌─────────────────────────────────────────────────┐
             │      Unified Web Interface & Analyst Studio     │
             │  • Live Search & 9-Tab Diagnostic Inspector     │
             │  • Hunting Leads Triage & Excel Exporter        │
             │  • Markdown Exploit Studio with PoC Highlighting│
             │  • Granular Trigger Settings & Dual Themes      │
             └─────────────────────────────────────────────────┘
```

---

## Core Architecture & Data Flow

RDash is engineered using an asynchronous, microservices-style architecture designed for high throughput, resilience, and horizontal scalability:

```mermaid
graph TD
    Client([Browser Client]) -->|HTTPS / WSS| Proxy[Caddy Reverse Proxy]
    Proxy -->|HTTP :8000| Core[FastAPI Application Gateway]
    
    subgraph Storage Tier
        DB[(MongoDB 6.0 Database)]
        DataVolume[(Persistent Volumes: Wordlists, Sources, Screenshots)]
    end
    
    Core <-->|Motor Async Driver| DB
    Core <--> DataVolume
    
    subgraph Autonomous Scanning Fleet
        Orch[Loop Orchestrator] --> Agent1[Subdomain Discovery & Mutator]
        Orch --> Agent2[Alive Prober - pd-httpx]
        Orch --> Agent3[Nmap Port Scanner]
        Orch --> Agent4[FFUF Directory & File Hunter]
        Orch --> Agent5[Dynamic JS & Secret Miner]
        Orch --> Agent6[Source Map Unpacker]
        Orch --> Agent7[403 Bypass Engine]
        Orch --> Agent8[Cloud Bucket Auditor]
        Orch --> Agent9[Archive Hunter - Wayback]
        Orch --> Agent10[WAF & LB Detector]
        Orch --> Agent11[OSINT & WHOIS Analyzer]
    end
    
    Agent1 <--> DB
    Agent2 <--> DB
    Agent3 <--> DB
    Agent4 <--> DB
    Agent5 <--> DB
    Agent6 <--> DB
    Agent7 <--> DB
    Agent8 <--> DB
    Agent9 <--> DB
    Agent10 <--> DB
    Agent11 <--> DB
    
    Agent5 -->|Unpacks Sources| DataVolume
    Agent6 -->|Extracts Codebases| DataVolume
```

- **API Gateway & Web Server**: Built with **FastAPI** (Python 3.11), leveraging asynchronous ASGI concurrency (`uvicorn`), client rate limiting (`slowapi`), and strict HTTP security headers.
- **Data Persistence**: **MongoDB** stores domain graphs, port maps, raw technical outputs, hunting leads, findings documentation, and configuration states.
- **Frontend Layer**: Modern HTML5, Vanilla JavaScript, and Tailwind CSS, featuring server-rendered Jinja2 templates, live Markdown rendering via `marked.js`, and multi-language syntax highlighting with `Prism.js`.
- **Edge Security & Routing**: **Caddy** acts as a reverse proxy providing automated SSL/TLS termination, HTTP/2 multiplexing, and static caching.
- **Agent Framework**: Standalone Python daemon processes subclasses from `BaseAgent` (`tools/base_agent.py`), communicating asynchronously via MongoDB collections for lock-free state synchronization and distributed execution.

---

## Key Platform Features

### 1. Unified Search & Asset Inventory
- **Real-Time Global Search**: Instant domain and IP address lookup across hundreds of thousands of target records with debounced queries.
- **Multi-Dimensional Filter Bar**: Filter inventory by Scan Status (`Scanned`, `Pending`, `On Hold`), Subdomain Existence (`Has Subdomains`, `No Subdomains`), Technology Stack, WAF Presence (`Cloudflare`, `AWS WAF`, `Imperva`, etc.), and Load Balancer Status.
- **9-Tab Diagnostic Asset Inspector**: Clicking any domain reveals a full-screen modal featuring:
  - **Overview**: IP address, country flag, reverse DNS, open ports, live screenshot thumbnail, and last-scanned timestamp.
  - **Analysis Summary**: Automated technology summary, discovered attack surface metrics, and risk overview.
  - **Exploitation Suggestions**: Actionable recommendations based on discovered ports, outdated technologies, and sensitive endpoints.
  - **Infrastructure**: Complete DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA), CDN/WAF detection, and load balancer profiling.
  - **Systems & Network**: Service versions, banner grabs, and raw Nmap port inspection.
  - **Web Applications**: Discovered endpoints, HTTP status codes, response content lengths, page titles, and live links.
  - **OSINT**: Email security posture (SPF, DMARC, DKIM), registrar data, and nameservers.
  - **WHOIS**: Domain registration, expiry dates, registrar contact, and status codes.
  - **Raw Data**: JSON viewer for direct pipeline inspection.
- **Interactive Asset Menu**: Right-click or button-click on any domain to inspect asset details, copy domain to clipboard, or open directly in a new browser tab.

### 2. Hunting Leads & Alerting Engine
- **Automated Risk Categorization**: Alerts are classified into four severity tiers: **Critical** (exposed credentials, `.env` files, `.git` leaks, unauthenticated writable S3 buckets), **High** (403 bypasses, admin portals, source map secrets, open database ports), **Medium** (port changes, backup archives, missing security headers), and **Low / Info** (technology disclosures, DNS changes).
- **Fingerprint-Based Deduplication**: Cryptographic hash fingerprints (`md5`/`sha256`) prevent duplicate alerts when multiple scanners discover the same finding across recurring cycles.
- **Alert Triage Workflow**: Manage lifecycle states directly from the UI: `New` ➔ `In Progress` ➔ `Investigating` ➔ `True Positive` ➔ `False Positive` ➔ `Benign` ➔ `Muted`.
- **Alert Suppression / Muting**: Suppress noisy leads to prevent inbox flooding while retaining historical records.
- **Collaborative Notes Editor**: Inline notes editor with Markdown support and instant autosave for every lead.
- **One-Click Promotion to Findings**: Seamlessly convert any hunting lead into a confirmed vulnerability entry in the Findings studio.
- **Excel Export**: Download all filtered hunting leads into formatted `.xlsx` spreadsheets for stakeholder reports.

### 3. Findings & PoC Documentation Studio
- **Dedicated Vulnerability Tracking**: A purpose-built interface for documenting validated security bugs, internal penetration test findings, and bug bounty submissions.
- **Split-Screen Markdown Workspace**: Side-by-side authoring pane with live HTML preview.
- **PoC Syntax Highlighting**: Native syntax highlighting for exploit proof-of-concepts, including `HTTP` request/response pairs, `Bash` one-liners, `Python` exploit scripts, `JSON` API payloads, and `SQL` injection strings.
- **Quick-Insert Vulnerability Templates**: Pre-structured markdown templates for OWASP Top 10 vulnerabilities (IDOR, SQL Injection, SSRF, XSS, RCE, Authentication Bypass, Sensitive Data Exposure).
- **Metadata Tagging**: Categorize findings by Severity, Status (`Draft`, `Confirmed`, `In Progress`, `Remediated`), Target Asset URL, Vulnerability Category (CWE/OWASP), and CVE/CVSS Identifier.
- **Keyboard Shortcuts**: Full support for `Ctrl+S` / `Cmd+S` instant saving, `Ctrl+B` (Bold), `Ctrl+I` (Italic).

### 4. Tools Monitoring & Scanner Control
- **Real-Time Engine Status**: Live health and execution metrics for all 18+ reconnaissance background processes.
- **Dual View Modes**: Switch between responsive card tiles and detailed list tables showing engine key, scan cadence, and execution status.
- **Global Scan Control**: Single-click master dynamic toggle (`Start Scanning` / `Stop Scanning`) to immediately pause or resume all background scanner microservices.
- **On-Demand Targeted Execution**: Trigger any specific tool on demand against a single target domain or across all registered domains with custom parameter overrides.

### 5. Granular Settings & Trigger Controls
- **17 Configurable Alert Detection Triggers**: Granular toggles to enable or disable specific alert generation without disabling the underlying scanner engine:
  - *Directory & File Hunter*: Critical sensitive files (`.env`, `.git`), high-risk configs, backup archives, directory listings.
  - *Source Map & Code Secrets*: Source map exposure, high-entropy secrets and API tokens, internal endpoints.
  - *Cloud Storage*: Writable S3/GCS buckets, listable buckets.
  - *Access Control*: Successful 403 bypass exploits.
  - *OSINT & Infrastructure*: Missing SPF/DMARC, new subdomains, port changes, security header regressions.
  - *Historical Archives*: Wayback Machine leaked sensitive endpoints.
- **Batch Actions**: `Enable All`, `Disable All`, and `Reset to Defaults` buttons.
- **Queue & Data Maintenance**: Purge orphaned leads, clear scan caches, and reindex database collections.

### 6. Dual Theme System (Cyber Dark & Daylight Light)
- **WCAG AA Compliant Contrast**: Meticulously tuned text-to-background contrast ratios exceeding 7:1 for headers, body text, badges, and buttons in both modes.
- **Cyber Dark (Default)**: Sleek obsidian slate (`#0f172a` / `#1e293b`) with neon cyan accents, engineered for prolonged night-time analysis and terminal sessions.
- **Daylight Light**: Cool slate-50 (`#f8fafc`) canvas with crisp white cards, rich slate-900 typography, and saturated pastel status pills.
- **Terminal Preservation**: PoC code blocks and command outputs retain their high-contrast dark terminal theme (`#0b1120`) in both daylight and dark modes for optimal readability.
- **Zero-Flash Startup**: Early inline script reads `localStorage` before DOM paint, eliminating theme flashes on page load.
- **Persistent Backend Sync**: Theme preference automatically synchronizes with user account settings in MongoDB.

### 7. Enterprise Access Control & MFA
- **Role-Based Access Control (RBAC)**:
  - `Admin`: Full system control, target management, user provisioning, global settings, and audit logs.
  - `Analyst`: Asset inspection, tool triggering, alert triaging, and finding authoring.
  - `Viewer`: Read-only access to dashboards, alerts, and reports.
- **TOTP Two-Factor Authentication**: RFC 6238 compliant multi-factor authentication compatible with Google Authenticator, Authy, and 1Password. Includes a zero-dependency CLI token generator (`get_totp.py`).
- **Comprehensive Audit Trail**: Immutable logging of all user logins, target additions, setting changes, and finding modifications (`/logs`).

---

## Reconnaissance Engines & Tools Catalog

RDash bundles a suite of autonomous, multi-threaded tools located in the `tools/` directory. Each tool runs in continuous loop mode or handles on-demand tasks from the queue.

| Tool Engine | Binary / Lib | Primary Function | Alert Triggered |
| :--- | :--- | :--- | :--- |
| `subdomain_discovery.py` | `subfinder`, `dnspython` | Active & passive subdomain enumeration + permutation runner | `new_subdomain_discovered` |
| `subdomain_mutator.py` | Custom Engine | Wordlist mutation (dev, stg, api, v1, v2) with DNS resolving | Subdomain discovery pipeline |
| `alive_check.py` | `pd-httpx` | HTTP/HTTPS probing, response codes, page titles, CDN checks | Asset live verification |
| `port_scanner.py` | `nmap` | Top port scanning, banner grabbing, delta change detection | `port_scan_change` |
| `directory_hunter.py` | `ffuf` | Two-phase recursive directory & sensitive file hunter | `sensitive_files_critical`, etc. |
| `dynamic_js_collector.py`| `playwright`, `httpx`| Headless JS crawling, inline script extraction, endpoint validation| Discovered endpoints |
| `source_map_unpacker.py` | Custom Webpack Engine| `.js.map` detection, frontend codebase reconstruction | `source_map_exposed` |
| `source_code_analyzer.py`| Regex / Entropy | Scans reconstructed source trees for hardcoded keys & secrets | `source_map_secrets_leak` |
| `bypass_403.py` | `httpx` | Header manipulation & path traversal against 403 endpoints | `bypass_403_success` |
| `cloud_storage_auditor.py`| `httpx` | S3, Google GCS, and Azure Blob unauthenticated bucket auditing | `cloud_storage_writable`, etc. |
| `archive_hunter.py` | Wayback / Common Crawl | Mining historical URLs for legacy parameters and hidden files | `archive_historical_leaks` |
| `tech_fingerprinter.py` | `whatweb`, `wafw00f` | Software stack, CMS, framework, and security header audit | `security_header_regressions` |
| `waf_detector.py` | `wafw00f` | Web Application Firewall detection & fingerprinting | Infrastructure tab update |
| `lb_detector.py` | `dnspython`, `httpx`| Load balancer & reverse proxy detection | Infrastructure tab update |
| `osint_agent.py` | `dnspython` | SPF, DMARC, DKIM, and MX email security posture auditing | `osint_spf_dmarc_missing` |
| `whois_agent.py` | `whois` | Domain registrar, nameservers, and lifecycle expiry tracking | WHOIS tab update |
| `screenshot_agent.py` | `chromium` | Headless browser visual screen capture of web interfaces | Dashboard visual thumbnail |
| `loop_orchestrator.py` | Python `asyncio` | Scan pipeline orchestrator ensuring dependency order execution | Pipeline coordination |

---

### Subdomain & Asset Discovery

#### 1. `subdomain_discovery.py` & `subdomain_mutator.py`
- **Mechanism**: Executes a hybrid passive-active reconnaissance workflow. It first runs ProjectDiscovery's `subfinder` to gather subdomains from certificate transparency logs, search engines, and passive DNS aggregators.
- **Built-in Permutation Engine**: Immediately upon discovering subdomains, it feeds roots into `subdomain_mutator.py`. The mutator applies hundreds of permutations (e.g., `-dev`, `-stg`, `-uat`, `-api`, `-internal`, `-corp`, numerical suffixes, cloud prefixes) and validates them against public DNS resolvers (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`).
- **Scope Compliance**: Strict enforcement ensures generated mutations never leave the registered target apex scope.
- **Output**: Discovered subdomains are automatically ingested into the `domains` collection, tagged as `pending`, and queued for live probing.

#### 2. `alive_check.py`
- **Mechanism**: Reads unprobed domains and executes `pd-httpx` with multi-threading.
- **Analysis**: Probes both `http://` and `https://` ports (80, 443, 8080, 8443), tracks redirects, extracts final response URLs, parses HTML page titles, measures response content length, and notes server headers.

---

### Network, Port & Service Profiling

#### 3. `port_scanner.py`
- **Mechanism**: Orchestrates `nmap` against target IP addresses and hosts. Runs rapid SYN/TCP connect scans against top attack ports (FTP, SSH, Telnet, SMTP, DNS, HTTP, HTTPS, SMB, MySQL, RDP, Redis, PostgreSQL, MongoDB, Elasticsearch, Kubernetes, Docker API).
- **Service Versioning**: Executes banner grabbing (`-sV`) and default script checks (`-sC`) to identify outdated software versions.
- **Delta Alerts**: Compares scan results with previous database snapshots. If a sensitive port (e.g., Redis `6379`, MySQL `3306`, or Elasticsearch `9200`) is newly opened, an immediate **High Severity Alert** is raised.

---

### Content & Sensitive File Hunter

#### 4. `directory_hunter.py`
- **Intelligent Two-Phase Methodology**:
  - **Phase 1 (Directory Enumeration)**: Uses `ffuf` with `raft-small-directories-lowercase.txt` to discover valid directories (e.g., `/admin`, `/api`, `/v1`, `/backup`, `/internal`, `/dev`).
  - **Phase 2 (Targeted Sensitive File Hunt)**: For every discovered directory plus the root, the engine launches targeted file probes against high-value patterns:
    - *Critical Files*: `.env`, `.git/HEAD`, `.git/config`, `id_rsa`, `id_rsa.pub`, `id_dsa`, `dump.sql`, `backup.sql`, `master.key`, `credentials.json`, `config.json`.
    - *High-Risk Configs*: `web.config`, `Dockerfile`, `docker-compose.yml`, `phpinfo.php`, `server-status`, `swagger.json`, `openapi.yaml`.
    - *Backup Archives*: `.zip`, `.tar.gz`, `.bak`, `.old`, `.swp`, `~`.
- **Validation**: Verifies HTTP response codes, filters out custom 404 soft-error catchalls by inspecting response entropy and length, and classifies leads with appropriate risk tiers.

---

### Client-Side, JavaScript & Source Map Intelligence

#### 5. `dynamic_js_collector.py`
- **Mechanism**: Utilizes headless Chromium via Playwright to crawl target web applications, executing JavaScript frameworks (React, Vue, Angular, Next.js) to discover dynamically loaded scripts.
- **Mining**: Scans DOM `<script src="...">` tags, inline `<script>` blocks, and CSS stylesheets. Uses advanced regex patterns to extract internal API routes, absolute URLs, hidden parameters, and cloud endpoints.
- **Live Link Verification**: Discovered URLs are actively probed with HTTP `HEAD`/`GET` requests; dead links (404/500 errors) are discarded to maintain clean data.

#### 6. `source_map_unpacker.py` & `source_code_analyzer.py`
- **Source Map Detection**: Automatically checks for exposed `.js.map` files referenced via `//# sourceMappingURL=` headers or common filenames (`bundle.js.map`, `main.js.map`, `app.js.map`).
- **Codebase Reconstruction**: Downloads and unpacks original Webpack/TypeScript source trees from the map file, writing human-readable source files to disk (`recovered_sources/`).
- **Secret Entropy Analysis**: Feeds the unpacked codebase into `source_code_analyzer.py`, scanning thousands of files for:
  - AWS Access Keys (`AKIA...`) and Secret Keys
  - Google Cloud / Firebase API Keys
  - Slack, Discord, and Telegram Bot Webhooks
  - JWT Tokens, Bearer Keys, and Private RSA Keys
  - Database Connection Strings (`postgres://`, `mongodb://`, `mysql://`)
- **Source Explorer UI**: Adds a direct **"Source Available"** badge in the Hunting Leads UI, enabling analysts to explore reconstructed source files and highlighted secret lines directly in their browser.

---

### Access Control & 403 Bypass Testing

#### 7. `bypass_403.py`
- **Mechanism**: Inspects target endpoints that returned `403 Forbidden` and attempts BurpSuite-style bypass techniques:
  - **Reverse Proxy Headers**: `X-Original-URL`, `X-Rewrite-URL`, `X-Custom-IP-Authorization`, `X-Forwarded-For: 127.0.0.1`, `X-Remote-IP: 127.0.0.1`, `X-Client-IP: 127.0.0.1`.
  - **Mid-Path Traversal Manipulation**: Injects `/./`, `/%2e/`, `..;/`, `;`, `%20`, `?`, `#` into the URI path (e.g., `/admin/..;/admin`).
  - **HTTP Method Override**: Tests `POST`, `PUT`, `TRACE`, `HEAD`, `PATCH`, and `X-HTTP-Method-Override: GET`.
  - **Port Variations**: Appends `:80`, `:443`, `:8080`, `:8443` to `Host` headers.
- **Result**: Successful bypasses (HTTP 200/302 responses with non-empty bodies) trigger a **High Severity Alert** with full request/response PoCs.

---

### Cloud Storage & Bucket Auditor

#### 8. `cloud_storage_auditor.py`
- **Target Discovery**: Derives bucket names from apex domain names, subdomains, organization keywords, and references extracted from JavaScript bundles.
- **Multi-Cloud Auditing**:
  - **AWS S3**: Probes `https://[bucket].s3.amazonaws.com` and `https://s3.amazonaws.com/[bucket]`.
  - **Google Cloud Storage (GCS)**: Probes `https://storage.googleapis.com/[bucket]`.
  - **Azure Blob Storage**: Probes `https://[account].blob.core.windows.net/[container]`.
- **Permission Tests**:
  - Tests unauthenticated object listing (`?list-type=2` or XML listing).
  - Tests unauthenticated upload/write permissions via `PUT` request with canary file.
- **Alerts**: Publicly writable buckets generate **Critical Severity Alerts**; publicly listable buckets generate **High Severity Alerts**.

---

### Historical Archive & Endpoint Mining

#### 9. `archive_hunter.py`
- **Mechanism**: Queries the **Wayback Machine** (web.archive.org CDX API) and **Common Crawl** for passive historical URLs indexed over the last 15+ years.
- **Filtering**: Filters through millions of records to extract high-value endpoints:
  - Legacy `.env`, `.sql`, `.bak`, `.zip`, `.log` files archived before remediation.
  - API endpoints with hardcoded query parameters containing API keys or tokens.
  - Historical admin paths and obsolete subdomains.
- **Verification**: Probes archived URLs to verify if any sensitive files remain accessible on the current live target.

---

### OSINT & Infrastructure Fingerprinting

#### 10. `osint_agent.py`, `whois_agent.py`, `tech_fingerprinter.py`, `waf_detector.py`, `lb_detector.py`
- **Email Security Auditing (`osint_agent.py`)**: Checks DNS for SPF (`v=spf1`), DMARC (`v=DMARC1`), and DKIM policies. Missing DMARC or `p=none` configurations trigger email spoofing alerts.
- **WHOIS & Domain Lifecycle (`whois_agent.py`)**: Gathers registrar details, creation dates, and expiration alerts for domains nearing lapse (preventing domain hijacking).
- **Technology Stack Identification (`tech_fingerprinter.py`)**: Identifies CMS platforms (WordPress, Drupal, Joomla), web servers (Nginx, Apache, IIS), languages (PHP, Node.js, Python), and frameworks (Laravel, Django, Next.js).
- **Firewall & Proxy Detection (`waf_detector.py` & `lb_detector.py`)**: Detects Cloudflare, Akamai, AWS CloudFront, F5 Big-IP, and HAProxy to assist analysts in tailoring their testing payloads.
- **Visual Capture (`screenshot_agent.py`)**: Automatically captures web application screenshots and generates thumbnails for rapid visual inspection in the dashboard.

---

## Installation & Deployment

### Prerequisites & System Requirements

| Component | Minimum Specification | Recommended Specification |
| :--- | :--- | :--- |
| **Operating System** | Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+), macOS, Windows (WSL2) | Ubuntu 22.04 LTS x86_64 |
| **Docker Engine** | Version 20.10.0+ | Latest Stable Docker Engine |
| **Docker Compose**| Version 2.0.0+ | Latest Docker Compose v2 |
| **CPU** | 2 Cores | 4+ Cores (for parallel Nmap & FFUF) |
| **RAM** | 4 GB | 8 GB - 16 GB |
| **Disk Space** | 20 GB free space | 50 GB+ SSD |

---

### Docker Deployment (Recommended)

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/recon-dashboard.git
   cd recon-dashboard
   ```

2. **Configure Environment Variables**:
   Copy the example environment configuration template:
   ```bash
   cp .env.example .env
   ```
   Open `.env` in your text editor and customize the values:
   ```bash
   nano .env
   ```
   *Ensure you set a strong `MONGO_ROOT_PASSWORD` and a random `SECRET_KEY`.*

3. **Build and Launch Containers**:
   ```bash
   docker compose up -d --build
   ```

4. **Verify Running Services**:
   ```bash
   docker compose ps
   ```
   You should see `recon-db`, `recon-dashboard`, `recon-proxy`, and all scanner microservices in an `Up` status.

---

### Initial Admin Login & 2FA Setup

Upon starting, RDash automatically provisions an initial administrative account using the parameters defined in your `.env` file.

- **URL**: `http://localhost` (or `https://localhost`)
- **Default Username**: `admin`
- **Default Password**: Defined by `ADMIN_INITIAL_PASSWORD` in `.env` (Default: `ChangeMe123!`)

#### Generating TOTP 2FA Codes

If `DISABLE_2FA=false`, RDash requires a 6-digit TOTP code. A helper utility is included to display your current one-time password:

```bash
# Run the local TOTP generator
python3 get_totp.py
```

Output:
```text
=======================================================
  RDash - Local Admin Credentials
=======================================================
  Username     : admin
  Password     : ChangeMe123!
  TOTP Secret  : JBSWY3DPEHPK3PXP
  Current Code : 482910  (22s remaining)
  TOTP URI     : otpauth://totp/RDash:admin?secret=JBSWY3DPEHPK3PXP&issuer=RDash
=======================================================
```
*You can also import the `TOTP URI` into Google Authenticator, 1Password, or Authy for mobile token generation.*

---

## Manual / Local Development Setup

If you wish to run RDash directly on your host system for development without Docker containers:

### 1. Install System Dependencies
On Debian / Ubuntu:
```bash
sudo apt update && sudo apt install -y \
    python3-pip python3-venv \
    nmap ffuf whois chromium whatweb wget unzip
```

Install ProjectDiscovery tools:
```bash
# Install subfinder
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip
unzip subfinder_2.6.6_linux_amd64.zip && sudo mv subfinder /usr/local/bin/ && rm subfinder_2.6.6_linux_amd64.zip

# Install httpx
wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip
unzip httpx_1.6.0_linux_amd64.zip && sudo mv httpx /usr/local/bin/pd-httpx && rm httpx_1.6.0_linux_amd64.zip
```

Download Wordlists:
```bash
mkdir -p wordlists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O wordlists/subdomains-top5000.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories-lowercase.txt -O wordlists/common-dirs.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files-lowercase.txt -O wordlists/common-files.txt
```

### 2. Setup Python Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

### 3. Start MongoDB
Ensure a local MongoDB server is active on `mongodb://localhost:27017`.

### 4. Run the Dashboard
```bash
chmod +x start.sh
./start.sh
```
The FastAPI web server will launch at `http://localhost:8000`.

### 5. Running Reconnaissance Agents Manually
You can test or run individual tools in standalone mode:
```bash
export MONGO_ROOT_PASSWORD="your_secure_mongo_password_here"

# Run subdomain discovery & permutation engine
python3 tools/subdomain_discovery.py

# Run directory & sensitive file hunter
python3 tools/directory_hunter.py

# Run 403 bypass tester
python3 tools/bypass_403.py
```

---

## Operational Workflows

### 1. Adding Target Domains
1. Navigate to **Target Domains** (`/domains`) in the left navigation menu.
2. Click **Add Domain** in the top-right corner.
3. Input a root domain (e.g., `example.com`), select scan intervals, and add notes.
4. For bulk additions, use the **Bulk Import** tab to paste domain lists or upload `.txt` / `.csv` files.
5. The background pipeline will automatically begin active enumeration.

### 2. Triaging Hunting Leads
1. Navigate to **Hunting Leads** (`/alerts`).
2. Filter leads by severity (e.g., `Critical` or `High`), target name, or tool origin.
3. Click any lead to open the **Alert Details Modal**:
   - Inspect technical details, status codes, and HTTP headers.
   - If source maps are exposed, click **Explore Source Code** to browse the reconstructed frontend tree.
   - Add notes in the embedded Markdown editor.
4. Click **Promote to Finding** to convert the lead into a verified vulnerability document.

### 3. Authoring Vulnerability Findings
1. Navigate to **Findings & Exploits** (`/findings`).
2. Select an existing finding or click **Create New Finding**.
3. Use the **Split View** mode to write Markdown with live preview.
4. Click **+ Insert Template...** to drop in an OWASP-standard vulnerability report structure.
5. Add PoC code blocks with syntax highlighting:
   ````markdown
   ```http
   POST /api/v1/user/update HTTP/1.1
   Host: target.com
   Authorization: Bearer <attacker-token>
   Content-Type: application/json

   {"role": "admin", "target_user_id": 1337}
   ```
   ````
6. Use `Ctrl+S` / `Cmd+S` or click **Save** to persist the document.

### 4. Customizing Alert Detection Triggers
1. Navigate to **System Settings** (`/settings`).
2. Under the **Alert Triggers** tab, toggle individual alerts on or off:
   - For example, disable `High-Risk Configs & Admin Portals` if testing an application with public documentation.
3. Disabled alert categories are suppressed by scanner engines and will not generate leads.
4. Click **Save Settings** to persist your configuration.

---

## Configuration Reference (`.env`)

| Variable Name | Default Value | Description |
| :--- | :--- | :--- |
| `MONGO_HOST` | `localhost` | Hostname or IP address for the MongoDB instance |
| `MONGO_ROOT_PASSWORD` | *Required* | Administrative root password for MongoDB |
| `SECRET_KEY` | *Required* | Cryptographic secret key used to sign JWT session tokens |
| `ADMIN_INITIAL_PASSWORD`| `ChangeMe123!` | Password for the default `admin` user upon first boot |
| `ADMIN_INITIAL_TOTP_SECRET`| `JBSWY3DPEHPK3PXP` | Base32 secret key used for initial TOTP 2FA authentication |
| `DISABLE_2FA` | `true` | Set to `false` to enforce mandatory TOTP 2FA for all logins |

---

## Extending RDash: Writing Custom Agents

RDash features a clean, extensible agent architecture. You can create custom scanner tools in minutes by subclassing `BaseAgent` from `tools/base_agent.py`.

### Example: Custom Header Analyzer Agent

Create `tools/my_custom_agent.py`:

```python
import asyncio
from base_agent import BaseAgent

class CustomSecurityAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_key="custom_security_scanner",
            agent_name="Custom Security Header Agent",
            type="script"
        )

    async def run(self):
        print(f"[{self.agent_name}] Starting execution loop...")
        while True:
            # Respect global pause / stop controls
            await self.wait_if_paused()
            
            # Fetch unscanned or pending domains from MongoDB
            domains = await self.get_target_domains(limit=5)
            for domain_doc in domains:
                target = domain_doc.get("domain")
                
                # Check if target is strictly within authorized scope
                if not self.is_in_scope(target, root_domain=target):
                    continue
                
                # Perform your custom analysis logic here...
                finding_detected = True
                
                if finding_detected:
                    # Emit a high-contrast hunting lead alert
                    await self.create_lead(
                        target=target,
                        title="Missing Critical Security Header",
                        risk_level="medium",
                        tool="custom_security_scanner",
                        description=f"Domain {target} is missing Content-Security-Policy.",
                        details={"target": target, "recommendation": "Deploy strict CSP"}
                    )
            
            await asyncio.sleep(60)

if __name__ == "__main__":
    agent = CustomSecurityAgent()
    asyncio.run(agent.run())
```

Register the agent in `docker-compose.yml`:
```yaml
  my-custom-agent:
    image: recon-dashboard:latest
    container_name: my-custom-agent
    command: ["python", "tools/my_custom_agent.py"]
    environment:
      - MONGO_HOST=localhost
      - MONGO_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD}
    volumes:
      - ./tools:/app/tools
    restart: always
    network_mode: "host"
    depends_on:
      - db
      - dashboard
```

---

## Legal & Ethical Usage

> [!WARNING]
> **RDash is designed exclusively for authorized penetration testing, vulnerability assessments, red team exercises, and authorized bug bounty programs.**

- Do not scan, probe, or interact with targets without **explicit, written authorization** from the asset owner.
- The developers of RDash assume no liability and are not responsible for any misuse, damage, or legal consequences caused by this software.
- Users are solely responsible for complying with all applicable local, national, and international laws, regulations, and bug bounty program policies.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>RDash</b> — Continuous Reconnaissance & Autonomous Perimeter Intelligence
</p>
