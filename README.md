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
1. [Platform Overview](#1-platform-overview)
2. [Core Architecture & Data Pipeline](#2-core-architecture--data-pipeline)
3. [Application Sections & Feature Documentation](#3-application-sections--feature-documentation)
   - [3.1 Main Dashboard & Asset Inventory (`/`)](#31-main-dashboard--asset-inventory-)
   - [3.2 9-Tab Diagnostic Asset Inspector Modal](#32-9-tab-diagnostic-asset-inspector-modal)
   - [3.3 Network & Infrastructure Topology Visualizer](#33-network--infrastructure-topology-visualizer)
   - [3.4 Target Scope & Domain Management (`/domains`)](#34-target-scope--domain-management-domains)
   - [3.5 Hunting Leads & Alert Triage Center (`/alerts`)](#35-hunting-leads--alert-triage-center-alerts)
   - [3.6 Findings & Vulnerability PoC Studio (`/findings`)](#36-findings--vulnerability-poc-studio-findings)
   - [3.7 Deep Asset Investigation Console (`/investigate`)](#37-deep-asset-investigation-console-investigate)
   - [3.8 Tools & Scanner Fleet Controller (`/tools`)](#38-tools--scanner-fleet-controller-tools)
   - [3.9 Global Settings & Detection Controls (`/settings`)](#39-global-settings--detection-controls-settings)
   - [3.10 Attack Surface Trends & Analytics (`/statistics`)](#310-attack-surface-trends--analytics-statistics)
   - [3.11 Audit Trail & Security Event Logs (`/logs`)](#311-audit-trail--security-event-logs-logs)
   - [3.12 User Administration & Access Control (`/admin`)](#312-user-administration--access-control-admin)
   - [3.13 Authentication & Multi-Factor Gate (`/login`)](#313-authentication--multi-factor-gate-login)
4. [Comprehensive Reconnaissance Engines & Tools Catalog](#4-comprehensive-reconnaissance-engines--tools-catalog)
   - [Tool 1: `subdomain_discovery.py` — Active & Passive Subdomain Enumeration](#tool-1-subdomain_discoverypy--active--passive-subdomain-enumeration)
   - [Tool 2: `alive_check.py` — Web Probing, Dual-Stack & Takeover Auditor](#tool-2-alive_checkpy--web-probing-dual-stack--takeover-auditor)
   - [Tool 3: `port_scanner.py` — Perimeter Port Scanner & TLS Certificate Auditor](#tool-3-port_scannerpy--perimeter-port-scanner--tls-certificate-auditor)
   - [Tool 4: `directory_hunter.py` — Two-Phase Directory, Sensitive File & Method Hunter](#tool-4-directory_hunterpy--two-phase-directory-sensitive-file--method-hunter)
   - [Tool 5: `dynamic_js_collector.py` — Headless JS Crawler, Secret Miner & Route Extractor](#tool-5-dynamic_js_collectorpy--headless-js-crawler-secret-miner--route-extractor)
   - [Tool 6: `source_map_unpacker.py` — Webpack Source Map Extractor & Codebase Reconstructor](#tool-6-source_map_unpackerpy--webpack-source-map-extractor--codebase-reconstructor)
   - [Tool 7: `source_code_analyzer.py` — Static Code Security & Shannon Entropy Secret Scanner](#tool-7-source_code_analyzerpy--static-code-security--shannon-entropy-secret-scanner)
   - [Tool 8: `api_schema_discovery.py` — OpenAPI, Swagger, Postman & GraphQL Schema Miner](#tool-8-api_schema_discoverypy--openapi-swagger-postman--graphql-schema-miner)
   - [Tool 9: `bypass_403.py` — Reverse Proxy Header Manipulation & Path Traversal Bypasser](#tool-9-bypass_403py--reverse-proxy-header-manipulation--path-traversal-bypasser)
   - [Tool 10: `cloud_storage_auditor.py` — Multi-Cloud Permutation & Bucket Auditor](#tool-10-cloud_storage_auditorpy--multi-cloud-permutation--bucket-auditor)
   - [Tool 11: `sync_cloud_footprint.py` — Continuous Cloud Storage Aggregator & Normalizer](#tool-11-sync_cloud_footprintpy--continuous-cloud-storage-aggregator--normalizer)
   - [Tool 12: `archive_hunter.py` — Historical Wayback & Common Crawl URL Miner](#tool-12-archive_hunterpy--historical-wayback--common-crawl-url-miner)
   - [Tool 13: `tech_fingerprinter.py` — Deep Tech Stack Fingerprinter & CVE Correlator](#tool-13-tech_fingerprinterpy--deep-tech-stack-fingerprinter--cve-correlator)
   - [Tool 14: `waf_detector.py` — Web Application Firewall (WAF) Fingerprinter](#tool-14-waf_detectorpy--web-application-firewall-waf-fingerprinter)
   - [Tool 15: `lb_detector.py` — Dual-Method Load Balancer & Reverse Proxy Fingerprinter](#tool-15-lb_detectorpy--dual-method-load-balancer--reverse-proxy-fingerprinter)
   - [Tool 16: `dns_analytics.py` — DNS Zone Analytics, NSEC Walker & Takeover Fingerprinter](#tool-16-dns_analyticspy--dns-zone-analytics-nsec-walker--takeover-fingerprinter)
   - [Tool 17: `osint_agent.py` — Mail Security Auditor & Public Bucket Correlator](#tool-17-osint_agentpy--mail-security-auditor--public-bucket-correlator)
   - [Tool 18: `whois_agent.py` — WHOIS Registrar Intelligence & Sister Domain Correlator](#tool-18-whois_agentpy--whois-registrar-intelligence--sister-domain-correlator)
   - [Tool 19: `screenshot_agent.py` — Headless Chromium Visual Page Renderer](#tool-19-screenshot_agentpy--headless-chromium-visual-page-renderer)
   - [Tool 20: `loop_orchestrator.py` — Master Workflow Pipeline Coordinator](#tool-20-loop_orchestratorpy--master-workflow-pipeline-coordinator)
   - [Tool 21: `base_agent.py` — Microservice Framework & Alert Engine](#tool-21-base_agentpy--microservice-framework--alert-engine)
   - [Tool 22: `sanitize_secrets.py` — Sensitive Data Redaction & Presentation Filter](#tool-22-sanitize_secretspy--sensitive-data-redaction--presentation-filter)
5. [Installation & Deployment](#5-installation--deployment)
6. [Configuration Reference (`.env`)](#6-configuration-reference-env)
7. [Operational Workflows & Playbooks](#7-operational-workflows--playbooks)
8. [Legal & Ethical Usage](#8-legal--ethical-usage)

---

## 1. Platform Overview

**RDash** is an enterprise-grade, self-hosted **External Attack Surface Management (EASM)**, continuous security monitoring, and automated threat hunting platform. Built specifically for security operations centers (SOC), red teams, penetration testers, and bug bounty researchers, RDash transforms disparate command-line reconnaissance tools into a synchronized, resilient, real-time intelligence ecosystem.

Unlike traditional vulnerability scanners that take slow, static snapshots, RDash operates on a **continuous, event-driven loop**:
- It maps the entire external digital footprint of an enterprise across DNS, cloud providers, APIs, web applications, and network perimeters.
- It detects **infrastructure drift**, such as newly opened ports, modified technology stacks, degraded security headers, dangling CNAMEs, and leaked credentials.
- It implements an intelligent **Initial Scan Cycle Rule**: alerts that indicate changes or regressions are automatically suppressed during a domain's first scan cycle to establish an accurate baseline, firing only on genuine drift in subsequent scan rounds.
- It provides a dedicated analyst workbench featuring cryptographic alert deduplication, interactive infrastructure topology graphs, split-screen vulnerability PoC documentation, and formatted Excel reporting.

```
       ┌─────────────────────────────────────────────────────────────┐
       │                       TARGET DOMAINS                        │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
   [Passive Recon & OSINT]                        [Active Scanning Fleet]
   • Subfinder & crt.sh (40+ feeds)               • Nmap Service Profiler & Port Delta
   • Wayback & Common Crawl URL Mining            • FFUF Phase 1 (Dirs) & Phase 2 (Files)
   • DNSSEC Plain NSEC Zone Walking               • 403 Forbidden Header/Path Bypasser
   • WHOIS Registrar & Sister Domains             • Headless JS Crawler & Endpoint Miner
   • SPF / DMARC / DKIM Email Spoofing            • Webpack Source Map Unpacker & SAST
   • Permutation Subdomain Mutation               • S3 / GCS / Azure Multi-Cloud Auditor
              │                                               │
              └───────────────────────┬───────────────────────┘
                                      │
                                      ▼
             ┌─────────────────────────────────────────────────┐
             │       RDash Core Orchestration Engine           │
             │  • Strict Scope Enforcement (Single vs Wild)    │
             │  • Cryptographic Alert Deduplication (SHA-256)  │
             │  • 48 Granular Alert Toggle Settings Matrix     │
             │  • Initial Scan Cycle Change Alert Suppression  │
             │  • Autonomous Stale Task Recovery Engine        │
             │  • Real-Time MongoDB Asynchronous State Store   │
             └────────────────────────┬────────────────────────┘
                                      │
                                      ▼
             ┌─────────────────────────────────────────────────┐
             │      Unified Web Interface & Analyst Studio     │
             │  • Live Search & 9-Tab Diagnostic Inspector     │
             │  • Interactive Network Topology Graph           │
             │  • Hunting Leads Triage Drawer & Excel Export   │
             │  • Split-Screen Markdown PoC Authoring Studio   │
             │  • Dual Themes (Cyber Dark & Daylight Light)    │
             │  • Role-Based Access Control (RBAC) & TOTP MFA  │
             └─────────────────────────────────────────────────┘
```

---

## 2. Core Architecture & Data Pipeline

RDash is architected as an asynchronous, containerized microservices ecosystem designed for high performance, horizontal scalability, and non-blocking execution:

```mermaid
graph TD
    Client([Analyst Browser]) -->|HTTPS / WSS| Proxy[Caddy Reverse Proxy :80/:443]
    Proxy -->|ASGI Proxy| Core[FastAPI Core Server :8000]
    
    subgraph Persistence Layer
        DB[(MongoDB 6.0 Database)]
        VolSources[(Recovered Codebases Volume)]
        VolScreenshots[(Screenshots Volume)]
    end
    
    Core <-->|Motor Async Driver| DB
    Core <--> VolSources
    Core <--> VolScreenshots
    
    subgraph Microservice Fleet [tools/ BaseAgent Daemons]
        Orch[loop_orchestrator.py]
        Sub[subdomain_discovery.py]
        Alive[alive_check.py]
        Port[port_scanner.py]
        Dir[directory_hunter.py]
        JS[dynamic_js_collector.py]
        Unpack[source_map_unpacker.py]
        SAST[source_code_analyzer.py]
        API[api_schema_discovery.py]
        Bypass[bypass_403.py]
        Cloud[cloud_storage_auditor.py]
        Arch[archive_hunter.py]
        Tech[tech_fingerprinter.py]
        WAF[waf_detector.py]
        LB[lb_detector.py]
        OSINT[osint_agent.py]
        Whois[whois_agent.py]
        Screen[screenshot_agent.py]
    end
    
    Orch -->|Dispatches Queue Tasks| DB
    Microservice Fleet <-->|Leases Tasks & Updates State| DB
    Screen -->|Writes PNGs| VolScreenshots
    Unpack -->|Reconstructs Project Trees| VolSources
    SAST -->|Scans Codebases| VolSources
```

### Key Architectural Tenets:
1. **Asynchronous Non-Blocking Core**: The web application and API gateway are powered by **FastAPI** running on **Python 3.11** with `uvicorn`, communicating with **MongoDB** via the `motor` asynchronous driver.
2. **Lock-Free Distributed Queue**: The `tasks` collection serves as a decentralized priority queue. Micro-agents lease tasks atomically (`pending` ➔ `processing` ➔ `completed` / `failed`), allowing multiple worker instances to scale horizontally.
3. **Heartbeat & Fault Tolerance**: Every tool daemon reports a regular heartbeat to the `scanners` collection. The `loop_orchestrator` monitors heartbeats and recovers tasks that stall or crash (> 180s without heartbeat) without terminating long-running active jobs like FFUF or Nmap.
4. **Scope-Enforced Execution**: Every tool derives from `BaseAgent`, which enforces strict boundary checks (`BaseAgent.is_in_scope`). Attempts to probe out-of-scope third parties or unapproved subdomains are blocked at the code level.
5. **Deduplicated Alert Engine**: Alert generation passes through a SHA-256 fingerprint hash calculation based on target, title, and findings keys. Once an alert is acknowledged, investigated, or muted, duplicate alerts are discarded across future scan cycles.

---

## 3. Application Sections & Feature Documentation

RDash is divided into specialized modules designed for specific stages of the reconnaissance and vulnerability management lifecycle:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                  RDASH NAVIGATION BAR                                  │
├───────────┬─────────┬─────────┬──────────┬───────────┬─────────────┬──────────┬────────┤
│ Dashboard │ Domains │ Leads   │ Findings │ Analytics │ Investigate │ Tools    │ Logs   │
│ (/)       │ (/dom)  │ (/alrt) │ (/find)  │ (/stats)  │ (/invest)   │ (/tools) │ (/log) │
└───────────┴─────────┴─────────┴──────────┴───────────┴─────────────┴──────────┴────────┘
```

---

### 3.1 Main Dashboard & Asset Inventory (`/`)
The primary operational cockpit providing an immediate birds-eye view and deep forensic inspection of the attack surface.

#### Features:
- **Global KPI Summary Cards**:
  - **Total Domains**: Total root apex domains registered under management.
  - **Scanned Assets**: Percentage and count of domains that have completed full reconnaissance cycles.
  - **Live Web Apps**: Verified HTTP/HTTPS endpoints actively responding to network probes.
  - **Discovered Endpoints**: Aggregate total of discovered directories, APIs, files, and historical URLs.
  - **Exposed Open Ports**: Unique network services discovered across all IP perimeters.
  - **Active Critical Leads**: Unresolved high-priority security alerts requiring immediate analyst review.
- **Multi-Faceted Live Filter Bar**:
  - **Global Search**: Sub-millisecond debounced text search across hostnames, IP addresses, technologies, and ports.
  - **Scan Status Filter**: Filter assets by `All`, `Scanned`, `Pending`, or `On Hold`.
  - **Subdomain Filter**: Quick toggle to isolate root domains with discovered subdomains vs single host targets.
  - **Technology Filter**: Select specific technologies (e.g. `WordPress`, `Laravel`, `React`, `Nginx`, `Node.js`) to view affected hosts.
  - **WAF Presence**: Filter targets protected or unprotected by specific firewalls (`Cloudflare`, `AWS WAF`, `Imperva`, `No WAF Detected`).
  - **Load Balancer**: Filter by clustered infrastructure vs standalone servers.
- **Asset Data Table & Visual Cards**:
  - Displays target hostname, IP address with country flag indicator, status pill, subdomain count badge, top 5 identified technologies, and last-scanned timestamp.
  - Right-click context menu and hover controls to trigger immediate rescans, copy URLs, toggle blacklist status, or open the diagnostic inspector.

---

### 3.2 9-Tab Diagnostic Asset Inspector Modal
Clicking on any target domain in the inventory opens a full-screen, 9-tab forensic inspector modal:

| Tab Name | Data Presented | Security Analyst Benefits |
| :--- | :--- | :--- |
| **1. Overview** | IP address, Reverse PTR, ASN & Org, Live Webpage Screenshot Thumbnail, Status Code, Open Port Pills, and Quick Actions. | Immediate visual and technical context of what the host represents without opening a browser. |
| **2. Analysis Summary** | Attack surface summary, detected operating system, perimeter complexity score, and asset tags. | High-level risk evaluation for rapid prioritization. |
| **3. Exploitation Suggestions** | Actionable, automated next-step testing guidance generated based on discovered open ports, headers, and technologies. | Step-by-step penetration testing playbooks tailored specifically to the asset's active software stack. |
| **4. Infrastructure & DNS** | Complete DNS zone table (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`), WAF vendor profile, Load Balancer clustering details, and CNAME alias chain. | Detection of dangling CNAME takeover vectors, misconfigured nameservers, and mail routing loopholes. |
| **5. Systems & Network** | Tabular port map: Port number, Protocol (`tcp`/`udp`), Service name, Software product, Exact version banner, and TLS certificate details. | Discovery of exposed internal management services, databases, and unpatched service vulnerabilities. |
| **6. Web Applications** | Complete list of all discovered web endpoints, response codes (`200`, `301`, `403`), response byte size, and page titles. | Direct roadmap of sensitive administration portals, REST API routes, and hidden application surfaces. |
| **7. OSINT & Mail** | SPF policy mode, DMARC policy mode (`none`, `quarantine`, `reject`), DKIM key status, and discovered public cloud buckets. | Verification of whether domain can be spoofed in phishing campaigns and identification of leaked storage. |
| **8. WHOIS & Entities** | Registrar name, IANA ID, creation date, expiration date, countdown to expiry, registrant organization, and status codes. | Monitoring domain renewal health to prevent domain lapse hijacking and corporate entity correlation. |
| **9. Raw JSON Data** | Syntax-highlighted, formatted JSON tree of the complete MongoDB domain document. | Direct technical verification for tool developers and raw data extraction. |

---

### 3.3 Network & Infrastructure Topology Visualizer
An interactive, force-directed network topology graph accessible directly from the dashboard:
- **Graph Nodes**: Visualizes apex root domains as central anchors, connected outward to resolved subdomains, hosting IP addresses, listening network ports, and identified technology frameworks.
- **Color Coding**: Visual cues by asset type (Apex Domain = Purple, Subdomain = Blue, IP Address = Green, Port = Amber, Vulnerability = Red).
- **Interactive Physics**: Drag, zoom, pan, and cluster nodes to understand multi-tier hosting environments, shared cloud infrastructure, and attack paths.
- **Inspector Handoff**: Clicking any node in the topology graph opens its detailed diagnostic card.

---

### 3.4 Target Scope & Domain Management (`/domains`)
The centralized scope definition interface where authorized programs, root domains, and target boundaries are configured:

#### Features:
- **Single Domain Onboarding**: Add individual domains with validation, automated protocol normalization, and immediate scan dispatch.
- **Bulk Domain Onboarding**:
  - Multi-line textarea paste supporting thousands of candidate domains.
  - CSV file upload parser with automatic column detection and deduplication.
  - Initial scan status selector (`Pending Scan` or `Import as Already Scanned`).
- **Single-Target Mode Switch (`single_domain_only`)**:
  - When enabled, restricts the platform strictly to the specified host. Subdomain discovery and wildcard expansion are completely bypassed. Ideal for single-host penetration tests or narrow bug bounty scopes.
- **Custom Scan Intervals**: Configure autonomous rescan frequencies on a per-domain basis (e.g. rescan every 24 hours, 72 hours, or weekly).
- **Blacklisting & Scope Isolation**: Instantly blacklist sensitive, third-party, or out-of-scope subdomains (e.g. third-party payment gateways, partner portals) with a single click. Blacklisted targets are skipped by all scanning engines.
- **Batch Management Operations**: Select multiple domains via checkboxes for Bulk Scan, Bulk Blacklist, Bulk Interval Modification, or Bulk Deletion.

---

### 3.5 Hunting Leads & Alert Triage Center (`/alerts`)
The centralized triage dashboard where findings from all scanners are aggregated, deduplicated, and prioritized:

#### Features:
- **Four-Tier Severity Classification**:
  - <span style="color:#ef4444; font-weight:bold;">CRITICAL</span>: Hardcoded AWS/database/SSH private keys, unauthenticated writable S3 buckets, exposed `.env` files, accessible `.git` repositories, critical CVEs (CVSS 9.0+).
  - <span style="color:#f97316; font-weight:bold;">HIGH</span>: 403 authorization bypasses, exposed administrative panels, source map secrets, unauthenticated Redis/Memcached ports, dangling CNAME takeovers, plain NSEC zone walks.
  - <span style="color:#eab308; font-weight:bold;">MEDIUM</span>: Tech stack changes, port status deltas, security header regressions, missing SPF/DMARC email policies, listable storage buckets, backup archives.
  - <span style="color:#3b82f6; font-weight:bold;">LOW / INFO</span>: Subdomain discoveries, SSL certificate expiration warnings (> 30 days), software version banners, informational headers.
- **Comprehensive Lifecycle Triage States**:
  - Transition alerts between: `New` ➔ `In Progress` ➔ `Investigating` ➔ `True Positive` ➔ `False Positive` ➔ `Benign` ➔ `Muted`.
- **Slide-Over Alert Drawer**:
  - Clicking any lead slides out an extensive technical investigation panel displaying:
    - Target URL and originating scanner agent.
    - Full vulnerability description and reproduction payload.
    - Raw technical details (request headers, response codes, leaked string snippets).
    - Step-by-step remediation and exploitation verification recommendations.
- **Cryptographic Fingerprint Deduplication**:
  - Each alert receives a deterministic SHA-256 fingerprint (`target|title|extra_key`). When a finding is muted or resolved, recurring scans will not generate duplicate leads.
- **First-Scan Cycle Suppression**:
  - Any alert indicating a delta or drift (e.g. `port_scanner_changes`, `tech_stack_changes`, `security_header_regressions`) is automatically suppressed during the domain's initial scan round, ensuring no false change alerts are raised before a baseline is recorded.
- **Collaborative Notes Editor**:
  - Inline analyst notes field with Markdown support and instant autosave.
- **One-Click Promotion to Findings**:
  - Convert any validated hunting lead into a formalized vulnerability finding in the Findings Studio with a single click.
- **Excel (.xlsx) Report Export**:
  - Export filtered alerts into a clean Microsoft Excel workbook with severity color coding, reproduction steps, and asset URLs.

---

### 3.6 Findings & Vulnerability PoC Studio (`/findings`)
A purpose-built vulnerability tracking and documentation studio designed for writing professional penetration testing reports and bug bounty submissions:

#### Features:
- **Split-Screen Markdown Workspace**:
  - Dual-pane interface with an authoring editor on the left and a live HTML rendered preview on the right.
- **Multi-Language PoC Syntax Highlighting (Prism.js)**:
  - Formatted highlighting for `HTTP` requests/responses, `Bash` terminal commands, `Python` exploit scripts, `JSON` payloads, and `SQL` injection strings.
- **Pre-Built OWASP Top 10 Templates**:
  - Instant one-click insertion of comprehensive vulnerability templates:
    - Insecure Direct Object References (IDOR)
    - SQL Injection (SQLi)
    - Server-Side Request Forgery (SSRF)
    - Cross-Site Scripting (Reflected & Stored XSS)
    - Remote Code Execution (RCE)
    - Broken Authentication & 403 Bypasses
    - Sensitive Data Exposure (.env / Git leaks)
- **Metadata Tagging**:
  - Track Severity (`Critical`, `High`, `Medium`, `Low`, `Info`), Status (`Draft`, `Confirmed`, `Reported`, `Remediated`), Target URL, CWE Number, CVSS Score, and Remediation Timelines.
- **Keyboard Shortcuts**:
  - Quick-save (`Ctrl+S` / `Cmd+S`), Bold (`Ctrl+B`), Italic (`Ctrl+I`), Code Block insertion.

---

### 3.7 Deep Asset Investigation Console (`/investigate`)
A specialized pivoting workspace where analysts can explore a specific hostname or IP address in complete isolation:
- Displays all correlated data points: DNS records, historical IP allocations, discovered subdomains under the same apex, associated WHOIS contact emails, all open ports, discovered JavaScript assets, and all security leads linked to the target.
- Enables pivoting to sibling domains sharing identical ASN allocations, Google Analytics tags, or TLS certificates.

---

### 3.8 Tools & Scanner Fleet Controller (`/tools`)
The operations management console for monitoring and orchestrating RDash's autonomous scanning fleet:

#### Features:
- **Real-Time Engine Health & Telemetry**:
  - Live heartbeat indicators for all microservices. Visual status badges (`Running`, `Idle`, `Paused`, `Stopped`).
- **Dual Display Modes**:
  - Switch between responsive card tiles and a detailed diagnostic table view.
- **Master Scan Switch (`Start Scanning` / `Stop Scanning`)**:
  - A global toggle that immediately pauses or resumes the entire background scanning fleet in real time across all containers.
- **On-Demand Targeted Task Dispatch**:
  - Trigger any specific tool on demand against a single target domain or across all registered domains.
  - Configure priority overrides (`Top of Queue` to skip existing backlogs) and custom execution arguments.

---

### 3.9 Global Settings & Detection Controls (`/settings`)
The configuration center for fine-tuning platform behaviors, detection thresholds, API keys, and alert switches:

#### Features:
- **48 Granular Alert Switches across 11 Functional Categories**:
  Enables disabling or enabling specific alert triggers without shutting down the underlying scanning engine:
  1. *Directory & File Hunter* (10 toggles): Critical sensitive files, high-risk configs, diagnostic endpoints, favicon fingerprints, mobile apps, internal apps, OpenID configs, HTTP TRACE/XST, WebDAV, arbitrary file write.
  2. *Dynamic JS Collector & API Discovery* (11 toggles): Hardcoded secrets, cloud storage leaks, cloud takeover risks, source maps, JWT tokens, sensitive comments, API specs, GraphQL introspection, GraphQL IDEs, hydration leaks, client routes, tracker pivots.
  3. *Cloud Storage Auditor* (2 toggles): Writable buckets, listable buckets.
  4. *403 Forbidden Bypass* (1 toggle): Successful reverse proxy bypasses.
  5. *Perimeter & Port Scanner / TLS* (7 toggles): Port status changes, exposed DevOps ports, unauthenticated databases/services, expired TLS certs, expiring TLS certs, internal domain leaks in certs, self-signed certs.
  6. *OSINT & Mail Security* (4 toggles): Email spoofing (SPF/DMARC), exposed public buckets, weak DKIM keys, DNSSEC plain NSEC zone walking.
  7. *WHOIS & Corporate Entity Correlation* (1 toggle): Corporate sister domain discovery.
  8. *Historical Archive Hunter* (2 toggles): Archived sensitive URL leaks, historical subdomains.
  9. *Tech Fingerprinter & Vulnerability Intel* (4 toggles): Tech stack changes, security header regressions, known CVE vulnerabilities, insecure cookie configurations.
  10. *WAF & Edge Infrastructure* (2 toggles): WAF protection gaps, WAF origin bypasses.
  11. *DNS & Origin Uncloaking* (3 toggles): Dual-stack origin exposure, historical origin IP exposed, dangling CNAME DNS takeover.
- **Initial Scan Cycle Rule**:
  - Built-in engine logic automatically suppresses change alerts during initial domain onboarding scans.
- **Automated Scanning Controls**:
  - Toggle automatic directory hunting (`auto_file_search`).
  - Toggle automatic source map unpacking (`auto_unpack_sourcemaps`).
  - Configure scan request rate delays (`rate_delay_ms`) to respect sensitive origin rate limits.
- **API Key Configuration**:
  - Securely store external API keys (e.g. NIST National Vulnerability Database API key for real-time CVE intelligence).
- **Batch Actions**:
  - `Enable All Alerts`, `Disable All Alerts`, and `Reset to Defaults` buttons.

---

### 3.10 Attack Surface Trends & Analytics (`/statistics`)
Visual metric dashboard aggregating attack surface metrics across the entire enterprise:
- **Severity Breakdown**: Interactive donut and bar charts showing distribution of Critical, High, Medium, and Low vulnerabilities.
- **Port Exposure Frequency**: Top 10 most common open ports across the fleet.
- **Technology Adoption Graph**: Distribution of web servers, frontend frameworks, programming languages, and CMS platforms.
- **WAF & Cloud Market Share**: Proportions of assets protected by Cloudflare, AWS WAF, Akamai, or direct unshielded origins.

---

### 3.11 Audit Trail & Security Event Logs (`/logs`)
An immutable audit trail providing comprehensive accountability for all actions performed within the platform:
- Logs authentication events (successful logins, failed attempts, TOTP verifications), target onboarding, domain deletions, tool dispatch events, finding edits, and global setting modifications.
- Filter logs by Action Type (`LOGIN`, `ADD_DOMAIN`, `RUN_TOOL`, `UPDATE_SETTINGS`, `DELETE_DOMAIN`), Username, Date Range, and free-text keyword search.

---

### 3.12 User Administration & Access Control (`/admin`)
Enterprise user and security governance:
- **Role-Based Access Control (RBAC)**:
  - `Admin`: Complete access to all assets, user management, audit logs, and global settings.
  - `Analyst`: Ability to add targets, dispatch scans, triage alerts, author findings, and export reports.
  - `Viewer`: Read-only access to view dashboards, inspection tabs, and findings without scan or edit capabilities.
- **User Lifecycle**: Create new users, modify usernames and passwords, update roles, and deactivate accounts.
- **MFA / TOTP Management**: View user 2FA status, reset lost TOTP secrets, or enforce two-factor authentication.

---

### 3.13 Authentication & Multi-Factor Gate (`/login`)
Security-hardened authentication portal:
- Session management using encrypted, `HttpOnly`, `SameSite=Lax` JWT authentication cookies.
- Brute-force rate limiting powered by `slowapi` to protect against credential stuffing attacks.
- Standard RFC 6238 Time-Based One-Time Password (TOTP) two-factor authentication compatible with Google Authenticator, 1Password, and Authy.

---

## 4. Comprehensive Reconnaissance Engines & Tools Catalog

RDash includes **22 modular tools and microservices** located in the `tools/` directory. Each tool is documented below with its exact purpose, methodology, backend commands, schema outputs, alert triggers, and security benefits.

---

### Tool 1: `subdomain_discovery.py` — Active & Passive Subdomain Enumeration

- **What it is for**: Uncovering an organization's complete external DNS attack surface by identifying all active and passive subdomains associated with registered apex domains.
- **What it does**:
  1. Leases `discovery` tasks from MongoDB for apex domains.
  2. Queries 40+ passive OSINT reconnaissance data feeds simultaneously using `subfinder`.
  3. Queries Certificate Transparency (CT) logs to identify newly issued SSL/TLS certificates.
  4. Cleans, normalizes, and strips wildcards and protocols from discovered hostnames.
  5. Asynchronously verifies DNS resolution for all discovered candidates using `dnspython`.
  6. Enforces strict program scope (`BaseAgent.is_in_scope`).
  7. Inserts unique validated subdomains into the domain's `infrastructure.subdomains` array.
  8. Automatically queues downstream tasks for newly discovered subdomains (`alive_check`, `verification`).
- **Commands & tools it uses in the background**:
  - `subfinder -d <domain> -all -silent`
  - `dnspython` (Asynchronous resolver queries for `A` and `CNAME` records)
- **Information it provides**:
  - List of discovered hostnames with timestamps and discovery sources (`subfinder`, `cert_transparency`).
  - Resolved IPv4/IPv6 addresses.
  - CNAME canonical alias targets.
- **Alerts it generates**:
  - `historical_subdomain_discovery`: Raised when subdomains are discovered via historical archive logs.
  - Logs `subdomain_discovered` timeline events to the domain's audit history.
- **Benefits of what it gathers**:
  - Discovers forgotten staging, development, and legacy systems (`dev.target.com`, `qa-api.target.com`) that typically have weaker access controls and unpatched vulnerabilities compared to the main production website.

---

### Tool 2: `alive_check.py` — Web Probing, Dual-Stack & Takeover Auditor

- **What it is for**: High-throughput web asset verification, HTTP status profiling, dual-stack IPv4/IPv6 origin bypass detection, historical IP uncloaking, and automated subdomain takeover auditing.
- **What it does**:
  1. Executes high-concurrency HTTP/HTTPS probing across ports 80, 443, 8080, 8443 using `pd-httpx`.
  2. Follows redirect chains and records status codes, response sizes, server banners, and page titles.
  3. **Dual-Stack Probe**: Resolves both IPv4 (`A`) and IPv6 (`AAAA`) records. Compares HTTP response headers and web server banners between IPv4 and IPv6 to identify origin servers unshielded by WAF/CDN controls.
  4. **Subdomain Takeover Audit**: Analyzes CNAME records against known cloud service signatures (AWS S3, GitHub Pages, Heroku, Azure, Shopify, Pantheons, Fastly) to identify unallocated, claimable resources.
  5. **Historical IP Uncloaking**: Compares current IP addresses against historical DNS archives to test if original web servers are reachable directly by sending raw HTTP requests with target `Host` headers.
  6. **Plain NSEC Zone Walking**: Detects plain NSEC records in DNSSEC configurations and walks the entire authoritative zone to enumerate all subdomains without dictionary brute-forcing.
- **Commands & tools it uses in the background**:
  - `pd-httpx -u <url> -sc -title -server -td -cl -method -json -silent`
  - `dnspython` (DNS queries for `A`, `AAAA`, `CNAME`, `NSEC`, `DNSKEY`)
  - Asynchronous raw socket connections for banner grabbing.
- **Information it provides**:
  - Web application alive state (`is_alive: True`), responsive URL, status code, response length, server banner, HTML title tag.
  - Dual-stack comparison report (`bypass_detected`, `ipv4_server`, `ipv6_server`).
  - Subdomain takeover signature match (`provider`, `cname`, `fingerprint`, `claimable`).
  - Discovered historical IPs responding directly to `Host` header injection.
- **Alerts it generates**:
  - `dual_stack_origin_exposure` (High): Fired when IPv6 bypasses CDN/WAF rules or resolves to a mismatched ASN.
  - `dangling_dns_takeover` (High): Fired when a subdomain points to an unclaimed cloud service.
  - `origin_ip_exposed` (High): Fired when a historical IP responds directly to target `Host` header probes.
  - `dnssec_nsec_zone_walk` (High): Fired when DNSSEC plain NSEC records permit full zone enumeration.
- **Benefits of what it gathers**:
  - Uncloaks true origin IP addresses hiding behind Cloudflare/Akamai, enabling direct exploitation without WAF interference, and identifies high-impact subdomain takeovers.

---

### Tool 3: `port_scanner.py` — Perimeter Port Scanner & TLS Certificate Auditor

- **What it is for**: Scanning TCP port ranges, identifying running services, grabbing banners, auditing SSL/TLS certificates, and detecting perimeter port deltas over time.
- **What it does**:
  1. Runs optimized Nmap SYN/connect scans across the top 1,000 TCP ports with service version detection.
  2. Runs lightweight parallel async TCP handshakes against targeted Cloud/DevOps ports (Docker API 2375, Kubernetes 6443, Redis 6379, Consul 8500, Prometheus 9090, Elasticsearch 9200, MongoDB 27017).
  3. Grabs protocol-specific banners (SSH, FTP, SMTP, Redis `INFO server`, Docker `/version`).
  4. Inspects SSL/TLS certificates: validates expiration dates, issuer signatures, Subject Alternative Names (SANs), and checks for internal corporate hostnames leaked in certificate fields.
  5. **Delta Change Tracking**: Compares current open ports against the historical `systems` records in MongoDB. Computes newly opened and closed ports.
  6. **First-Scan Suppression**: Checks `is_first_scan_cycle(domain_doc)`. Suppresses port change alerts on the initial scan, firing only when port changes occur on subsequent scan rounds.
- **Commands & tools it uses in the background**:
  - `nmap -sS --top-ports 1000 -sV --max-retries 1 --max-rtt-timeout 500ms -T4 <target> -oX -`
  - Python `ssl` library (`getpeercert` for SAN extraction, expiry calculation, and issuer analysis)
  - Custom async TCP socket banner probes
- **Information it provides**:
  - Complete port map: Port number, Protocol, State (`open`), Service name, Software product, Exact version.
  - TLS certificate metadata: Expiry timestamp, Remaining days, Self-signed flag, Leaked internal hostnames.
  - Historical delta events (`port_opened`, `port_closed`).
- **Alerts it generates**:
  - `port_scanner_changes` (High/Medium): Port opened or closed (suppressed on first scan cycle).
  - `cloud_devops_port_exposed` (Critical): Exposed Docker daemon, Kubernetes API, etcd, or Consul.
  - `unauthenticated_service_exposed` (Critical): Open Redis, Memcached, MongoDB, or Elasticsearch without authentication.
  - `tls_cert_expired` (Medium): Expired SSL/TLS certificate.
  - `tls_cert_expiry` (Low): Certificate expiring in less than 30 days.
  - `tls_internal_domain_leak` (Medium): Certificate SAN leaks internal staging or `.corp` hostnames.
  - `tls_cert_self_signed` (Low): Untrusted self-signed certificate.
- **Benefits of what it gathers**:
  - Identifies exposed databases and cloud administration endpoints that permit unauthenticated remote code execution or data exfiltration, while tracking unauthorized perimeter changes over time.

---

### Tool 4: `directory_hunter.py` — Two-Phase Directory, Sensitive File & Method Hunter

- **What it is for**: High-speed web content discovery, recursive path fuzzing, sensitive configuration file identification, HTTP method permission auditing, and favicon fingerprinting.
- **What it does**:
  1. **Phase 1 (Directory Enumeration)**: Fuzzes directory paths using `ffuf` to discover valid administrative and application sections (`/admin`, `/api`, `/v1`, `/dev`, `/portal`).
  2. **Phase 2 (Sensitive File Probing)**: Probes discovered directories and web roots for high-value sensitive files (`.env`, `.git/config`, `backup.sql`, `id_rsa`, `web.config`, `actuator/heapdump`, `phpinfo.php`).
  3. **HTTP Method Audit**: Tests HTTP methods (`TRACE`, `PUT`, `DELETE`, `PROPFIND`, `OPTIONS`) to detect Cross-Site Tracing (XST), arbitrary file uploads via WebDAV, or insecure HTTP methods.
  4. **Favicon Fingerprinting**: Downloads `/favicon.ico`, computes MurmurHash3 and MD5 hashes, and matches them against known software frameworks (Spring Boot, Jenkins, Jira, Django).
  5. **Well-Known Endpoints**: Probes `/.well-known/assetlinks.json`, `apple-app-site-association`, and `openid-configuration` to extract internal API routes, tenant IDs, and OAuth endpoints.
  6. **Soft-404 Calibration**: Sends canary requests to calculate dynamic baseline response lengths, word counts, and entropy to eliminate false positives from single-page application (SPA) catchalls.
- **Commands & tools it uses in the background**:
  - `ffuf -u <url>/FUZZ -w <wordlist> -mc 200,301,302,403 -ac -s`
  - Asynchronous `httpx` client for targeted probing and method testing
  - `mmh3` (MurmurHash3 calculation for favicon hashes)
- **Information it provides**:
  - Valid endpoints with status codes, content lengths, redirects, and response word counts.
  - Allowed HTTP methods and WebDAV file write test results.
  - Favicon hash and matched framework fingerprint.
  - Discovered mobile app IDs and OAuth configuration schemas.
- **Alerts it generates**:
  - `sensitive_files_critical` (Critical): Exposed `.env`, `.git`, or database backups.
  - `sensitive_files_high` (High): Configuration files, internal documentation, or admin consoles.
  - `sensitive_files_diagnostic` (Medium): Exposed Swagger UI, PHPInfo, or Spring Actuator endpoints.
  - `favicon_fingerprint` (Low): Favicon matched to a specific technology framework.
  - `well_known_mobile_apps` (Info): Mobile app package IDs extracted from assetlinks.
  - `well_known_internal_app` (Medium): Internal enterprise application metadata exposed.
  - `well_known_openid_configuration` (Info): Discovered OpenID Connect endpoint configuration.
  - `http_method_trace_xst` (Medium): HTTP TRACE enabled (Cross-Site Tracing vulnerability).
  - `http_method_webdav_enabled` (Medium): WebDAV methods enabled.
  - `http_method_arbitrary_write` (Critical): Web server permits arbitrary HTTP PUT/file creation.
- **Benefits of what it gathers**:
  - Finds exposed database credentials, source code leaks, and administrative consoles that provide immediate direct access to internal infrastructure.

---

### Tool 5: `dynamic_js_collector.py` — Headless JS Crawler, Secret Miner & Route Extractor

- **What it is for**: Crawling client-side Single Page Applications (SPA), intercepting network requests, harvesting JavaScript bundles, and extracting hidden API routes, secrets, and GraphQL endpoints.
- **What it does**:
  1. Launches a headless Chromium browser instance via Playwright to fully execute dynamic JavaScript, render SPAs, and capture post-hydration DOM content.
  2. Intercepts network traffic to capture dynamically loaded script bundles, webpack chunks, and asynchronous `fetch`/XHR requests.
  3. Extracts inline scripts, external script URLs, and CSS files.
  4. Parses JavaScript content with specialized regular expressions to extract:
     - Hardcoded API credentials, JWT tokens, and cloud storage bucket names.
     - Internal REST API endpoints (`/api/v1/...`) and framework routes.
     - Sensitive developer comments (`TODO`, `FIXME`, internal server IPs).
     - Next.js / Nuxt.js hydration payloads (`__NEXT_DATA__`, `window.__NUXT__`).
     - Discovered third-party tracking IDs (Google Analytics, Sentry, Segment).
  5. Discovers and probes GraphQL endpoints (`/graphql`, `/api/graphql`) for active introspection queries and IDE playgrounds (GraphQL Playground, GraphiQL).
  6. Automatically queues discovered source maps for unpacking by `source_map_unpacker.py`.
- **Commands & tools it uses in the background**:
  - Playwright Chromium (`headless=True`, custom User-Agent, network interception)
  - `httpx` (Asynchronous validation of discovered endpoints)
  - Python `re` (Regex matching for API keys, routes, and tokens)
- **Information it provides**:
  - Complete catalog of script assets, API routes, and query parameters.
  - Hardcoded credential candidates with line numbers and file contexts.
  - GraphQL schema metadata and IDE accessibility status.
  - Next.js hydration payload dumps containing server-side configuration data.
- **Alerts it generates**:
  - `js_hardcoded_secrets` (Critical): API keys, tokens, or credentials discovered in client JavaScript.
  - `js_cloud_storage_leaks` (High): Cloud bucket URLs discovered in script bundles.
  - `js_cloud_storage_takeover` (High): Reference to unclaimed or non-existent cloud storage bucket.
  - `js_source_maps` (High): Exposed `.map` source map files discovered.
  - `js_jwt_tokens` (Medium): Hardcoded JSON Web Tokens found in scripts.
  - `sensitive_comment_leak` (Low): Developer comments revealing internal IPs, logic, or credentials.
  - `api_spec_discovered` (Medium): Discovered OpenAPI, Swagger, or Postman collection paths.
  - `graphql_introspection_enabled` (Medium): GraphQL endpoint permits full schema introspection.
  - `graphql_ide_exposed` (Medium): Publicly accessible GraphiQL or GraphQL Playground interface.
  - `js_hydration_payload_leak` (Medium): Server-rendered state leak containing session data or config.
  - `js_client_framework_routes` (Info): Discovered frontend application routes.
  - `js_third_party_tracker_pivots` (Info): Third-party analytics IDs for cross-domain correlation.
- **Benefits of what it gathers**:
  - Uncovers hidden API endpoints not linked in HTML, recovers private developer tokens exposed to clients, and discovers GraphQL schemas for backend data mining.

---

### Tool 6: `source_map_unpacker.py` — Webpack Source Map Extractor & Codebase Reconstructor

- **What it is for**: Reconstructing unminified, developer-authored frontend source code from production JavaScript source maps (`.js.map`).
- **What it does**:
  1. Detects source map URLs via `//# sourceMappingURL=` comments or probes common paths (`main.js.map`, `bundle.js.map`, `app.js.map`).
  2. Downloads the source map file and parses the JSON structure.
  3. Extracts the `sources` array (original filenames and directory structures) and `sourcesContent` array (uncompiled source code).
  4. Sanitizes directory traversal sequences to enforce safe filesystem writes.
  5. Reconstructs the complete project directory structure on disk under `recovered_sources/<domain>/<bundle_name>/`, restoring original TypeScript (`.ts`, `.tsx`), React JSX, Vue SFC (`.vue`), and build configs.
  6. Automatically triggers `source_code_analyzer.py` to scan the recovered codebase for secrets.
- **Commands & tools it uses in the background**:
  - Asynchronous `httpx` client for stream downloading large source map files.
  - Python `json`, `os`, and `aiofiles` for high-speed filesystem tree reconstruction.
- **Information it provides**:
  - Total count of recovered source files and lines of code.
  - Complete reconstructed filesystem path for direct browsing via the dashboard Source Code Explorer.
  - Metadata record stored in `recovered_source_maps` collection.
- **Alerts it generates**:
  - `js_source_maps` (High): Generated when production source maps are successfully unpacked.
- **Benefits of what it gathers**:
  - Gives security analysts access to the application's original source code, internal business logic, database models, internal API routes, and developer comments exactly as written in the development repository.

---

### Tool 7: `source_code_analyzer.py` — Static Code Security & Shannon Entropy Secret Scanner

- **What it is for**: Performing Static Application Security Testing (SAST) on unpacked source codebases to detect embedded credentials, private keys, and high-entropy secrets.
- **What it does**:
  1. Recursively walks directory trees in `recovered_sources/`.
  2. Filters target files by extension (`.js`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.json`, `.env`, `.yml`) while ignoring third-party libraries (`node_modules`, `vendor/`, `moment/locale`).
  3. Scans source code against an extensive library of verified credential regex signatures (AWS, Google Cloud, Firebase, Stripe, Slack, GitHub, SSH private keys, database URIs).
  4. Calculates Shannon entropy on candidate string literals ($H = -\sum p_i \log_2 p_i$) to detect randomized API tokens and cryptographic secrets that do not match known regex patterns.
  5. Extracts surrounding code context (5 lines before and after) to present verified proof-of-concept evidence.
- **Commands & tools it uses in the background**:
  - Custom Shannon entropy calculation algorithms in Python.
  - Optimized pre-compiled regex pattern engines.
- **Information it provides**:
  - Secret type (e.g. `AWS Access Key`, `Stripe Secret Key`, `SSH Private Key`).
  - File path and exact line number.
  - Code snippet evidence with secret masked for safe presentation.
  - Shannon entropy score.
- **Alerts it generates**:
  - `js_hardcoded_secrets` (Critical): Raised when validated API keys or credentials are discovered in recovered source code.
- **Benefits of what it gathers**:
  - Uncovers production backend credentials inadvertently bundled into frontend builds, providing immediate demonstration of critical security risk.

---

### Tool 8: `api_schema_discovery.py` — OpenAPI, Swagger, Postman & GraphQL Schema Miner

- **What it is for**: Discovering, extracting, parsing, and documenting REST API specifications, Postman collections, and GraphQL schemas across target applications.
- **What it does**:
  1. Probes for standardized API documentation endpoints: `/swagger.json`, `/openapi.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger/v1/swagger.json`, `/postman_collection.json`.
  2. Parses JSON and YAML specification schemas, extracting all paths, HTTP methods (`GET`, `POST`, `PUT`, `DELETE`), required headers, query parameters, request bodies, and authentication schemes.
  3. **GraphQL Field Suggestion Harvesting**: If a GraphQL endpoint has standard introspection disabled, it sends canary probes with intentional syntax anomalies to elicit and harvest "Did you mean ...?" schema field suggestions from error responses, mapping the backend schema even when protected.
  4. Generates an automated API testing matrix for fuzzing and access control verification.
- **Commands & tools it uses in the background**:
  - Asynchronous `httpx` client with custom headers.
  - Python `json` and `yaml` parsers.
  - Custom GraphQL query generation engine.
- **Information it provides**:
  - Structured API specification catalog stored in `domains.api_schemas`.
  - Comprehensive parameter list and data type definitions for every route.
  - Harvested GraphQL types, queries, and mutations.
- **Alerts it generates**:
  - `api_spec_discovered` (Medium): Raised when public OpenAPI, Swagger, or Postman specifications are found.
  - `graphql_introspection_enabled` (Medium): Raised when GraphQL schema introspection is permitted.
- **Benefits of what it gathers**:
  - Provides a complete map of all backend API endpoints, parameters, and authentication requirements, exposing unauthenticated endpoints and BOLA/IDOR vulnerabilities.

---

### Tool 9: `bypass_403.py` — Reverse Proxy Header Manipulation & Path Traversal Bypasser

- **What it is for**: Automatically circumventing HTTP `403 Forbidden` and `401 Unauthorized` restrictions on restricted administrative and private endpoints.
- **What it does**:
  1. Identifies endpoints returning HTTP 403 or 401 status codes discovered by other tools.
  2. Executes an automated battery of reverse proxy header manipulations:
     - `X-Original-URL: <path>`
     - `X-Rewrite-URL: <path>`
     - `X-Custom-IP-Authorization: 127.0.0.1`
     - `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `X-Remote-IP: 127.0.0.1`
     - `X-Forwarded-Host: localhost`
  3. Executes path normalization and traversal permutations:
     - Mid-path traversal: `/admin/..;/admin`, `/%2e/admin`, `/admin/.`, `/admin?`, `/admin#`
     - Semicolon delimiters and URL encoding: `/admin;`, `/admin/..;/`
  4. Tests HTTP method overrides (`POST`, `PUT`, `TRACE`, `HEAD`, `PATCH`, `X-HTTP-Method-Override: GET`).
  5. Tests port modifications in `Host` headers (`target.com:80`, `target.com:443`, `target.com:8080`).
  6. Validates response transitions (e.g. `403 Forbidden` ➔ `200 OK`) and checks for response body size variations to eliminate false positives.
- **Commands & tools it uses in the background**:
  - Asynchronous `httpx` HTTP engine with raw header manipulation.
- **Information it provides**:
  - Successful bypass technique (exact header or path permutation).
  - Transition status code and content length.
  - Exact, reproducible `curl` reproduction command.
- **Alerts it generates**:
  - `bypass_403_success` (High): Raised when a 403 restriction is successfully bypassed.
- **Benefits of what it gathers**:
  - Exposes unauthenticated administrative dashboards, internal debug consoles, and private API routes that were intended to be restricted to local or trusted networks.

---

### Tool 10: `cloud_storage_auditor.py` — Multi-Cloud Permutation & Bucket Auditor

- **What it is for**: Discovering and auditing public cloud storage buckets (AWS S3, Google Cloud Storage, Azure Blob Storage) associated with the target organization.
- **What it does**:
  1. Generates bucket name permutations using the apex domain, subdomains, organization name, and environment keywords (`-assets`, `-backup`, `-data`, `-dev`, `-staging`, `-prod`, `-media`, `-files`).
  2. Probes target bucket endpoints across cloud providers:
     - AWS S3: `https://[bucket].s3.amazonaws.com`
     - Google Cloud Storage: `https://storage.googleapis.com/[bucket]`
     - Azure Blob: `https://[account].blob.core.windows.net/[container]`
  3. **Permission Testing**:
     - Tests for public object listing (`GET /?list-type=2`).
     - Tests for anonymous file uploads by sending a benign `PUT` request with a randomized canary UUID.
  4. Integrates discovered cloud assets into the domain's infrastructure cloud footprint.
- **Commands & tools it uses in the background**:
  - Asynchronous `httpx` client with XML payload parsing.
- **Information it provides**:
  - Discovered bucket name, cloud provider, and full URL.
  - Access status: `vulnerable_write` (Publicly Writable), `open` (Publicly Listable), `secured` (Private/Access Denied), or `unknown`.
  - Discovered object keys and file count.
- **Alerts it generates**:
  - `cloud_storage_writable` (Critical): Bucket permits anonymous public file uploads/modifications.
  - `cloud_storage_listable` (High): Bucket permits anonymous public object listing.
- **Benefits of what it gathers**:
  - Identifies misconfigured cloud storage containing sensitive database backups, customer records, or public upload permissions that allow website defacement or supply chain compromise.

---

### Tool 11: `sync_cloud_footprint.py` — Continuous Cloud Storage Aggregator & Normalizer

- **What it is for**: Aggregating, normalizing, and persistently syncing all discovered cloud storage buckets across all tools into the domain's infrastructure inventory.
- **What it does**:
  1. Runs continuously in the background and on system startup.
  2. Scans the `leads` collection and active web application records for cloud storage references (S3, GCS, Azure Blobs).
  3. Resolves each discovered bucket to its parent root apex domain.
  4. Categorizes buckets into structured categories (`s3_buckets`, `azure_blobs`, `gcp_buckets`, `other_buckets`).
  5. Deduplicates entries and ranks them by severity (`vulnerable_write` > `vulnerable_takeover` > `open` > `secured`).
  6. Updates the `infrastructure.cloud_footprint` dictionary on the corresponding domain documents.
- **Commands & tools it uses in the background**:
  - Python `motor.motor_asyncio` database pipeline.
- **Information it provides**:
  - Centralized, correlated cloud storage footprint attached to each target domain.
- **Alerts it generates**:
  - Synchronizes alert findings directly into the domain's permanent inventory.
- **Benefits of what it gathers**:
  - Provides a single, consolidated view of an organization's multi-cloud footprint across AWS, Azure, and GCP.

---

### Tool 12: `archive_hunter.py` — Historical Wayback & Common Crawl URL Miner

- **What it is for**: Passively mining historical web archives to discover forgotten endpoints, legacy backup files, leaked API keys, and decommissioned subdomains.
- **What it does**:
  1. Queries the **Wayback Machine CDX API** and **Common Crawl** index across historical archives dating back over 15 years.
  2. Filters wildcard queries (`*.target.com/*`) for valid response codes (`200`, `302`).
  3. Analyzes indexed URLs with regex to extract sensitive file extensions (`.sql`, `.bak`, `.zip`, `.env`, `.log`, `.old`), administrative paths, and sensitive query parameters (`token=`, `key=`, `secret=`, `auth=`).
  4. Discovers historical subdomains and queues them into the discovery pipeline.
  5. Asynchronously probes discovered sensitive URLs against the modern live web application to verify if forgotten files remain exposed today.
- **Commands & tools it uses in the background**:
  - Asynchronous `httpx` client querying Wayback Machine CDX API.
- **Information it provides**:
  - Historical endpoint catalog stored in `domains.endpoints`.
  - Discovered historical subdomains and parameter names.
  - Active accessibility verification status of historical files.
- **Alerts it generates**:
  - `archive_historical_leaks` (High/Medium): Raised when a historical URL containing sensitive data or backups is confirmed to still be active on the live web server today.
  - `historical_subdomain_discovery` (Low): Raised when new subdomains are discovered via archive indexes.
- **Benefits of what it gathers**:
  - Uncovers legacy database backups, forgotten API documentation, and private endpoints that were decommissioned from navigation menus but remain exposed on web servers.

---

### Tool 13: `tech_fingerprinter.py` — Deep Tech Stack Fingerprinter & CVE Correlator

- **What it is for**: Deep technology stack fingerprinting, OWASP security header compliance auditing, CVE vulnerability correlation, session cookie security analysis, and HTTP protocol support auditing.
- **What it does**:
  1. Combines technology signatures from `whatweb`, `pd-httpx`, HTML meta tags, script paths, server headers, and cookie attributes.
  2. Normalizes software names and versions (`WordPress:6.4`, `nginx/1.24`, `PHP/8.2`).
  3. **Security Header Regression Analysis**: Audits security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`). Compares against historical headers in MongoDB to detect regressions where a security header was removed during subsequent deployments.
  4. **CVE Vulnerability Correlation**: Correlates identified software versions against known CVE databases (including CISA KEV - Known Exploited Vulnerabilities) and NIST NVD API.
  5. **Session Cookie Audit**: Evaluates cookies for missing security flags (`HttpOnly`, `Secure`, `SameSite=Strict/Lax`).
  6. **Protocol Audit**: Tests for modern protocol support (HTTP/2, HTTP/3 QUIC).
  7. **First-Scan Suppression**: Checks `is_first_scan_cycle(domain_doc)`. Suppresses tech stack change and header regression alerts during the domain's initial scan cycle.
- **Commands & tools it uses in the background**:
  - `whatweb -a 3 --log-json=<temp> <url>`
  - `pd-httpx -u <url> -td -title -server -sc -json -silent`
  - Asynchronous `httpx` client for header and cookie inspection.
- **Information it provides**:
  - Canonical technology stack list and software versions.
  - OWASP security header compliance scorecard.
  - Correlated CVE list with CVSS scores and remediation steps.
  - Insecure session cookie inventory.
  - HTTP/2 and HTTP/3 QUIC support profile.
- **Alerts it generates**:
  - `tech_stack_changes` (Medium): Technology stack modified (suppressed on first scan cycle).
  - `security_header_regressions` (High): Previously present security header removed (suppressed on first scan cycle).
  - `known_vulnerability_detected` (Critical/High): Software version matches known CVE or CISA KEV entry.
  - `insecure_cookie_configuration` (Medium): Session cookie missing `HttpOnly` or `Secure` flags.
- **Benefits of what it gathers**:
  - Identifies out-of-date components with public exploits, flags security header regressions that expose applications to clickjacking or XSS, and uncovers session hijacking vectors.

---

### Tool 14: `waf_detector.py` — Web Application Firewall (WAF) Fingerprinter

- **What it is for**: Identifying and fingerprinting Web Application Firewalls (WAF) protecting target web applications.
- **What it does**:
  1. Executes `wafw00f` to actively probe web endpoints with signature HTTP requests designed to trigger firewall inspection rules.
  2. Analyzes response codes, HTTP headers, and error page templates.
  3. Identifies WAF manufacturer (Cloudflare, AWS WAF, Imperva Incapsula, Akamai Ghost, F5 BIG-IP, ModSecurity, Sucuri, Fastly).
  4. Detects WAF protection gaps where specific subdomains or origin servers lack firewall coverage.
- **Commands & tools it uses in the background**:
  - `wafw00f -a -o <temp.json> -f json <url>`
- **Information it provides**:
  - WAF detected flag (`detected: True/False`).
  - Firewall product name, manufacturer, and detection confidence level.
  - Updates `domains.waf` object.
- **Alerts it generates**:
  - `waf_protection_gap` (Medium): Live web application detected with no active WAF protection.
  - `waf_origin_bypass` (High): Origin server found reachable directly, bypassing WAF rules.
- **Benefits of what it gathers**:
  - Informs penetration testers which attack payloads will be filtered by edge firewalls and identifies unprotected assets that can be attacked directly without evasion techniques.

---

### Tool 15: `lb_detector.py` — Dual-Method Load Balancer & Reverse Proxy Fingerprinter

- **What it is for**: Detecting whether target hostnames are backed by multi-node load-balanced clusters, reverse proxies, or content delivery networks.
- **What it does**:
  1. **Method 1 (DNS Round-Robin)**: Performs consecutive asynchronous DNS resolutions across intervals to detect IP rotation or multi-IP DNS pools.
  2. **Method 2 (HTTP Variance Analysis)**: Sends 8 consecutive HTTP requests and compares response headers:
     - Detects sub-second timestamp drift in `Date` headers across unsynchronized backend nodes.
     - Flags varying `Server` or `X-Served-By` headers.
     - Identifies load-balancer affinity cookies (`BIGipServer`, `AWSALB`, `HAPROXYID`).
- **Commands & tools it uses in the background**:
  - `dnspython` (Asynchronous DNS resolution)
  - `httpx` (Header comparison across consecutive requests)
- **Information it provides**:
  - Load balancer detected flag (`detected: True/False`), detection method, and cluster IP pool.
  - Updates `domains.load_balancer` object.
- **Alerts it generates**:
  - Diagnostic infrastructure profile (powers the Load Balancer filter in the asset table).
- **Benefits of what it gathers**:
  - Alerts testers that requests are hitting multiple distinct backend servers, explaining intermittent vulnerabilities or inconsistent state behavior.

---

### Tool 16: `dns_analytics.py` — DNS Zone Analytics, NSEC Walker & Takeover Fingerprinter

- **What it is for**: Advanced DNS record analysis, dangling CNAME subdomain takeover auditing, plain NSEC zone walking, and ASN network ownership resolution.
- **What it does**:
  1. **Subdomain Takeover Engine**: Analyzes CNAME chains against signatures for 15+ cloud platforms (AWS S3, GitHub Pages, Heroku, Azure, Shopify, Fastly, Pantheons, Zendesk) to identify unallocated resources that can be registered by an attacker.
  2. **Plain NSEC Zone Walker**: Tests for DNSSEC implementation using plain NSEC records (RFC 4034). If NSEC3 hashing is not used, it systematically walks the next-domain pointers to enumerate the entire DNS zone.
  3. **ASN & Network Resolver**: Queries IP address allocations to determine Autonomous System Numbers (ASN), organization names, CIDR routing prefixes, and reverse PTR hostnames.
- **Commands & tools it uses in the background**:
  - `dnspython` (DNS queries for `NSEC`, `CNAME`, `TXT`, `SOA`)
  - Team Cymru / IPWhois DNS ASN lookup service
- **Information it provides**:
  - Subdomain takeover vulnerability reports.
  - Complete list of zone hostnames harvested via NSEC walking.
  - IP network routing profile (ASN, Org, Country, PTR).
- **Alerts it generates**:
  - `dangling_dns_takeover` (High): Subdomain points to an unallocated cloud service.
  - `dnssec_nsec_zone_walk` (High): Authoritative zone records enumerated via plain NSEC walk.
- **Benefits of what it gathers**:
  - Identifies critical subdomain takeovers before malicious actors claim the domains, and extracts complete internal DNS zones without generating noisy brute-force logs.

---

### Tool 17: `osint_agent.py` — Mail Security Auditor & Public Bucket Correlator

- **What it is for**: Auditing DNS mail anti-spoofing policies (SPF, DMARC, DKIM) and identifying publicly accessible cloud storage buckets associated with corporate domains.
- **What it does**:
  1. **Email Anti-Spoofing Audit**:
     - Evaluates SPF records (`v=spf1`) for dangerous qualifiers (`+all`, `?all`), duplicate records, or missing records.
     - Evaluates DMARC records (`_dmarc.<domain>`) for policy mode (`p=none`, `p=quarantine`, `p=reject`), reporting emails (`rua`), and enforcement percentage.
     - Audits DKIM keys for weak key lengths (< 1024 bits).
  2. **Public Bucket Correlation**: Searches public cloud storage datasets and DNS TXT verification records for exposed S3 and GCS bucket references.
- **Commands & tools it uses in the background**:
  - `dnspython` (DNS TXT queries for SPF, DMARC, and DKIM)
- **Information it provides**:
  - SPF record syntax, DMARC policy mode, and email security compliance status.
  - Populates `domains.osint` dictionary.
- **Alerts it generates**:
  - `osint_email_spoofing` (Medium): Domain lacks DMARC enforcement (`p=none` or missing), allowing email spoofing.
  - `weak_dkim_key` (Medium): DKIM key length is below 1024 bits.
  - `osint_public_buckets` (High): Discovered public cloud storage bucket associated with domain.
- **Benefits of what it gathers**:
  - Identifies domains vulnerable to CEO fraud and business email compromise (BEC) due to absent or non-enforcing email authentication records.

---

### Tool 18: `whois_agent.py` — WHOIS Registrar Intelligence & Sister Domain Correlator

- **What it is for**: Extracting domain registrar registration metadata, tracking expiration timelines to prevent domain lapse hijacking, and correlating corporate sister domains.
- **What it does**:
  1. Queries authoritative WHOIS servers for registered apex domains.
  2. Extracts registrar name, IANA ID, creation date, updated date, expiration date, registrant organization, and status codes.
  3. Calculates exact days remaining until domain expiration.
  4. Correlates registrant organization and email across registered domains to identify sister domains and unmapped corporate acquisitions.
- **Commands & tools it uses in the background**:
  - System `whois` CLI utility
  - Python `re` and `datetime`
- **Information it provides**:
  - Registrar metadata, expiration timestamp, days remaining, and EPP status codes.
  - Correlated corporate sister domain list.
  - Populates `domains.whois` dictionary.
- **Alerts it generates**:
  - `whois_sister_domains` (Info): Newly identified sister domain owned by the same organization.
- **Benefits of what it gathers**:
  - Prevents domain loss by alerting before corporate domains expire, and discovers unknown subsidiary domains owned by the same parent enterprise.

---

### Tool 19: `screenshot_agent.py` — Headless Chromium Visual Page Renderer

- **What it is for**: Rendering live web applications in a sandboxed headless browser to capture high-resolution visual screenshots and thumbnail previews.
- **What it does**:
  1. Launches a sandboxed headless Chromium browser via Playwright with a 1280x800 desktop viewport.
  2. Navigates to active HTTP/HTTPS URLs with SSL verification bypass (`ignore_https_errors=True`).
  3. Waits for network idle states and DOM rendering to ensure dynamic single-page applications are fully captured.
  4. Saves PNG screenshots to `screenshots/<domain>.png` and generates optimized thumbnails for fast dashboard display.
- **Commands & tools it uses in the background**:
  - Playwright Chromium engine
- **Information it provides**:
  - Screenshot file path stored in `domains.screenshot_path`.
  - Visual preview thumbnail rendered in the Asset Inventory search table and Asset Inspector modal.
- **Alerts it generates**:
  - Visual asset preview (no security alerts generated).
- **Benefits of what it gathers**:
  - Allows security analysts to immediately understand what an asset is (e.g. login portal, default router page, error page, staging app) without opening a browser.

---

### Tool 20: `loop_orchestrator.py` — Master Workflow Pipeline Coordinator

- **What it is for**: Master autonomous scheduling daemon managing pipeline execution stages, task queue leasing, dependency ordering, and recovering stalled tasks.
- **What it does**:
  1. Coordinates the multi-stage scanning pipeline:
     - *Stage 1*: Subdomain Discovery
     - *Stage 2*: Web Probing (`alive_check`)
     - *Stage 3*: Network & Service Profiling (`port_scanner`, `tech_fingerprinter`, `waf_detector`, `lb_detector`, `osint_agent`, `screenshot_agent`)
     - *Stage 4*: Deep Surface Hunting (`directory_hunter`, `dynamic_js_collector`, `cloud_storage_auditor`, `archive_hunter`)
     - *Stage 5*: Exploitation & Unpacking (`source_map_unpacker`, `source_code_analyzer`, `bypass_403`)
  2. Leases pending tasks from MongoDB `tasks` collection.
  3. **Stale Task Recovery**: Checks worker heartbeat timestamps in `scanners`. If an agent is dead (> 180s without heartbeat), it reclaims stalled tasks automatically without killing active long-running jobs.
  4. Manages domain rescan schedules based on configured intervals.
  5. Preserves `last_cycle_completed` timestamps to ensure continuous monitoring and drift detection across cycles.
- **Commands & tools it uses in the background**:
  - Python `asyncio` task scheduling loops and `motor.motor_asyncio`.
- **Information it provides**:
  - Coordinates global execution state across all database collections.
- **Alerts it generates**:
  - System orchestration telemetry (no security alerts generated).
- **Benefits of what it gathers**:
  - Ensures the entire reconnaissance platform runs autonomously 24/7 without manual intervention, recovering automatically from process crashes.

---

### Tool 21: `base_agent.py` — Microservice Framework & Alert Engine

- **What it is for**: The foundational abstract base class inherited by all reconnaissance tools, providing database connectivity, scope enforcement, pause handling, alert deduplication, and initial scan suppression.
- **What it does**:
  1. Initializes asynchronous MongoDB connections (`motor`) and sets up standardized structured logging.
  2. Enforces program scope boundaries via `BaseAgent.is_in_scope()`: validates that targets are within the approved domain or wildcard boundary.
  3. Provides `create_alert()` API:
     - Classifies alert titles into normalized keys.
     - Checks Global Settings to verify if the alert type is enabled.
     - **Initial Scan Cycle Rule**: Checks `is_first_scan_cycle(domain_doc)`. If the domain has never completed a scan cycle, any change alert (`port_scanner_changes`, `tech_stack_changes`, `security_header_regressions`) is suppressed.
     - Computes SHA-256 fingerprints to deduplicate alerts.
     - Syncs discovered cloud buckets directly into the domain's cloud storage footprint.
  4. Manages global scan pause synchronization via `asyncio.Event`.
  5. Implements `check_completion(root_domain)`: when all tasks for a root domain finish, sets `scanned: True`, `last_scanned: now_iso`, and marks `initial_scan_completed: True`.
- **Commands & tools it uses in the background**:
  - `motor.motor_asyncio`, `hashlib.sha256`, `urllib.parse`.
- **Information it provides**:
  - Core data models for `scanners`, `leads`, `alert_fingerprints`, and `tasks`.
- **Alerts it generates**:
  - Serves as the central generation, classification, and deduplication gate for all 48 alert types.
- **Benefits of what it gathers**:
  - Ensures robust, modular agent design, guarantees zero out-of-scope scanning, and eliminates false positive change alert noise on newly onboarded domains.

---

### Tool 22: `sanitize_secrets.py` — Sensitive Data Redaction & Presentation Filter

- **What it is for**: Validating discovered credentials and masking sensitive tokens before storage and UI presentation to protect secrets and eliminate false positives.
- **What it does**:
  1. Validates candidate secrets against known token structures (Google API Key, AWS Access Key, AWS Secret Key, JWT Token, Bearer Token, Stripe Key, Firebase Key, Slack Webhook, GitHub Token, SSH Private Key).
  2. Rejects false-positive strings (URLs, file paths, image assets, common code keywords like `recaptcha`, `undefined`, `placeholder`).
  3. Enforces minimum entropy and length thresholds.
  4. Masks sensitive characters (e.g. `AKIA************1234`) for secure display in dashboard tables and reports.
- **Commands & tools it uses in the background**:
  - Python `re` pattern validation.
- **Information it provides**:
  - Sanitized, verified secret objects stored in `domains.web_applications.secrets`.
- **Alerts it generates**:
  - Sanitization filter (no security alerts generated).
- **Benefits of what it gathers**:
  - Prevents alert fatigue by filtering out non-secret strings, and ensures sensitive API keys are presented securely in reports.

---

## 5. Installation & Deployment

### System Requirements

| Resource | Minimum Specification | Recommended Specification |
| :--- | :--- | :--- |
| **Operating System** | Linux (Ubuntu 20.04+, Debian 11+), macOS (Colima / Docker Desktop), Windows (WSL2) | Ubuntu 22.04 LTS x86_64 |
| **Docker Engine** | Version 20.10.0+ | Latest Stable Docker Engine |
| **Docker Compose**| Version 2.0.0+ | Latest Docker Compose v2 |
| **CPU** | 2 Cores | 4 - 8 Cores (for parallel Nmap, FFUF & Chromium) |
| **RAM** | 4 GB | 8 GB - 16 GB |
| **Disk Space** | 20 GB free space | 50 GB+ SSD |

---

### Quickstart Deployment (Docker Compose)

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
   Open `.env` in an editor and define your secure credentials:
   ```bash
   nano .env
   ```
   *Ensure you set a strong `MONGO_ROOT_PASSWORD` and `SECRET_KEY`.*

3. **Launch the Platform**:
   ```bash
   docker compose up -d --build
   ```

4. **Verify Container Status**:
   ```bash
   docker compose ps
   ```
   All 18+ services should be in an `Up` status.

5. **Access the Web Dashboard**:
   - Open your browser to `http://localhost` (or `https://localhost` if Caddy TLS is configured).
   - Default Username: `admin`
   - Default Password: Defined by `ADMIN_INITIAL_PASSWORD` in your `.env` (default: `ChangeMe123!`).

---

### Generating TOTP 2FA Codes

If `DISABLE_2FA=false`, RDash enforces two-factor authentication. Run the included helper script to generate the current TOTP token:

```bash
python3 get_totp.py
```

Output:
```text
=======================================================
  RDash - Local Admin Credentials
=======================================================
  Username     : admin
  Password     : ChangeMe123!
  TOTP Secret  : S5B5SRQQN3VSBAWEZLO34IQMP6HHYRXZ
  Current Code : 591823  (24s remaining)
  TOTP URI     : otpauth://totp/RDash:admin?secret=S5B5SRQQN3VSBAWEZLO34IQMP6HHYRXZ&issuer=RDash
=======================================================
```
*You can import the `TOTP URI` into Google Authenticator, 1Password, or Authy on your mobile device.*

---

## 6. Configuration Reference (`.env`)

| Variable | Description | Default | Security Recommendation |
| :--- | :--- | :--- | :--- |
| `MONGO_ROOT_PASSWORD` | Master password for MongoDB administrative user | *Required* | Use a randomized 32-character string |
| `SECRET_KEY` | HMAC key for signing JWT authentication session cookies | *Required* | Generate via `openssl rand -hex 32` |
| `ADMIN_INITIAL_PASSWORD`| Initial password for the default `admin` account | `ChangeMe123!` | Change immediately upon first deployment |
| `ADMIN_INITIAL_TOTP_SECRET`| Base32 secret for default admin TOTP 2FA | *Random Base32*| Store in a secure password manager |
| `DISABLE_2FA` | Disables mandatory 2FA enforcement | `false` | Set to `false` in production environments |
| `MONGO_HOST` | Hostname or IP of the MongoDB database | `localhost` | Keep `localhost` when using host networking |
| `CHECK_INTERVAL` | Orchestrator queue poll frequency in seconds | `15` | Default is optimal for responsiveness |
| `RESCAN_INTERVAL_HOURS` | Default rescan cadence for completed domains | `168` (1 week) | Set between `24` and `168` hours |

---

## 7. Operational Workflows & Playbooks

### Workflow 1: Continuous Perimeter Monitoring & Drift Detection
1. **Onboarding**: Add target apex domains (e.g. `example.com`) via the `/domains` page.
2. **Initial Baseline Cycle**: The pipeline automatically runs discovery, probing, port scanning, and fingerprinting. Change alerts are suppressed to establish a clean baseline.
3. **Continuous Monitoring**: The orchestrator schedules recurring rescans.
4. **Drift Alerting**: If a developer exposes port 8080, upgrades PHP to an unpatched version, or removes an HSTS header, RDash immediately fires `Port Change Detected`, `Tech Stack Change`, or `Security Header Regression` leads.
5. **Triage & Remediation**: The SOC team investigates the lead, documents the fix in the Notes editor, and marks the alert as `True Positive`.

### Workflow 2: Rapid Single-Target Bug Bounty Assessment
1. **Scope Isolation**: Add the target via `/domains` with **Single Domain Only** enabled. Wildcard expansion is disabled.
2. **Targeted Scanning**: From the `/tools` page, trigger `directory_hunter` and `dynamic_js_collector` with `Top of Queue` priority.
3. **Source Code Recovery**: If `.js.map` files are discovered, `source_map_unpacker` and `source_code_analyzer` automatically extract the original TypeScript source and scan for embedded API tokens.
4. **PoC Documentation**: Promote discovered secrets directly into `/findings`, select the *Sensitive Data Exposure* template, and export a formatted report.

### Workflow 3: Uncloaking Origin Servers Behind WAFs
1. **Discovery**: `alive_check` probes both IPv4 and IPv6 addresses.
2. **Bypass Detection**: If IPv6 returns an Apache banner while IPv4 returns Cloudflare, `alive_check` fires a `Dual-Stack Origin / CDN Bypass Detected` alert.
3. **Exploitation**: Send requests directly to the unshielded IPv6 address with `Host: target.com`, bypassing all WAF filtering rules.

---

## 8. Legal & Ethical Usage

> [!CAUTION]
> **RDash is engineered exclusively for authorized security audits, internal penetration testing, authorized bug bounty engagements, and authorized defensive attack surface management.**
>
> Executing port scans, directory fuzzing, 403 bypasses, or active vulnerability probing against targets without prior explicit written authorization is illegal in most jurisdictions. Users are strictly responsible for adhering to all applicable local, national, and international cybersecurity laws. The creators and contributors assume no liability for misuse or damage caused by this software.
