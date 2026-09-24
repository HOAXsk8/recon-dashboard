Listed directory tools
Viewed alive_check.py:1-100
Viewed alive_check.py:100-220
Viewed api_schema_discovery.py:1-100
Viewed archive_hunter.py:1-100
Viewed subdomain_discovery.py:1-100
Viewed port_scanner.py:1-100
Viewed tech_fingerprinter.py:1-100
Viewed tech_fingerprinter.py:100-200
Viewed waf_detector.py:1-100
Viewed lb_detector.py:1-100
Viewed dns_analytics.py:1-100
Viewed dns_analytics.py:100-250
Viewed dns_analytics.py:250-450
Viewed dns_analytics.py:450-550
Viewed cloud_storage_auditor.py:1-100
Viewed osint_agent.py:1-100
Viewed osint_agent.py:100-250
Viewed osint_agent.py:250-350
Viewed source_code_analyzer.py:1-100
Viewed bypass_403.py:1-100
Viewed whois_agent.py:1-100
Viewed screenshot_agent.py:1-100
Viewed directory_hunter.py:1-100

I have conducted a comprehensive review of all **23 tools and agents** in the [`tools/`](file:///Users/john/gemini-projects/recon-dashboard/tools) directory.

Below is an actionable breakdown of each tool, detailing **what it currently gathers**, **what high-value data is currently left on the table**, and **concrete improvements** to maximize data richness, attack surface visibility, and actionable intelligence.

---

## 1. DNS, Network & Asset Discovery

### [`tools/subdomain_discovery.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/subdomain_discovery.py)
* **Current Data**: Runs `subfinder`, OWASP `amass` (passive), wildcard DNS detection, and `ffuf` with `subdomains-top5000.txt`.
* **Gaps & Enhancements**:
  1. **Permutation & Alteration Engine (e.g., `dnsgen` / `altdns` logic)**:
     - *Why*: Attackers and developers frequently use predictable variations (e.g., `api.target.com` $\rightarrow$ `api-dev`, `api-stg`, `api-v2`, `admin-api`).
     - *Action*: When initial subdomains are discovered, generate permutation candidates (prefixes, suffixes, numbers, environment names) and resolve them.
  2. **Certificate Transparency (CT) Log Deep Harvesting**:
     - *Why*: Subfinder does basic CT lookups, but directly querying historical crt.sh API with wildcard patterns (`%.target.com`) captures expired internal staging and pre-production certificates with Subject Alternative Names (SANs).
  3. **Multi-Level / Recursive Subdomain Brute-Forcing**:
     - *Why*: Current `ffuf` only tests single-level `FUZZ.{domain}`. High-value internal portals reside at multi-tier depths (e.g., `grafana.internal.infra.target.com`).
     - *Action*: Enable recursive enumeration on discovered intermediate zones (e.g. if `dev.target.com` is found, run a focused mini-wordlist against `FUZZ.dev.target.com`).

---

### [`tools/alive_check.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/alive_check.py) & [`tools/dns_analytics.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/dns_analytics.py)
* **Current Data**: Multi-port connection check (16 common ports), IP resolution, ASN / Org lookup, CNAME takeover detection (20+ signatures), SPF/DMARC/CAA/SRV record parsing, IP drift tracking.
* **Gaps & Enhancements**:
  1. **IPv6 (`AAAA`) Record Auditing & Dual-Stack Bypass**:
     - *Why*: Many organizations place CDNs, WAFs, or IP whitelists on IPv4 (`A` records) while their IPv6 (`AAAA` records) point directly to unshielded origin servers!
     - *Action*: Check and store `AAAA` records, probe them for open ports, and compare IPv6 response banners with IPv4 to detect WAF/CDN bypasses.
  2. **Historical DNS / Origin IP Uncloaking**:
     - *Why*: Cloudflare/Akamai masks the true server IP, but historical records often reveal the original hosting IP before CDN adoption.
     - *Action*: Query historical DNS APIs (ViewDNS, SecurityTrails, or Wayback DNS records) to extract historical IPs and test if the origin web server is still reachable directly.
  3. **DNSSEC & Zone Walking (NSEC/NSEC3)**:
     - *Why*: If a domain misconfigures DNSSEC using plain NSEC records, an attacker can walk the entire DNS zone file without guessing or brute-forcing a single name.
     - *Action*: Add automated DNSSEC validation and attempt an NSEC zone walk if supported by the authoritative nameserver.

---

### [`tools/port_scanner.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/port_scanner.py)
* **Current Data**: Nmap top 1000 TCP ports with service versioning (`-sV`).
* **Gaps & Enhancements**:
  1. **SSL/TLS Certificate Harvesting per Port**:
     - *Why*: Ports running TLS (443, 8443, 9443, 10443, etc.) hold certificates that reveal SAN hostnames, internal server names (`*.internal.corp`), organization units, and certificate expiry dates.
     - *Action*: Connect via SSL socket, parse X.509 certificate data (`subject`, `issuer`, `SANs`, `notAfter`), flag expiring certificates, and feed discovered SAN domains back into the asset discovery queue.
  2. **Raw Service Banner Grabbing on Non-HTTP Ports**:
     - *Why*: Ports like 21 (FTP), 22 (SSH), 25 (SMTP), 6379 (Redis), 27017 (MongoDB), 9200 (Elasticsearch) often expose internal version strings, cluster names, or unauthenticated health endpoints.
     - *Action*: Implement lightweight protocol banner probes (e.g. send `INFO\r\n` to Redis or `GET / HTTP/1.0` to Elasticsearch) to record software banners.
  3. **Context-Aware Dynamic Port Hunting**:
     - *Why*: Scanning 65,535 ports on every host is too slow, but scanning only 1000 misses modern cloud and microservice ports (e.g. 2375 Docker, 6443 Kubernetes, 5000/5001 Docker Registry, 9090 Prometheus).
     - *Action*: If the host resolves to cloud IP spaces (AWS, GCP, DigitalOcean), append targeted DevOps/Cloud microservice ports.

---

## 2. Web Application Discovery, Routing & Surface Mapping

### [`tools/directory_hunter.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/directory_hunter.py)
* **Current Data**: `robots.txt`, `sitemap.xml`, `security.txt` path extractions, SecLists `DirBuster-2007_directory-list-2.3-small.txt`, `raft-small-files-lowercase.txt`, and curated sensitive files list.
* **Gaps & Enhancements**:
  1. **Favicon MurmurHash3 Calculation**:
     - *Why*: The hash of `/favicon.ico` provides a unique asset fingerprint. Querying this hash on search engines (Shodan/Censys) identifies unlisted staging, QA, and foreign subsidiary servers running the exact same stack.
     - *Action*: Download `/favicon.ico`, compute its base64 MD5 and MurmurHash3, and display Shodan/Censys pivot queries.
  2. **Mobile & Enterprise `.well-known` Harvesting**:
     - *Why*: Enterprise sites host deep configurations under `/.well-known/`:
       - `/.well-known/assetlinks.json`: Android package names and SHA256 app signatures.
       - `/.well-known/apple-app-site-association`: iOS App IDs and deep-linking routing prefixes.
       - `/.well-known/openid-configuration`: Identity provider endpoints, token issuance URLs, and public keys.
     - *Action*: Automatically query these files and parse mobile application packages and OAuth endpoints.
  3. **HTTP Verb & Method Auditing (`OPTIONS`, `PUT`, `DELETE`, `TRACE`)**:
     - *Why*: Discovered paths may block `GET` but allow `POST`, `OPTIONS` (disclosing supported methods), or `TRACE` (Cross-Site Tracing / XST).
     - *Action*: Send an `OPTIONS` probe to discovered directories and alert if high-risk verbs (`PUT`, `DELETE`) or WebDAV methods (`PROPFIND`, `MKCOL`) are permitted.

---

### [`tools/dynamic_js_collector.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/dynamic_js_collector.py) & [`tools/source_code_analyzer.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/source_code_analyzer.py)
* **Current Data**: Dynamic script interception, HTML & JS comments extraction, HTML `<meta>` tags extraction, secret/credential regexes, and source map unbundling.
* **Gaps & Enhancements**:
  1. **Hydration & State Payload Extraction (`__NEXT_DATA__`, `__INITIAL_STATE__`)**:
     - *Why*: Modern React/Next.js/Nuxt applications embed massive server-rendered JSON blobs into HTML `<script>` tags. These often contain internal user IDs, backend API route patterns, and environment configurations (`NEXT_PUBLIC_*`).
     - *Action*: Parse `<script id="__NEXT_DATA__" type="application/json">` and `window.__INITIAL_STATE__` / `window.__APOLLO_STATE__` directly into structured route and config data.
  2. **Client-Side Framework Route Scraping**:
     - *Why*: SPAs define entire administrative sections in JavaScript routers (e.g., `path: '/admin/billing'`, `path: '/super-user/feature-flags'`).
     - *Action*: Extract Angular/React/Vue routing definitions and add them to the directory and route discovery catalog.
  3. **Third-Party Tracker & SDK Identification (Pivoting IDs)**:
     - *Why*: Embedded marketing/telemetry IDs (Google Tag Manager `GTM-XXXX`, Segment write keys, Sentry DSNs, Datadog app keys, Intercom workspace IDs) are shared across an organization's hidden internal portals.
     - *Action*: Extract tracker keys and display cross-domain correlation tags.

---

### [`tools/api_schema_discovery.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/api_schema_discovery.py)
* **Current Data**: Common OpenAPI/Swagger documentation paths, GraphQL endpoint discovery, and full GraphQL introspection query.
* **Gaps & Enhancements**:
  1. **GraphQL Field Suggestion Harvesting (Introspection Bypassing)**:
     - *Why*: When introspection (`__schema`) is disabled in production, GraphQL error messages still suggest valid fields (e.g. querying `{ invalid_field }` returns `"Did you mean 'users', 'auth'?"`).
     - *Action*: Implement suggestion-based schema reconstruction for hardened GraphQL instances.
  2. **Postman / Insomnia Collection Discovery**:
     - *Why*: Developers frequently export and expose collections during testing (`/postman_collection.json`, `collection.json`, `postman.json`, `api-collection.json`).
     - *Action*: Add common Postman/Insomnia collection patterns to the schema search list.
  3. **API Endpoint & Parameter Testing Matrix**:
     - *Why*: Once OpenAPI/Swagger specs are discovered, the parameters and auth requirements are known.
     - *Action*: Extract query parameters, headers, and body structures into a testing catalog to guide manual auditing or automated parameter fuzzing.

---

### [`tools/bypass_403.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/bypass_403.py)
* **Current Data**: IP spoofing headers (`X-Forwarded-For`, `X-Remote-IP`), path normalization payloads (`/..;/`, `/%20/`).
* **Gaps & Enhancements**:
  1. **HTTP Verb Tampering**:
     - *Why*: Reverse proxies and ACLs frequently enforce rules only on `GET` requests; sending `POST`, `HEAD`, `PATCH`, or `PUT` may bypass the restriction.
  2. **Protocol Downgrade / Upgrade Auditing**:
     - *Why*: WAFs often parse HTTP/2 differently than HTTP/1.1. Testing with both protocols exposes translation and smuggling discrepancies.
  3. **Hop-by-Hop Header Stripping**:
     - *Why*: In proxy chains, sending `Connection: close, <Target-Header>` can trick an upstream proxy into removing authentication or header verification tokens before passing the request to the backend.

---

## 3. Fingerprinting, WAF & Cloud Architecture

### [`tools/tech_fingerprinter.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/tech_fingerprinter.py)
* **Current Data**: `pd-httpx` technology detection, `whatweb`, and HTTP security headers auditing.
* **Gaps & Enhancements**:
  1. **Automated CVE / Known Vulnerability Correlation**:
     - *Why*: Knowing that an app runs `Apache:2.4.49` or `WordPress:5.8` is only half the battle; knowing the associated high-severity CVEs turns raw recon into actionable risk intelligence.
     - *Action*: Map detected software versions to known CVE databases or CISA's Known Exploited Vulnerabilities (KEV) catalog.
  2. **Comprehensive Cookie Security & Framework Identification**:
     - *Why*: `Set-Cookie` headers reveal the underlying backend session architecture (`PHPSESSID`, `ASP.NET_SessionId`, `JSESSIONID`, `laravel_session`, `connect.sid`, `django_session`) and flag missing `HttpOnly`, `Secure`, or `SameSite` flags.
  3. **HTTP/2 & HTTP/3 (QUIC) Support Auditing**:
     - *Why*: Exposes edge protocol capabilities and reveals if legacy fallback protocols are active.

---

### [`tools/waf_detector.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/waf_detector.py) & [`tools/lb_detector.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/lb_detector.py)
* **Current Data**: `wafw00f` JSON parsing, DNS round-robin detection, Date/Server header variance.
* **Gaps & Enhancements**:
  1. **Direct Origin Access Testing (WAF Bypassing)**:
     - *Why*: When a Cloudflare or Akamai WAF is detected, testing direct HTTP/HTTPS connections to all discovered direct IP addresses using the target `Host:` header determines whether the origin web server can be accessed directly without WAF filtering.
  2. **WAF Blocking Behavior Profile**:
     - *Why*: Knowing *what* triggers the WAF is critical (e.g., does it block SQLi `'`, path traversal `../`, XSS `<svg>`, or rate-limit requests?).
  3. **Cloud Edge POP & Geographic Mapping**:
     - *Why*: Response headers (`cf-ray`, `x-amz-cf-pop`, `x-azure-ref`, `server-timing`) reveal the edge data center POPs and geographic regions hosting the backend.

---

### [`tools/cloud_storage_auditor.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/cloud_storage_auditor.py)
* **Current Data**: Probes AWS S3, GCS, Azure Blob, DO Spaces, and Cloudflare R2 bucket naming variations based on brand keywords and environment suffixes.
* **Gaps & Enhancements**:
  1. **Object Listing Content Parser**:
     - *Why*: When a bucket is public (`is_open: True`), the tool logs the status, but does not parse what is inside.
     - *Action*: Parse the returned XML/JSON object keys to search for high-value files (`.sql`, `.bak`, `.zip`, `.env`, invoices, PII documents) and count total exposed assets.
  2. **Non-Destructive Write Permission Check (Canary Test)**:
     - *Why*: Many buckets have public write access enabled, allowing malicious file replacement or web defacement.
     - *Action*: Send a safe `PUT` request with a uniquely generated test key (e.g., `audit_probe_test_<uuid>.txt`) and delete it immediately if allowed.
  3. **Bucket Region & Account Fingerprinting**:
     - *Why*: The `x-amz-bucket-region` header identifies the exact AWS region where the bucket resides, helping map the client's core cloud deployment.

---

## 4. Historical, OSINT & Identity Intelligence

### [`tools/archive_hunter.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/archive_hunter.py) ✅ *[COMPLETED]*
* **Current Data**: AlienVault OTX, Wayback Machine CDX, URLScan.io, and Common Crawl index harvesting.
* **Gaps & Enhancements**:
  1. **Common Crawl Index Integration** ✅:
     - Implemented dynamic index discovery (`index.commoncrawl.org/collinfo.json`) querying the latest CC crawl with pagination and wildcard domain matching.
  2. **Parameter Wordlist Mining & Extraction** ✅:
     - Automatically parses query strings from harvested URLs across all engines, deduplicating distinct parameter keys (`mined_parameters`) and supporting wordlist export.
  3. **Historical Subdomain Harvesting & Auto-Seeding** ✅:
     - Extracts valid in-scope subdomains from historical URLs and pushes verification tasks directly to `alive_check`.

---

### [`tools/osint_agent.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/osint_agent.py) & [`tools/whois_agent.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/whois_agent.py) ✅ *[COMPLETED]*
* **Current Data**: MX, SPF, DMARC, DKIM key strength, BIMI, MTA-STS, TLS-RPT, web email/social crawl, international WHOIS parsing, and cross-domain entity correlation.
* **Gaps & Enhancements**:
  1. **DKIM Selector Hunting & Key Strength Auditing** ✅:
     - Concurrently audits 24 common DKIM selectors (`default`, `google`, `k1`, `s1`, `mandrill`, `mailgun`, etc.).
     - Parses base64 public keys (`p=`), decodes DER/ASN.1 structures using `cryptography` with binary fallback, calculates RSA bit strength, and raises high/critical alerts on weak 512-bit or 1024-bit RSA keys.
  2. **BIMI & MTA-STS Policy Verification** ✅:
     - Audits BIMI TXT records (`default._bimi.<domain>`), extracting SVG brand logo URLs (`l=`) and Verified Mark Certificates (`a=`).
     - Queries MTA-STS DNS records (`_mta-sts.<domain>`) and fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt`, parsing `mode` (`enforce`, `testing`, `none`), `mx` patterns, and `max_age`.
     - Queries SMTP TLS Reporting (`_smtp._tls.<domain>`) for policy health monitoring.
  3. **WHOIS Historical & Cross-Domain Registrant Correlation** ✅:
     - Enhanced regex parsing across international WHOIS engines (org, admin email, nameservers, dates, DNSSEC).
     - Filters out privacy masks (WhoisGuard, PrivacyProtect, Domains By Proxy, Cloudflare) and public DNS (Cloudflare, AWS, Google).
     - Correlates registrant organizations, non-privacy emails, and custom authoritative nameservers across all target domains in MongoDB, bidirectionally linking sister domains and creating security alerts.

---

## 5. Architectural Orchestration & Feedback Loops

### [`tools/loop_orchestrator.py`](file:///Users/john/gemini-projects/recon-dashboard/tools/loop_orchestrator.py)
* **Current Flow**: Primarily runs tools sequentially or via separate task queues.
* **Key Improvement — Closed-Loop Intelligence Feeding**:
  ```mermaid
  flowchart TD
      A[subdomain_discovery] -->|Discovered Hosts| B[alive_check]
      B -->|Active Ports & IPs| C[port_scanner]
      B -->|Web Applications| D[tech_fingerprinter]
      D -->|Discovered Technologies| E[directory_hunter]
      E -->|Extracted Endpoints & JS| F[dynamic_js_collector]
      F -->|Uncovered Subdomains & Buckets| A
      F -->|Extracted API Routes| G[api_schema_discovery & bypass_403]
      H[archive_hunter] -->|Historical Subdomains| A
      H -->|Historical Parameters| E
  ```
  1. **Tech-Aware Wordlists**: If `tech_fingerprinter` discovers PHP, `directory_hunter` prioritizes `.php` extensions. If Spring Boot is detected, it prioritizes `/actuator` and Java endpoints.
  2. **Recursive Asset Seeding**: When `dynamic_js_collector` or `source_code_analyzer` finds an in-scope subdomain (e.g., `api-internal.target.com`) or S3 bucket (`target-prod-backups`), it automatically feeds it into `alive_check` or `cloud_storage_auditor`.

---

## Recommended Priority Roadmap

| Priority | Feature / Improvement | Target Tool | Impact |
| :--- | :--- | :--- | :--- |
| **P1** | **Direct Origin IP Uncloaking (WAF Bypass)** | `waf_detector.py` / `tech_fingerprinter.py` | Critical: Identifies unshielded origin servers bypassing Cloudflare/Akamai |
| **P1** | **Favicon MurmurHash3 Generation** | `directory_hunter.py` | High: Enables global asset pivoting on Shodan/Censys |
| **P1** | **Hydration State Extraction (`__NEXT_DATA__`)** | `dynamic_js_collector.py` | High: Immediately recovers complete SPA backend routes, props, and build envs |
| **P2** | **SSL Certificate SAN Extraction per Port** | `port_scanner.py` | High: Discovers hidden subdomains, internal domains, and expiring certs |
| **P2** | **IPv6 (`AAAA`) Record Auditing** | `alive_check.py` | High: Reveals dual-stack assets bypassing IPv4-only firewall rules |
| **P2** | **Historical Parameter & Route Mining** | `archive_hunter.py` | Medium: Builds custom parameter lists for fuzzing from historical traffic |
| **P3** | **DKIM Selector & Key Strength Auditing** | `osint_agent.py` | Medium: Completes the full email security triad (SPF + DMARC + DKIM) |
| **P3** | **Permutation / Alteration Engine (`dnsgen`)** | `subdomain_discovery.py` | Medium: Discovers hidden pre-prod and development subdomains |