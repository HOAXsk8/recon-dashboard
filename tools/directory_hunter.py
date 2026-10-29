import asyncio
import datetime
import logging
import json
import os
import re
import base64
import codecs
import hashlib
import secrets
import urllib.parse
from collections import Counter, deque
import httpx
try:
    import mmh3
except ImportError:
    mmh3 = None

def mmh3_hash32(key: bytes, seed: int = 0) -> int:
    """Pure-Python implementation of MurmurHash3 32-bit (x86). Matches Shodan http.favicon.hash standard."""
    length = len(key)
    nblocks = length // 4
    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for i in range(nblocks):
        k1 = int.from_bytes(key[i*4 : (i+1)*4], byteorder='little')
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

    tail = key[nblocks * 4:]
    k1 = 0
    tail_len = len(tail)
    if tail_len == 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)

    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1

FAVICON_FRAMEWORKS = {
    116323821: "Spring Boot",
    0: "Spring Boot",
    81586312: "Jenkins",
    942082276: "Jira",
    -942082276: "Jira",
    -305179312: "Confluence",
    -2053896777: "Django",
    1583491410: "WordPress",
    -1444555869: "WordPress",
    611598424: "WordPress",
    1278323681: "GitLab",
    -821946395: "Grafana",
    -159868778: "Kibana",
    1231872951: "phpMyAdmin",
    -1343825835: "Apache Tomcat",
    -125026938: "Vue.js",
    539070856: "React",
    -190379963: "React",
    -1812328221: "Next.js",
    827727986: "Laravel",
    -134704386: "Laravel",
    -1308960810: "Ruby on Rails",
    -1205602330: "Flask",
    -1250860824: "Express",
    -1049788196: "Strapi",
    -1107567735: "Directus",
    -1473111077: "Keycloak",
    -1875154378: "cPanel",
    -1981143896: "Plesk",
    -1488032435: "Apache Superset",
    -1065135167: "Sonarqube",
    -188241517: "RabbitMQ",
    143329046: "Swagger UI",
    -34674003: "Consul",
    1398055326: "Zabbix",
    644781744: "Roundcube",
    -1698260799: "OwnCloud",
    -1111629853: "Nextcloud",
    1466099395: "Drupal",
    -1042788506: "Joomla",
    -1520138950: "Ghost",
    -2041285408: "Shopify",
}

FAVICON_MD5_FRAMEWORKS = {
    "0488faca4c3fb063a4504a18fa764698": "Spring Boot",
    "28f51142940251765c9296bc7520e5db": "Jenkins",
    "f46e297858bf43cbe665e7d2cf2e411b": "WordPress",
    "709dcf348698044700d23fb275811d7f": "Django",
    "e485459344407ab6b64f33d7d740c025": "GitLab",
    "98b46574c866f82794eb8e3efb69204c": "Grafana",
    "858d247f12eb60b64f52e505cc7eeefb": "Jira",
    "074b6aa6b231eb93a89a05cb3d9bb205": "phpMyAdmin",
    "5d70e671754020a5976b7e64177db0a2": "Apache Tomcat",
    "2f4469e36502da28562725faeb2074e5": "Laravel",
    "600282b8a6fcf7c7c1fa79c6bb1cb6d2": "Next.js",
    "bb635560b4fb8a6669910d5f8ceb0981": "Vue.js",
    "5c75ff3bb4e44439c2c62c95d2c20638": "React",
}

from base_agent import BaseAgent, logger

DIR_WORDLIST = "/app/wordlists/common-directories.txt"
FULL_DIR_WORDLIST = "/app/wordlists/DirBuster-2007_directory-list-2.3-small.txt"
FILE_WORDLIST = "/app/wordlists/raft-small-files-lowercase.txt"

LOCAL_DIR_WORDLIST = "wordlists/common-directories.txt"
LOCAL_FULL_DIR_WORDLIST = "wordlists/DirBuster-2007_directory-list-2.3-small.txt"
LOCAL_FILE_WORDLIST = "wordlists/raft-small-files-lowercase.txt"

TECH_WORDLISTS = {
    "php": ["/app/wordlists/php-files.txt", "wordlists/php-files.txt"],
    "asp": ["/app/wordlists/asp-files.txt", "wordlists/asp-files.txt"],
    "java": ["/app/wordlists/java-files.txt", "wordlists/java-files.txt"],
    "node": ["/app/wordlists/node-files.txt", "wordlists/node-files.txt"],
    "python": ["/app/wordlists/python-files.txt", "wordlists/python-files.txt"],
}

SECLISTS_DIRBUSTER_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt"
SECLISTS_RAFT_FILES_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files-lowercase.txt"

# Curated high-impact sensitive files scanned across EVERY discovered directory
CURATED_SENSITIVE_FILES = [
    # Environment & Secrets
    ".env", ".env.local", ".env.production", ".env.dev", ".env.stage", ".env.backup", ".env.old",
    ".git/config", ".git/HEAD", ".gitignore", ".htaccess", ".htpasswd", ".DS_Store", ".npmrc",
    "web.config", "web.config.bak", "settings.py", "settings.json", "secrets.json", "credentials.json",
    "parameters.yml", "database.yml", "config.json", "config.php", "config.php.bak", "config.yaml",
    "config.yml", "configuration.php", "appsettings.json", "appsettings.Development.json",
    
    # Backups & Dumps
    "backup.zip", "backup.tar.gz", "backup.tgz", "backup.sql", "dump.sql", "db.sql", "database.sql",
    "database.sqlite", "data.sql", "site.zip", "app.zip", "old.zip", "archive.zip", "1.zip", "temp.zip",
    "backup.bak", "backup.old", "db.sqlite3", "dump.tar.gz",
    
    # Admin & Portals
    "admin.php", "admin.html", "admin.jsp", "admin.aspx", "login.php", "login.html", "login.jsp",
    "auth.php", "dashboard.php", "dashboard.html", "users.php", "manage.php", "portal.php",
    "control.php", "master.php", "panel.php", "root.php", "console",
    
    # APIs & Schemas
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "api.json", "schema.json",
    "swagger-ui.html", "api-docs", "graphql", "graphiql",
    
    # Diagnostics & Internal
    "phpinfo.php", "info.php", "version.txt", "readme.txt", "readme.md", "changelog.txt",
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt", "health", "healthz", "metrics", "actuator/health", "actuator/env",
    "actuator", "server-status", "debug", "test.php", "test.html",
    
    # Mobile & Enterprise Well-Known & Assets
    "favicon.ico", ".well-known/assetlinks.json", ".well-known/apple-app-site-association",
    "apple-app-site-association", ".well-known/openid-configuration", ".well-known/oauth-authorization-server",

    # Common entrypoints & assets
    "index.php", "index.html", "main.js", "app.js", "api.php", "upload.php", "download.php"
]

class DirectoryHunterAgent(BaseAgent):
    def __init__(self):
        instance_id = os.getenv("INSTANCE_ID", "").strip()
        agent_key = f"directory_hunter_{instance_id}" if instance_id else "directory_hunter"
        agent_name = f"Directory & File Hunter #{instance_id}" if instance_id else "Directory & File Hunter"
        super().__init__(agent_key, agent_name)
        self.alert_hashes_col = self.db["alert_hashes"]
        self.probe_cache = {}

    def get_directory_wordlist(self) -> str:
        """
        Locates the directory wordlist. Prioritizes the curated common-directories.txt,
        falling back to DirBuster-2007_directory-list-2.3-small.txt.
        Auto-downloads from SecLists GitHub if missing.
        """
        for p in [
            DIR_WORDLIST,
            LOCAL_DIR_WORDLIST,
            FULL_DIR_WORDLIST,
            LOCAL_FULL_DIR_WORDLIST,
            "/app/wordlists/directory-list-2.3-small.txt",
            "wordlists/directory-list-2.3-small.txt",
        ]:
            if os.path.exists(p):
                return p

        # Attempt to auto-download if not present
        target_dest = FULL_DIR_WORDLIST if os.path.exists("/app/wordlists") else LOCAL_FULL_DIR_WORDLIST
        try:
            os.makedirs(os.path.dirname(target_dest), exist_ok=True)
            logger.info(f"Downloading DirBuster-2007_directory-list-2.3-small.txt from SecLists to {target_dest}...")
            import urllib.request
            urllib.request.urlretrieve(SECLISTS_DIRBUSTER_URL, target_dest)
            logger.info(f"Successfully downloaded DirBuster list ({os.path.getsize(target_dest)} bytes)")
            return target_dest
        except Exception as e:
            logger.warning(f"Failed to auto-download DirBuster list from SecLists: {e}")
            return ""

    def get_file_wordlist(self) -> str:
        """
        Locates the SecLists raft-small-files wordlist (raft-small-files-lowercase.txt).
        Auto-downloads from SecLists GitHub if missing.
        """
        for p in [
            FILE_WORDLIST,
            LOCAL_FILE_WORDLIST,
            "/app/wordlists/raft-small-files.txt",
            "/app/wordlists/common-files.txt",
            "wordlists/raft-small-files.txt",
            "wordlists/common-files.txt",
        ]:
            if os.path.exists(p):
                return p

        # Attempt auto-download if missing
        target_dest = FILE_WORDLIST if os.path.exists("/app/wordlists") else LOCAL_FILE_WORDLIST
        try:
            os.makedirs(os.path.dirname(target_dest), exist_ok=True)
            logger.info(f"Downloading raft-small-files-lowercase.txt from SecLists to {target_dest}...")
            import urllib.request
            urllib.request.urlretrieve(SECLISTS_RAFT_FILES_URL, target_dest)
            logger.info(f"Successfully downloaded raft small files list ({os.path.getsize(target_dest)} bytes)")
            return target_dest
        except Exception as e:
            logger.warning(f"Failed to auto-download raft small files list from SecLists: {e}")
            return ""

    def get_tech_file_wordlist(self, tech_cat: str) -> list:
        """
        Reads dedicated technology-specific file wordlists (e.g. PHP, ASP, Java, Node, Python).
        """
        candidates = TECH_WORDLISTS.get(tech_cat.lower(), [])
        for p in candidates:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [line.strip().lstrip("/") for line in f if line.strip() and not line.startswith("#")]
                        if lines:
                            return lines
                except Exception as e:
                    logger.debug(f"Error reading tech wordlist {p}: {e}")
        return []

    def identify_tech_from_file_path(self, path: str) -> list:
        """
        Analyzes a discovered file path and identifies any associated technologies.
        Returns a list of technology names (e.g. ['PHP', 'WordPress'], ['ASP.NET', 'IIS'], ['Java', 'Spring Boot']).
        """
        p_lower = path.lower().strip()
        techs = []

        # PHP & PHP Frameworks
        if re.search(r'\.(php\d?|phtml|inc|phar)$', p_lower) or any(x in p_lower for x in ['wp-config.php', 'xmlrpc.php', 'wp-login.php', 'phpinfo.php', 'composer.json']):
            techs.append("PHP")
        if any(x in p_lower for x in ['wp-config.php', 'wp-login.php', 'xmlrpc.php', 'wp-content', 'wp-includes']):
            techs.append("WordPress")
            if "PHP" not in techs:
                techs.append("PHP")
        if any(x in p_lower for x in ['artisan', 'composer.json', 'composer.lock', 'laravel']):
            techs.append("Laravel")
            if "PHP" not in techs:
                techs.append("PHP")
        if any(x in p_lower for x in ['drupal', 'sites/default']):
            techs.append("Drupal")
            if "PHP" not in techs:
                techs.append("PHP")
        if any(x in p_lower for x in ['joomla', 'configuration.php']):
            techs.append("Joomla")
            if "PHP" not in techs:
                techs.append("PHP")

        # Microsoft / ASP.NET / IIS
        if re.search(r'\.(aspx?|ashx|asmx|axd|cs|vb)$', p_lower) or 'web.config' in p_lower or 'appsettings.json' in p_lower:
            techs.append("ASP.NET")
            techs.append("IIS")

        # Java / Spring Boot / Tomcat
        if re.search(r'\.(jspx?|do|action|war|jar)$', p_lower) or any(x in p_lower for x in ['actuator/', 'web-inf/', 'meta-inf/', 'application.properties', 'application.yml', 'pom.xml']):
            techs.append("Java")
        if any(x in p_lower for x in ['actuator/', 'application.properties', 'application.yml']):
            techs.append("Spring Boot")
            if "Java" not in techs:
                techs.append("Java")
        if any(x in p_lower for x in ['manager/html', 'host-manager/html']):
            techs.append("Apache Tomcat")
            if "Java" not in techs:
                techs.append("Java")

        # Node.js & Javascript Runtimes
        if any(x in p_lower for x in ['package.json', 'package-lock.json', '.npmrc', 'server.js', 'next.config.js', 'nuxt.config.js']):
            techs.append("Node.js")
        if 'next.config' in p_lower or '_next/' in p_lower:
            techs.append("Next.js")
            if "Node.js" not in techs:
                techs.append("Node.js")

        # Python & Frameworks
        if any(x in p_lower for x in ['wsgi.py', 'asgi.py', 'requirements.txt', 'settings.py', 'pipfile', 'pyproject.toml', 'manage.py']):
            techs.append("Python")
        if any(x in p_lower for x in ['settings.py', 'manage.py']):
            techs.append("Django")
            if "Python" not in techs:
                techs.append("Python")

        # Ruby / Rails
        if any(x in p_lower for x in ['gemfile', 'gemfile.lock', 'config/database.yml', 'config/routes.rb']):
            techs.append("Ruby on Rails")

        # ColdFusion
        if re.search(r'\.(cfc|cfm)$', p_lower):
            techs.append("ColdFusion")

        return list(dict.fromkeys(techs))

    async def update_tech_fingerprint(self, target: str, root_domain: str, new_techs: list, source_file: str, base_url: str):
        """
        Persists newly identified technology to target and root domain documents in MongoDB,
        and creates an informative tech_stack_changes alert lead.
        """
        clean_target = target.lower().strip()
        clean_root = root_domain.lower().strip()
        
        # 1. Update target document
        await self.domains_col.update_one(
            {"domain": clean_target},
            {"$addToSet": {"tech_stack": {"$each": new_techs}}}
        )
        await self.domains_col.update_one(
            {"domain": clean_target, "web_applications.target": target},
            {"$addToSet": {"web_applications.$.tech_stack": {"$each": new_techs}}}
        )
        
        # 2. Update parent root domain document
        if clean_root != clean_target:
            await self.domains_col.update_one(
                {"domain": clean_root, "web_applications.target": target},
                {"$addToSet": {"web_applications.$.tech_stack": {"$each": new_techs}}}
            )

        # 3. Check apex domain candidates
        parts = clean_target.split(".")
        for i in range(1, len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand != clean_target:
                await self.domains_col.update_one(
                    {"domain": cand, "web_applications.target": target},
                    {"$addToSet": {"web_applications.$.tech_stack": {"$each": new_techs}}}
                )
            
        # 4. Create tech stack alert
        title = f"Tech Stack Discovery: {', '.join(new_techs)} Identified"
        desc = f"Newly identified technology {', '.join(new_techs)} discovered on {target} via file finding: {source_file}"
        details = (
            f"**Target:** `{target}` ({root_domain})\n"
            f"**Discovered Technologies:** `{', '.join(new_techs)}`\n"
            f"**Discovery Source File:** `{source_file}`\n"
            f"**URL:** {base_url}/{source_file}"
        )
        exploitation = (
            f"1. **Technology-Specific Audit**: Run focused enumeration and security checks for {', '.join(new_techs)}.\n"
            f"2. **Check for Known CVEs**: Cross-reference identified components with vulnerability feeds.\n"
            f"3. **File Access Control**: Verify that `{source_file}` does not expose sensitive source code or credentials."
        )
        try:
            await self.create_alert(
                title=title,
                description=desc,
                target=target,
                risk_level="info",
                details=details,
                exploitation_suggestions=exploitation,
                alert_type="tech_stack_changes",
                root_domain=root_domain
            )
        except Exception as e:
            logger.debug(f"Error creating tech discovery alert: {e}")

    def _extract_dirs_from_path(self, path: str, dir_set: set, target: str = "", root_domain: str = ""):
        """Extracts directory prefix hierarchy from an in-scope route or endpoint path."""
        if not path or not isinstance(path, str):
            return
        if path.startswith("http://") or path.startswith("https://"):
            try:
                parsed = urllib.parse.urlparse(path)
                u_host = (parsed.hostname or "").lower().strip()
                clean_target = (target or "").lower().strip()
                clean_root = (root_domain or "").lower().strip()
                # Verify that absolute URLs belong to our target or root_domain
                if clean_target or clean_root:
                    in_scope = False
                    if clean_target and (u_host == clean_target or u_host.endswith("." + clean_target)):
                        in_scope = True
                    elif clean_root and (u_host == clean_root or u_host.endswith("." + clean_root)):
                        in_scope = True
                    if not in_scope:
                        return
                path = parsed.path
            except Exception:
                return
        path = path.split("?")[0].split("#")[0].strip()
        parts = [p.strip() for p in path.strip("/").split("/") if p.strip()]
        if not parts:
            return
        for i in range(1, len(parts) + 1):
            sub_path = "/".join(parts[:i])
            # Filter out static files (.png, .css, .js, .map, etc.)
            if not re.search(r'\.(html|htm|js|css|png|jpg|jpeg|svg|gif|ico|woff|woff2|ttf|map|json|txt|xml|pdf)$', sub_path, re.I):
                dir_set.add(sub_path)

    async def harvest_initial_directories(self, target: str, root_domain: str) -> set:
        """
        Harvests initial seed directories from:
        1. Dynamic JS Collector in-scope routes & endpoints stored in web_applications and domain docs
        2. Prior discovered directories
        """
        initial_dirs = set([""]) # Always start with root
        clean_target = target.lower().strip()
        clean_root = root_domain.lower().strip()

        # Query all documents where target or root_domain is present
        query = {
            "$or": [
                {"domain": clean_target},
                {"domain": clean_root},
                {"web_applications.target": clean_target},
                {"web_applications.target": target}
            ]
        }
        try:
            docs = await self.domains_col.find(query).to_list(length=20)
            for doc in docs:
                # Top level routes if any
                for r in doc.get("client_routes", []) + doc.get("dynamic_js", {}).get("client_routes", []):
                    path = r.get("path") if isinstance(r, dict) else str(r)
                    self._extract_dirs_from_path(path, initial_dirs, target=clean_target, root_domain=clean_root)
                for ep in doc.get("extracted_endpoints", []) + doc.get("dynamic_js", {}).get("extracted_endpoints", []):
                    if isinstance(ep, dict) and ep.get("is_in_scope") is False:
                        continue
                    path = ep.get("path") or ep.get("url") if isinstance(ep, dict) else str(ep)
                    self._extract_dirs_from_path(path, initial_dirs, target=clean_target, root_domain=clean_root)

                # Web applications
                for app in doc.get("web_applications", []):
                    app_t = (app.get("target") or "").lower().strip()
                    if app_t == clean_target or clean_target in (app.get("url") or "").lower():
                        all_routes = (
                            (app.get("client_routes") or []) +
                            (app.get("routes") or []) +
                            (app.get("dynamic_js", {}).get("client_routes") or [])
                        )
                        for r in all_routes:
                            path = r.get("path") if isinstance(r, dict) else str(r)
                            self._extract_dirs_from_path(path, initial_dirs, target=clean_target, root_domain=clean_root)

                        all_eps = (
                            (app.get("extracted_endpoints") or []) +
                            (app.get("dynamic_js", {}).get("extracted_endpoints") or []) +
                            (app.get("dynamic_js", {}).get("api_discovered_routes") or [])
                        )
                        for ep in all_eps:
                            if isinstance(ep, dict) and ep.get("is_in_scope") is False:
                                continue
                            path = ep.get("path") or ep.get("url") if isinstance(ep, dict) else str(ep)
                            self._extract_dirs_from_path(path, initial_dirs, target=clean_target, root_domain=clean_root)

                        for dd in app.get("discovered_directories", []):
                            dp = dd.get("path") if isinstance(dd, dict) else str(dd)
                            dp = dp.strip("/")
                            if dp:
                                initial_dirs.add(dp)
        except Exception as e:
            logger.warning(f"Error harvesting initial directories from DB: {e}")

        logger.info(f"[+] Harvested {len(initial_dirs)} seed directories from JS discovery & prior findings for {target}: {sorted(list(initial_dirs))[:10]}")
        return initial_dirs

    def generate_contextual_permutations(self, target: str, root_domain: str) -> list:
        """
        Generates brand-, domain-, and environment-specific permutations for high-value
        target discovery (backups, database dumps, environment configs, private keys).
        """
        tokens = set()
        clean_target = (target or "").lower().strip()
        clean_root = (root_domain or "").lower().strip()

        # 1. Extract apex brand token (e.g. virginmedia from virginmedia.co.uk)
        root_base = clean_root
        for tld in [".co.uk", ".com.au", ".co.nz", ".co.jp", ".com", ".net", ".org", ".io", ".tech", ".co", ".app", ".dev", ".uk", ".de", ".eu"]:
            if root_base.endswith(tld):
                root_base = root_base[:-len(tld)]
                break
        if root_base:
            tokens.add(root_base)
            for part in re.split(r'[-_.]', root_base):
                if len(part) >= 3:
                    tokens.add(part)

        # 2. Extract subdomain tokens (e.g. vmanep, euw2, sit7, api, admin)
        target_no_root = clean_target.replace(clean_root, "").strip(".")
        if target_no_root:
            for chunk in re.split(r'[-_.]', target_no_root):
                if chunk and len(chunk) >= 2:
                    tokens.add(chunk)
                    m = re.match(r'^([a-zA-Z]+)(\d+)$', chunk)
                    if m:
                        tokens.add(m.group(1))

        # Add common environment labels if present
        env_labels = ["sit", "dev", "stage", "staging", "uat", "prod", "production", "test", "qa"]
        for env in env_labels:
            if env in clean_target:
                tokens.add(env)

        years = ["2026", "2025", "2024"]
        permutations = []

        for tok in list(tokens):
            if not tok or len(tok) < 2:
                continue
            # Archive & Backups
            permutations.extend([
                f"{tok}.zip", f"{tok}.tar.gz", f"{tok}.tgz", f"{tok}.bak", f"{tok}.old",
                f"{tok}_backup.zip", f"{tok}-backup.zip", f"backup_{tok}.zip", f"backup-{tok}.zip",
                f"backup_{tok}.tar.gz", f"{tok}_db.sql", f"{tok}_dump.sql", f"{tok}.sql",
                f"dump_{tok}.sql", f"db_{tok}.sql", f"backup_{tok}.sql"
            ])
            for yr in years:
                permutations.extend([
                    f"{tok}_{yr}.zip", f"{tok}_{yr}.sql", f"backup_{tok}_{yr}.zip", f"dump_{tok}_{yr}.sql"
                ])

            # Configs & Environment
            permutations.extend([
                f"{tok}.env", f".env.{tok}", f"appsettings.{tok}.json",
                f"config.{tok}.json", f"config.{tok}.php", f"configuration.{tok}.php",
                f"settings_{tok}.py", f"parameters_{tok}.yml", f"database_{tok}.yml"
            ])

            # Certificates & Keys
            permutations.extend([
                f"{tok}.key", f"{tok}.pem", f"{tok}.crt", f"{tok}.pfx", f"{tok}.p12"
            ])

        return list(dict.fromkeys(permutations))

    def build_smart_file_wordlist_for_dir(self, d_clean: str = "", tech_stack: list = None, target: str = "", root_domain: str = "") -> str:
        """
        Builds a smart file discovery wordlist for a directory combining:
        1. Curated universal high-impact sensitive files (.env, .git/HEAD, backups, etc.)
        2. Technology-specific wordlists based on detected tech_stack (PHP, ASP.NET, Java/Spring, Node.js, Python)
        3. Contextual brand, environment, and domain permutations for target
        4. Fallback probes for unverified technologies to discover backend stack quickly
        5. Contextual directory-based filenames
        6. Filtered SecLists raft small files
        Writes to a temporary file and returns file path for ffuf.
        """
        words = list(CURATED_SENSITIVE_FILES)
        base_label = d_clean.split("/")[-1].lower() if d_clean else ""

        # Contextual filenames matching directory name
        if base_label:
            words.extend([
                f"{base_label}.php", f"{base_label}.aspx", f"{base_label}.jsp",
                f"{base_label}.html", f"{base_label}.json", f"{base_label}.js",
                f"{base_label}.bak", f"{base_label}.zip", f"{base_label}.sql",
                f"{base_label}.txt", f"{base_label}.xml"
            ])

        # Target-aware contextual permutations (on root or level-1 directories)
        if target and (not d_clean or len(d_clean.split("/")) <= 1):
            words.extend(self.generate_contextual_permutations(target, root_domain))

        tech_str = " ".join(str(t).lower() for t in (tech_stack or []))

        is_php = any(x in tech_str for x in ["php", "wordpress", "laravel", "drupal", "joomla", "symfony"])
        is_asp = any(x in tech_str for x in ["asp", "iis", "windows", ".net", "c#"])
        is_java = any(x in tech_str for x in ["java", "spring", "tomcat", "jboss", "weblogic", "websphere", "struts"])
        is_node = any(x in tech_str for x in ["node", "express", "next", "nuxt", "koa", "sails"])
        is_python = any(x in tech_str for x in ["python", "django", "flask", "fastapi", "tornado", "py"])
        is_ruby = any(x in tech_str for x in ["ruby", "rails", "sinatra"])

        # 1. PHP Smart Wordlist
        if is_php:
            php_wl = self.get_tech_file_wordlist("php")
            if php_wl:
                words.extend(php_wl)
            else:
                words.extend([
                    "wp-config.php", "wp-config.php.bak", "wp-config.php~", "wp-login.php", "xmlrpc.php",
                    "phpinfo.php", "info.php", "test.php", "config.php", "config.inc.php", "db.php",
                    "connect.php", "admin.php", "login.php", "upload.php", "functions.php", "composer.json",
                    "composer.lock", ".env", "artisan", "index.php", "api.php", "setup.php", "install.php"
                ])
            # Add .php variants for contextual directory
            if base_label:
                words.extend([f"{base_label}.php.bak", f"{base_label}.php~", f"{base_label}.phtml"])

        # 2. ASP.NET / IIS Smart Wordlist
        if is_asp:
            asp_wl = self.get_tech_file_wordlist("asp")
            if asp_wl:
                words.extend(asp_wl)
            else:
                words.extend([
                    "web.config", "web.config.bak", "web.config.old", "global.asax", "global.asax.bak",
                    "default.aspx", "default.asp", "index.aspx", "index.asp", "login.aspx", "admin.aspx",
                    "trace.axd", "elmah.axd", "WebResource.axd", "appsettings.json", "appsettings.Development.json"
                ])

        # 3. Java / Spring Boot Smart Wordlist
        if is_java:
            java_wl = self.get_tech_file_wordlist("java")
            if java_wl:
                words.extend(java_wl)
            else:
                words.extend([
                    "actuator", "actuator/health", "actuator/env", "actuator/mappings", "actuator/beans",
                    "actuator/info", "actuator/metrics", "actuator/threaddump", "actuator/heapdump",
                    "application.properties", "application.yml", "pom.xml", "WEB-INF/web.xml",
                    "META-INF/MANIFEST.MF", "manager/html", "index.jsp", "login.jsp", "admin.jsp"
                ])

        # 4. Node.js Smart Wordlist
        if is_node:
            node_wl = self.get_tech_file_wordlist("node")
            if node_wl:
                words.extend(node_wl)
            else:
                words.extend([
                    "package.json", "package-lock.json", ".npmrc", "server.js", "app.js", "index.js",
                    "next.config.js", "next.config.mjs", "ecosystem.config.js", "tsconfig.json", ".env.local"
                ])

        # 5. Python Smart Wordlist
        if is_python:
            py_wl = self.get_tech_file_wordlist("python")
            if py_wl:
                words.extend(py_wl)
            else:
                words.extend([
                    "settings.py", "local_settings.py", "wsgi.py", "asgi.py", "requirements.txt",
                    "Pipfile", "pyproject.toml", "manage.py", "app.py", "main.py", ".env"
                ])

        # 6. Ruby on Rails
        if is_ruby:
            words.extend(["Gemfile", "Gemfile.lock", "config/database.yml", "config/routes.rb", "Rakefile"])

        # 7. Unverified Technology Probes: if no backend stack is known, include key probes across all stacks
        if not (is_php or is_asp or is_java or is_node or is_python or is_ruby):
            words.extend([
                "index.php", "test.php", "info.php", "phpinfo.php", "wp-login.php", "config.php", "admin.php",
                "default.aspx", "index.aspx", "web.config", "trace.axd", "login.aspx",
                "index.jsp", "actuator/health", "actuator/env", "application.properties", "WEB-INF/web.xml",
                "package.json", "server.js", "next.config.js",
                "requirements.txt", "wsgi.py", "settings.py"
            ])

        # 8. Raft small files integration
        raft_wl = self.get_file_wordlist()
        if raft_wl and os.path.exists(raft_wl):
            try:
                with open(raft_wl, "r", encoding="utf-8", errors="ignore") as rf:
                    count = 0
                    for line in rf:
                        line = line.strip().lstrip("/")
                        if line and not line.startswith("#"):
                            # Filter based on technology if identified
                            if is_php and (line.endswith(".asp") or line.endswith(".aspx") or line.endswith(".jsp")):
                                continue
                            if is_asp and (line.endswith(".php") or line.endswith(".jsp")):
                                continue
                            if is_java and (line.endswith(".php") or line.endswith(".asp") or line.endswith(".aspx")):
                                continue
                            words.append(line)
                            count += 1
                            if count >= 1500:
                                break
            except Exception as e:
                logger.debug(f"Error reading raft files: {e}")

        # Deduplicate preserving order
        deduped = list(dict.fromkeys(words))
        wl_path = f"/tmp/smart_file_wl_{os.getpid()}_{base_label or 'root'}.txt"
        try:
            with open(wl_path, "w", encoding="utf-8") as f:
                f.write("\n".join(deduped) + "\n")
            return wl_path
        except Exception as e:
            logger.debug(f"Error writing smart file wordlist: {e}")
            return self.get_file_wordlist() or FILE_WORDLIST

    def build_file_wordlist_for_dir(self, d_clean: str = "", tech_stack: list = None, include_raft: bool = True) -> str:
        return self.build_smart_file_wordlist_for_dir(d_clean=d_clean, tech_stack=tech_stack)

    def build_curated_wordlist_for_dir(self, d_clean: str = "", tech_stack: list = None) -> str:
        return self.build_smart_file_wordlist_for_dir(d_clean=d_clean, tech_stack=tech_stack)

    async def fetch_robots_and_sitemaps(self, base_url: str, target: str):
        """
        Discovers, fetches, and parses robots.txt and sitemap.xml files.
        Extracts paths from Disallow/Allow/Sitemap directives in robots.txt
        and <loc> elements in sitemap.xml files.
        Concurrently probes discovered paths to obtain their actual HTTP status and lengths.
        Returns a dict with extracted items, discovered directories, and stats.
        """
        logger.info(f"Phase 0: Checking robots.txt and sitemaps for {base_url}")
        items = []
        discovered_dirs = set()
        robots_paths = set()
        sitemap_paths = set()
        candidate_sitemaps = set()

        headers = {
            "User-Agent": self.user_agent
        }

        robots_meta = {"present": False, "paths_extracted": 0, "sitemaps_declared": 0}
        sitemap_meta = {"present": False, "paths_extracted": 0, "sitemaps_parsed": 0}

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True, headers=headers) as client:
            # 1. Fetch & parse robots.txt
            robots_url = f"{base_url.rstrip('/')}/robots.txt"
            try:
                r_resp = await client.get(robots_url)
                if r_resp.status_code == 200 and r_resp.content:
                    body_text = r_resp.text
                    has_robots_keywords = bool(re.search(r'(user-agent|disallow|allow|sitemap):', body_text, re.I))
                    is_html = "<!doctype html" in body_text.lower() or ("<html" in body_text.lower() and "<body" in body_text.lower())

                    if has_robots_keywords or not is_html:
                        robots_meta["present"] = True
                        items.append({
                            "path": "robots.txt",
                            "directory": "",
                            "status": 200,
                            "length": len(r_resp.content),
                            "source": "robots.txt",
                            "words": len(body_text.split())
                        })

                        for raw_line in body_text.splitlines():
                            line = raw_line.split("#")[0].strip()
                            if not line:
                                continue

                            # Check Disallow / Allow directives
                            match_dir = re.match(r'^(disallow|allow):\s*(.+)$', line, re.I)
                            if match_dir:
                                p = match_dir.group(2).strip()
                                p = p.rstrip("$").rstrip("*").strip()
                                p = p.split("?")[0].strip()
                                p = p.lstrip("/")
                                if p and p != "/":
                                    robots_paths.add(p)
                                    dir_part = p.rstrip("/").rsplit("/", 1)[0] if "/" in p.rstrip("/") else (p if p.endswith("/") else "")
                                    if dir_part:
                                        discovered_dirs.add(dir_part.strip("/"))

                            # Check Sitemap directive
                            match_sm = re.match(r'^sitemap:\s*(.+)$', line, re.I)
                            if match_sm:
                                sm = match_sm.group(1).strip()
                                if sm.startswith("http://") or sm.startswith("https://"):
                                    candidate_sitemaps.add(sm)
                                elif sm.startswith("/"):
                                    candidate_sitemaps.add(f"{base_url.rstrip('/')}{sm}")

                        robots_meta["paths_extracted"] = len(robots_paths)
                        robots_meta["sitemaps_declared"] = len(candidate_sitemaps)
                        logger.info(f"robots.txt parsed: {len(robots_paths)} paths, {len(candidate_sitemaps)} sitemaps declared")
            except Exception as e:
                logger.debug(f"robots.txt fetch error on {base_url}: {e}")

            # 2. Add default sitemap candidate locations
            candidate_sitemaps.add(f"{base_url.rstrip('/')}/sitemap.xml")
            candidate_sitemaps.add(f"{base_url.rstrip('/')}/sitemap_index.xml")
            candidate_sitemaps.add(f"{base_url.rstrip('/')}/sitemap.txt")

            # 3. Fetch & parse sitemaps (limit to at most 6 sitemaps)
            processed_sitemaps = set()
            sitemaps_queue = list(candidate_sitemaps)[:6]

            while sitemaps_queue and len(processed_sitemaps) < 6:
                sm_url = sitemaps_queue.pop(0)
                if sm_url in processed_sitemaps:
                    continue
                processed_sitemaps.add(sm_url)

                try:
                    sm_resp = await client.get(sm_url)
                    if sm_resp.status_code == 200 and sm_resp.content:
                        sm_text = sm_resp.text
                        is_xml = ("<urlset" in sm_text) or ("<sitemapindex" in sm_text) or ("<loc>" in sm_text)
                        is_txt = sm_url.endswith(".txt") and bool(re.search(r'https?://[^\s]+', sm_text))

                        if is_xml or is_txt:
                            sitemap_meta["present"] = True
                            sitemap_meta["sitemaps_parsed"] += 1

                            rel_sm = sm_url.replace(base_url, "").lstrip("/") if base_url in sm_url else sm_url.split("/")[-1]
                            items.append({
                                "path": rel_sm,
                                "directory": "",
                                "status": 200,
                                "length": len(sm_resp.content),
                                "source": "sitemap.xml",
                                "words": len(sm_text.split())
                            })

                            target_host = (target.split(":")[0]).lower()

                            if is_xml:
                                locs = re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', sm_text, re.I)
                                for loc in locs:
                                    loc_clean = loc.strip()
                                    if loc_clean.lower().endswith(".xml") or "sitemap" in loc_clean.lower():
                                        if loc_clean not in processed_sitemaps and len(sitemaps_queue) < 6:
                                            sitemaps_queue.append(loc_clean)
                                    else:
                                        try:
                                            parsed = urllib.parse.urlparse(loc_clean)
                                            parsed_host = (parsed.hostname or "").lower()
                                            if not parsed_host or parsed_host == target_host or parsed_host.endswith(f".{target_host}"):
                                                p = parsed.path.lstrip("/")
                                                if p:
                                                    sitemap_paths.add(p)
                                                    if "/" in p:
                                                        discovered_dirs.add(p.rsplit("/", 1)[0].strip("/"))
                                        except Exception:
                                            pass
                            elif is_txt:
                                for line in sm_text.splitlines():
                                    line = line.strip()
                                    if line.startswith("http://") or line.startswith("https://") or line.startswith("/"):
                                        try:
                                            parsed = urllib.parse.urlparse(line)
                                            parsed_host = (parsed.hostname or "").lower()
                                            if not parsed_host or parsed_host == target_host or parsed_host.endswith(f".{target_host}"):
                                                p = parsed.path.lstrip("/")
                                                if p:
                                                    sitemap_paths.add(p)
                                                    if "/" in p:
                                                        discovered_dirs.add(p.rsplit("/", 1)[0].strip("/"))
                                        except Exception:
                                            pass
                except Exception as e:
                    logger.debug(f"Sitemap fetch error on {sm_url}: {e}")

            sitemap_meta["paths_extracted"] = len(sitemap_paths)
            logger.info(f"Sitemaps parsed: {sitemap_meta['sitemaps_parsed']} sitemap(s), {len(sitemap_paths)} total page path(s)")

            # 3.5 Fetch & parse security.txt (RFC 9116 /.well-known/security.txt and legacy /security.txt)
            security_meta = {"present": False, "url": None, "contacts": [], "policies": []}
            security_paths = set()
            sec_urls = [
                f"{base_url.rstrip('/')}/.well-known/security.txt",
                f"{base_url.rstrip('/')}/security.txt"
            ]
            for sec_url in sec_urls:
                try:
                    sec_resp = await client.get(sec_url)
                    if sec_resp.status_code == 200 and sec_resp.content:
                        sec_text = sec_resp.text
                        has_sec_keywords = bool(re.search(r'(contact|policy|encryption|acknowledgments|canonical):', sec_text, re.I))
                        is_html = "<!doctype html" in sec_text.lower() or ("<html" in sec_text.lower() and "<body" in sec_text.lower())
                        if has_sec_keywords or not is_html:
                            security_meta["present"] = True
                            security_meta["url"] = sec_url
                            rel_sec = ".well-known/security.txt" if "/.well-known/" in sec_url else "security.txt"
                            dir_sec = ".well-known" if "/.well-known/" in sec_url else ""
                            if dir_sec:
                                discovered_dirs.add(dir_sec)

                            items.append({
                                "path": rel_sec,
                                "directory": dir_sec,
                                "status": 200,
                                "length": len(sec_resp.content),
                                "source": "security.txt",
                                "words": len(sec_text.split())
                            })

                            # Parse directives and extract local policy/contact URLs
                            for sline in sec_text.splitlines():
                                sline = sline.strip()
                                match_field = re.match(r'^(contact|policy|acknowledgments|hiring|canonical):\s*(.+)$', sline, re.I)
                                if match_field:
                                    field_name, field_val = match_field.groups()
                                    field_val = field_val.strip()
                                    if field_name.lower() == "contact":
                                        security_meta["contacts"].append(field_val)
                                    elif field_name.lower() == "policy":
                                        security_meta["policies"].append(field_val)

                                    if field_val.startswith("http://") or field_val.startswith("https://") or field_val.startswith("/"):
                                        try:
                                            p_parsed = urllib.parse.urlparse(field_val)
                                            p_host = (p_parsed.hostname or "").lower()
                                            t_host = (target.split(":")[0]).lower()
                                            if not p_host or p_host == t_host or p_host.endswith(f".{t_host}"):
                                                clean_sec_path = p_parsed.path.lstrip("/")
                                                if clean_sec_path and clean_sec_path not in robots_paths and clean_sec_path not in sitemap_paths and clean_sec_path not in security_paths:
                                                    security_paths.add(clean_sec_path)
                                                    if "/" in clean_sec_path:
                                                        discovered_dirs.add(clean_sec_path.rsplit("/", 1)[0].strip("/"))
                                        except Exception:
                                            pass

                            logger.info(f"security.txt discovered at {sec_url}")
                            if "/.well-known/" in sec_url:
                                break
                except Exception as e:
                    logger.debug(f"security.txt fetch error on {sec_url}: {e}")

            # 4. Probing discovered paths
            paths_to_probe = []
            for p in sorted(list(robots_paths)):
                paths_to_probe.append((p, "robots.txt"))
            for p in sorted(list(sitemap_paths)):
                if p not in robots_paths:
                    paths_to_probe.append((p, "sitemap.xml"))
            for p in sorted(list(security_paths)):
                if p not in robots_paths and p not in sitemap_paths:
                    paths_to_probe.append((p, "security.txt"))

            paths_to_probe = paths_to_probe[:150]
            logger.info(f"Probing {len(paths_to_probe)} paths extracted from robots.txt, sitemaps, and security.txt...")

            sem = asyncio.Semaphore(15)

            async def probe_one(p_tuple):
                path_str, src = p_tuple
                probe_url = f"{base_url.rstrip('/')}/{path_str}"
                status = 200
                length = 0
                async with sem:
                    try:
                        r = await client.head(probe_url, timeout=5.0, follow_redirects=True)
                        if r.status_code == 405:
                            r = await client.get(probe_url, timeout=5.0, follow_redirects=True)
                        status = r.status_code
                        length = int(r.headers.get("content-length") or len(r.content or b""))
                    except Exception:
                        status = 200
                        length = 0

                dir_part = path_str.rstrip("/").rsplit("/", 1)[0] if "/" in path_str.rstrip("/") else ""
                return {
                    "path": path_str,
                    "directory": dir_part,
                    "status": status,
                    "length": length,
                    "source": src
                }

            if paths_to_probe:
                probed_results = await asyncio.gather(*[probe_one(pt) for pt in paths_to_probe], return_exceptions=True)
                for pr in probed_results:
                    if isinstance(pr, dict):
                        items.append(pr)

        return {
            "items": items,
            "discovered_dirs": discovered_dirs,
            "robots_txt": robots_meta,
            "sitemap": sitemap_meta,
            "security_txt": security_meta
        }

    async def fetch_favicon_fingerprint(self, base_url: str, target: str, root_domain: str):
        """
        Downloads /favicon.ico (or icon referenced in HTML <link rel='icon'>),
        calculates MurmurHash3 (Shodan standard: mmh3.hash(codecs.encode(favicon, 'base64'))),
        MD5, SHA-256, and generates search engine pivot queries (Shodan, Censys, ZoomEye).
        """
        logger.info(f"Phase 0.5: Probing favicon and computing asset hash fingerprints for {base_url}")
        headers = {
            "User-Agent": self.user_agent
        }
        candidate_urls = [f"{base_url.rstrip('/')}/favicon.ico"]

        favicon_bytes = None
        final_favicon_url = None
        content_type = "image/x-icon"

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True, headers=headers) as client:
            # 1. Probe direct /favicon.ico
            try:
                resp = await client.get(candidate_urls[0])
                if resp.status_code == 200 and resp.content and len(resp.content) >= 16:
                    raw = resp.content.strip()
                    # Verify it's not a custom HTML 404
                    if not (raw.lower().startswith(b"<!doctype html") or raw.lower().startswith(b"<html")):
                        favicon_bytes = resp.content
                        final_favicon_url = str(resp.url)
                        content_type = resp.headers.get("content-type", "image/x-icon")
            except Exception as e:
                logger.debug(f"Direct favicon.ico probe failed on {base_url}: {e}")

            # 2. If direct favicon failed or was HTML, inspect root HTML for <link rel="icon">
            if not favicon_bytes:
                try:
                    home_resp = await client.get(base_url.rstrip("/") + "/")
                    if home_resp.status_code == 200 and home_resp.text:
                        html = home_resp.text
                        matches = re.findall(
                            r'<link\b[^>]*\brel=["\'](?:shortcut\s+)?icon["\'][^>]*\bhref=["\']([^"\']+)["\']',
                            html,
                            re.IGNORECASE
                        )
                        if not matches:
                            matches = re.findall(
                                r'<link\b[^>]*\bhref=["\']([^"\']+)["\'][^>]*\brel=["\'](?:shortcut\s+)?icon["\']',
                                html,
                                re.IGNORECASE
                            )
                        if matches:
                            icon_href = matches[0].strip()
                            resolved_url = urllib.parse.urljoin(base_url, icon_href)
                            logger.info(f"Discovered custom favicon link in HTML: {resolved_url}")
                            icon_resp = await client.get(resolved_url)
                            if icon_resp.status_code == 200 and icon_resp.content and len(icon_resp.content) >= 16:
                                raw = icon_resp.content.strip()
                                if not (raw.lower().startswith(b"<!doctype html") or raw.lower().startswith(b"<html")):
                                    favicon_bytes = icon_resp.content
                                    final_favicon_url = str(icon_resp.url)
                                    content_type = icon_resp.headers.get("content-type", "image/x-icon")
                except Exception as e:
                    logger.debug(f"HTML favicon parsing failed on {base_url}: {e}")

        if not favicon_bytes:
            logger.info(f"No valid favicon discovered for {base_url}")
            return None

        # Calculate hashes
        md5_hash = hashlib.md5(favicon_bytes).hexdigest()
        sha256_hash = hashlib.sha256(favicon_bytes).hexdigest()
        
        # Standard Shodan MurmurHash3 calculation:
        # Shodan encodes raw bytes into base64 with newlines every 76 characters (codecs.encode)
        shodan_hash = None
        if mmh3 is not None:
            try:
                b64_encoded = codecs.encode(favicon_bytes, 'base64')
                shodan_hash = int(mmh3.hash(b64_encoded))
            except Exception as e:
                logger.error(f"MurmurHash3 computation error: {e}")
        if shodan_hash is None:
            try:
                b64_encoded = codecs.encode(favicon_bytes, 'base64')
                shodan_hash = mmh3_hash32(b64_encoded)
            except Exception as e:
                logger.error(f"Fallback MurmurHash3 computation error: {e}")

        matched_framework = FAVICON_FRAMEWORKS.get(shodan_hash) or FAVICON_MD5_FRAMEWORKS.get(md5_hash)

        shodan_query = f"http.favicon.hash:{shodan_hash}" if shodan_hash is not None else None
        censys_query = f'services.http.response.favicons.md5_hash:"{md5_hash}"'
        zoomeye_query = f'iconhash:"{shodan_hash}"' if shodan_hash is not None else None

        favicon_info = {
            "url": final_favicon_url,
            "mmh3": shodan_hash,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "size": len(favicon_bytes),
            "content_type": content_type,
            "framework": matched_framework,
            "shodan_query": shodan_query,
            "censys_query": censys_query,
            "zoomeye_query": zoomeye_query
        }

        # Check for configured Shodan API key in settings or environment
        shodan_api_key = None
        try:
            settings_doc = await self.settings_col.find_one({"key": "global_settings"})
            if settings_doc:
                shodan_api_key = settings_doc.get("api_keys", {}).get("shodan_api_key")
        except Exception as e:
            logger.debug(f"Error reading Shodan API key: {e}")
        
        if not shodan_api_key:
            shodan_api_key = os.environ.get("SHODAN_API_KEY")

        shodan_live = None
        if shodan_api_key and shodan_hash is not None:
            logger.info(f"Querying Shodan API for favicon MurmurHash3: {shodan_hash}")
            shodan_live = await self.query_shodan_favicon_hash(shodan_hash, shodan_api_key)
            if shodan_live and "total" in shodan_live:
                favicon_info["shodan_live"] = shodan_live

        # Create alert/lead
        try:
            hash_display = f"MurmurHash3 {shodan_hash}" if shodan_hash is not None else f"MD5 {md5_hash[:12]}"
            details = (
                f"Target: {target}\n"
                f"Asset URL: {final_favicon_url}\n"
                f"MurmurHash3 (Shodan): {shodan_hash}\n"
                f"MD5 Hash: {md5_hash}\n"
                f"SHA256 Hash: {sha256_hash}\n"
                f"Size: {len(favicon_bytes)} bytes\n"
            )
            if matched_framework:
                details += f"Identified Framework: **{matched_framework}**\n"
            details += (
                f"\nSearch Engine Pivot Queries:\n"
                f"- Shodan Query: `{shodan_query}`\n"
                f"- Censys Query: `{censys_query}`\n"
                f"- ZoomEye Query: `{zoomeye_query}`"
            )

            if shodan_live and shodan_live.get("total", 0) > 0:
                total_shodan = shodan_live["total"]
                ips_sample = ", ".join(shodan_live["ips"][:5])
                title = f"Favicon Origin Discovery via Shodan: {total_shodan} Host(s) (MMH3 {shodan_hash})"
                description = (
                    f"Favicon search on Shodan uncovered {total_shodan} Internet-facing host(s) sharing this hash. "
                    f"Sample IPs: {ips_sample}"
                )
                if matched_framework:
                    description += f" [Identified: {matched_framework}]"
                risk_level = "high" if len(shodan_live["ips"]) > 0 else "medium"

                shodan_section = (
                    f"\n\n### Shodan Live Reconnaissance Discovery\n"
                    f"- **Total Matching Hosts**: `{total_shodan}`\n"
                    f"- **Discovered IPs**: {', '.join(shodan_live['ips'][:15]) or 'None'}\n"
                    f"- **Discovered Hostnames**: {', '.join(shodan_live['hostnames'][:10]) or 'None'}\n"
                )
                if shodan_live.get("sample_results"):
                    shodan_section += "\n#### Sample Matched Infrastructure:\n"
                    for sm in shodan_live["sample_results"][:4]:
                        shodan_section += f"- `{sm['ip']}:{sm['port']}` ({sm['org']}, {sm['country']}) - Hosts: {', '.join(sm['hostnames']) or 'N/A'}\n"

                details += shodan_section
                exploitation = (
                    f"### Direct Origin Bypassing Guidance\n\n"
                    f"1. **Direct IP Access**: Test direct HTTP/HTTPS connections to discovered IPs (`curl -k -H 'Host: {target}' https://<ip>`). If the backend server responds directly, Cloudflare/Akamai WAFs and DDoS shields can be bypassed completely.\n"
                    f"2. **Host Correlation**: Check discovered hostnames for forgotten staging or development environments.\n"
                    f"3. **Shodan Pivot**: View full query results at [http.favicon.hash:{shodan_hash}](https://www.shodan.io/search?query=http.favicon.hash:{shodan_hash})."
                )
            else:
                title = f"Favicon Framework Match: {matched_framework}" if matched_framework else f"Favicon Asset Fingerprint: {hash_display}"
                description = (
                    f"Favicon identified as {matched_framework} on {target} ({len(favicon_bytes)}B). MMH3: {shodan_hash}" if matched_framework else
                    f"Favicon asset fingerprinted on {target} ({len(favicon_bytes)}B). Shodan: {shodan_query or 'N/A'}, Censys MD5: {md5_hash}"
                )
                risk_level = "low"
                exploitation = (
                    f"### Asset Pivoting & Origin Uncloaking Guidance\n\n"
                    f"1. **Shodan Pivot**: Search [{shodan_query}](https://www.shodan.io/search?query=http.favicon.hash:{shodan_hash}) to discover origin IP addresses, staging subdomains, or forgotten subsidiary servers hosting the identical favicon.\n"
                    f"2. **Censys Pivot**: Search Censys for [{censys_query}](https://search.censys.io/search?q=services.http.response.favicons.md5_hash:\"{md5_hash}\") to find associated certificates and open cloud assets.\n"
                    f"3. **Host Context**: Discovered on `{target}` ({root_domain})."
                )

            await self.create_alert(
                title=title,
                description=description,
                target=target,
                risk_level=risk_level,
                details=details,
                exploitation_suggestions=exploitation,
                response_size=len(favicon_bytes),
                extra_key=str(shodan_hash or md5_hash),
                alert_type="favicon_fingerprint"
            )
        except Exception as e:
            logger.debug(f"Error creating favicon alert: {e}")

        logger.info(f"Favicon fingerprinted on {target}: Shodan MMH3={shodan_hash}, MD5={md5_hash}, Framework={matched_framework}")
        return favicon_info

    async def query_shodan_favicon_hash(self, shodan_hash: int, api_key: str) -> dict:
        """
        Query Shodan API using the MurmurHash3 favicon hash to find all Internet-connected
        origin IP addresses, hostnames, and exposed ports sharing this identical icon.
        """
        if not shodan_hash or not api_key:
            return None
        
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=http.favicon.hash:{shodan_hash}"
        try:
            cmd = ["curl", "-s", "-m", "15", "-A", self.user_agent, url]
            stdout, stderr = await self.run_command(cmd, timeout=20)
            if not stdout:
                return None
            data = json.loads(stdout)
            if "error" in data:
                logger.warning(f"Shodan API error for favicon hash {shodan_hash}: {data.get('error')}")
                return {"error": data.get("error")}
            
            total = data.get("total", 0)
            matches = data.get("matches", [])
            
            discovered_ips = []
            discovered_hosts = set()
            sample_results = []

            for m in matches:
                ip = m.get("ip_str")
                if ip and ip not in discovered_ips:
                    discovered_ips.append(ip)
                for h in m.get("hostnames", []):
                    if h:
                        discovered_hosts.add(h)
                
                if len(sample_results) < 8:
                    sample_results.append({
                        "ip": ip,
                        "port": m.get("port"),
                        "hostnames": m.get("hostnames", []),
                        "org": m.get("org", ""),
                        "country": m.get("location", {}).get("country_name", ""),
                        "product": m.get("product", "")
                    })

            return {
                "total": total,
                "ips": discovered_ips[:25],
                "hostnames": sorted(list(discovered_hosts))[:25],
                "sample_results": sample_results
            }
        except Exception as e:
            logger.error(f"Error querying Shodan API for favicon {shodan_hash}: {e}")
            return None

    async def harvest_well_known_profiles(self, base_url: str, target: str, root_domain: str):
        """
        Harvests enterprise & mobile metadata hosted under /.well-known/:
        1. /.well-known/assetlinks.json: Android package names & SHA256 fingerprints.
        2. /.well-known/apple-app-site-association: iOS App IDs & deep-linking routes.
        3. /.well-known/openid-configuration: Identity provider endpoints & public keys.
        """
        logger.info(f"Phase 0.5: Harvesting enterprise & mobile .well-known configurations on {base_url}")
        headers = {
            "User-Agent": self.user_agent
        }

        discovered_items = []
        discovered_dirs = set()
        extracted_paths = set()

        assetlinks_data = {"present": False, "packages": [], "fingerprints": []}
        aasa_data = {"present": False, "app_ids": [], "paths": [], "webcredentials": []}
        openid_data = {"present": False, "issuer": None, "authorization_endpoint": None, "token_endpoint": None, "userinfo_endpoint": None, "jwks_uri": None, "registration_endpoint": None, "scopes": []}

        endpoints = [
            ("assetlinks", f"{base_url.rstrip('/')}/.well-known/assetlinks.json", ".well-known/assetlinks.json"),
            ("aasa_well_known", f"{base_url.rstrip('/')}/.well-known/apple-app-site-association", ".well-known/apple-app-site-association"),
            ("aasa_root", f"{base_url.rstrip('/')}/apple-app-site-association", "apple-app-site-association"),
            ("openid", f"{base_url.rstrip('/')}/.well-known/openid-configuration", ".well-known/openid-configuration"),
            ("oauth_server", f"{base_url.rstrip('/')}/.well-known/oauth-authorization-server", ".well-known/oauth-authorization-server")
        ]

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True, headers=headers) as client:
            for ep_type, ep_url, rel_path in endpoints:
                try:
                    resp = await client.get(ep_url)
                    if resp.status_code == 200 and resp.content and len(resp.content) > 10:
                        body_text = resp.text.strip()
                        # Avoid HTML false positives
                        if body_text.startswith("<") or "<html" in body_text.lower():
                            continue

                        discovered_items.append({
                            "path": rel_path,
                            "directory": ".well-known" if rel_path.startswith(".well-known") else "",
                            "status": 200,
                            "length": len(resp.content),
                            "source": "well-known",
                            "words": len(body_text.split())
                        })
                        if rel_path.startswith(".well-known"):
                            discovered_dirs.add(".well-known")

                        # Parse JSON payload
                        try:
                            json_obj = json.loads(body_text)
                        except Exception:
                            match_json = re.search(r'(\{[\s\S]*\})', body_text)
                            if match_json:
                                try:
                                    json_obj = json.loads(match_json.group(1))
                                except Exception:
                                    json_obj = None
                            else:
                                json_obj = None

                        if not json_obj:
                            continue

                        # 1. Parse assetlinks.json
                        if ep_type == "assetlinks" and isinstance(json_obj, list):
                            assetlinks_data["present"] = True
                            for stmt in json_obj:
                                if not isinstance(stmt, dict):
                                    continue
                                target_spec = stmt.get("target", {})
                                pkg = target_spec.get("package_name")
                                if pkg and pkg not in assetlinks_data["packages"]:
                                    assetlinks_data["packages"].append(pkg)
                                for fp in target_spec.get("sha256_cert_fingerprints", []):
                                    if fp not in assetlinks_data["fingerprints"]:
                                        assetlinks_data["fingerprints"].append(fp)

                            if assetlinks_data["packages"]:
                                internal_pkgs = [p for p in assetlinks_data["packages"] if any(k in p.lower() for k in ["beta", "stage", "staging", "dev", "internal", "test", "debug", "qa"])]
                                if internal_pkgs:
                                    title = f"Internal/Pre-Release Android Package Exposed: {internal_pkgs[0]}"
                                    risk = "medium"
                                    alert_type = "well_known_internal_app"
                                else:
                                    title = f"Android App Asset Links Discovered: {target}"
                                    risk = "low"
                                    alert_type = "well_known_mobile_apps"

                                details = (
                                    f"URL: {ep_url}\n"
                                    f"Android Packages Discovered:\n" + "\n".join(f"- `{p}`" for p in assetlinks_data["packages"]) + "\n\n"
                                    f"Certificate Fingerprints:\n" + "\n".join(f"- `{f}`" for f in assetlinks_data["fingerprints"][:5])
                                )
                                exploitation = (
                                    f"### Mobile App Association Analysis\n\n"
                                    f"1. **Analyze Application ID**: Query Google Play Store or APK repositories for package IDs: `{', '.join(assetlinks_data['packages'][:3])}`.\n"
                                    f"2. **Decompile Mobile Client**: Extract mobile client APK to find embedded API keys, secret headers, and internal backend gateways.\n"
                                    f"3. **Domain Ownership**: Confirms explicit deep-linking trust delegation from `{target}` to mobile app."
                                )
                                await self.create_alert(
                                    title=title,
                                    description=f"Android digital assetlinks discovered on {target}: {len(assetlinks_data['packages'])} package(s)",
                                    target=target,
                                    risk_level=risk,
                                    details=details,
                                    exploitation_suggestions=exploitation,
                                    response_size=len(resp.content),
                                    extra_key=f"assetlinks_{target}",
                                    alert_type=alert_type
                                )

                        # 2. Parse Apple App Site Association
                        elif ep_type in ("aasa_well_known", "aasa_root") and isinstance(json_obj, dict):
                            aasa_data["present"] = True
                            applinks = json_obj.get("applinks", {})
                            details_list = applinks.get("details", [])
                            if isinstance(details_list, dict):
                                details_list = [details_list]

                            for d in details_list:
                                if not isinstance(d, dict):
                                    continue
                                app_id = d.get("appID")
                                if app_id and app_id not in aasa_data["app_ids"]:
                                    aasa_data["app_ids"].append(app_id)
                                for aid in d.get("appIDs", []):
                                    if aid not in aasa_data["app_ids"]:
                                        aasa_data["app_ids"].append(aid)

                                # Extract deep linking paths
                                for p in d.get("paths", []):
                                    if isinstance(p, str):
                                        clean_p = p.strip().lstrip("/").rstrip("*").rstrip("/")
                                        if clean_p and clean_p not in aasa_data["paths"]:
                                            aasa_data["paths"].append(clean_p)
                                            extracted_paths.add(clean_p)
                                            dir_part = clean_p.rsplit("/", 1)[0] if "/" in clean_p else clean_p
                                            if dir_part:
                                                discovered_dirs.add(dir_part)

                                # Components (AASA modern format)
                                for comp in d.get("components", []):
                                    if isinstance(comp, dict) and "/" in comp:
                                        cp = str(comp["/"]).strip().lstrip("/").rstrip("*").rstrip("/")
                                        if cp and cp not in aasa_data["paths"]:
                                            aasa_data["paths"].append(cp)
                                            extracted_paths.add(cp)
                                            dir_part = cp.rsplit("/", 1)[0] if "/" in cp else cp
                                            if dir_part:
                                                discovered_dirs.add(dir_part)

                            # Webcredentials
                            webcred = json_obj.get("webcredentials", {})
                            for wa in webcred.get("apps", []):
                                if wa not in aasa_data["app_ids"]:
                                    aasa_data["app_ids"].append(wa)

                            if aasa_data["app_ids"] and not aasa_data.get("_alerted"):
                                aasa_data["_alerted"] = True
                                internal_aids = [a for a in aasa_data["app_ids"] if any(k in a.lower() for k in ["beta", "stage", "staging", "dev", "internal", "test", "debug"])]
                                if internal_aids:
                                    title = f"Internal/Pre-Release iOS App ID Exposed: {internal_aids[0]}"
                                    risk = "medium"
                                    alert_type = "well_known_internal_app"
                                else:
                                    title = f"Apple Universal Links Association Discovered: {target}"
                                    risk = "low"
                                    alert_type = "well_known_mobile_apps"

                                details = (
                                    f"URL: {ep_url}\n"
                                    f"iOS App IDs (TeamID.BundleID):\n" + "\n".join(f"- `{a}`" for a in aasa_data["app_ids"]) + "\n\n"
                                    f"Deep-Linking Route Paths:\n" + "\n".join(f"- `/{p}`" for p in aasa_data["paths"][:10])
                                )
                                exploitation = (
                                    f"### iOS Universal Links Attack Surface Guidance\n\n"
                                    f"1. **Identify App Bundle**: Cross-reference App Store or internal TestFlight builds using bundle IDs: `{', '.join(aasa_data['app_ids'][:3])}`.\n"
                                    f"2. **Route Scraping**: The paths defined in AASA (`{', '.join(aasa_data['paths'][:5])}`) reveal client-side deep-link routing schemes.\n"
                                    f"3. **Shared Web Credentials**: Check if `webcredentials` allows seamless credential autofill between the iOS app and web portal."
                                )
                                await self.create_alert(
                                    title=title,
                                    description=f"Apple App Site Association discovered on {target}: {len(aasa_data['app_ids'])} App ID(s)",
                                    target=target,
                                    risk_level=risk,
                                    details=details,
                                    exploitation_suggestions=exploitation,
                                    response_size=len(resp.content),
                                    extra_key=f"aasa_{target}",
                                    alert_type=alert_type
                                )

                        # 3. Parse OpenID Configuration / OAuth Server
                        elif ep_type in ("openid", "oauth_server") and isinstance(json_obj, dict):
                            openid_data["present"] = True
                            openid_data["issuer"] = json_obj.get("issuer")
                            openid_data["authorization_endpoint"] = json_obj.get("authorization_endpoint")
                            openid_data["token_endpoint"] = json_obj.get("token_endpoint")
                            openid_data["userinfo_endpoint"] = json_obj.get("userinfo_endpoint")
                            openid_data["jwks_uri"] = json_obj.get("jwks_uri")
                            openid_data["registration_endpoint"] = json_obj.get("registration_endpoint")
                            openid_data["scopes"] = json_obj.get("scopes_supported", [])

                            if not openid_data.get("_alerted"):
                                openid_data["_alerted"] = True
                                reg_ep = openid_data.get("registration_endpoint")
                                has_dynamic_reg = bool(reg_ep)
                                risk = "medium" if has_dynamic_reg else "low"
                                title = f"OpenID Connect Identity Provider Discovered: {target}"
                                
                                details = (
                                    f"URL: {ep_url}\n"
                                    f"Issuer: `{openid_data.get('issuer')}`\n"
                                    f"Authorization Endpoint: `{openid_data.get('authorization_endpoint')}`\n"
                                    f"Token Endpoint: `{openid_data.get('token_endpoint')}`\n"
                                    f"UserInfo Endpoint: `{openid_data.get('userinfo_endpoint')}`\n"
                                    f"JWKS URI: `{openid_data.get('jwks_uri')}`\n"
                                    f"Dynamic Client Registration: `{reg_ep or 'None'}`\n"
                                    f"Supported Scopes: `{', '.join(openid_data.get('scopes', [])[:10])}`"
                                )
                                exploitation = (
                                    f"### OAuth / OIDC Identity Provider Auditing\n\n"
                                    f"1. **Dynamic Client Registration**: If `{reg_ep}` is reachable, test whether unauthenticated client application registration is allowed.\n"
                                    f"2. **SSO & Token Endpoints**: Check token endpoint `{openid_data.get('token_endpoint')}` for supported grant types (`client_credentials`, `authorization_code`).\n"
                                    f"3. **JWKS Key Disclosure**: Inspect public keys at `{openid_data.get('jwks_uri')}` for algorithm configuration (e.g., RS256/ES256 vs weak keys).\n"
                                    f"4. **UserInfo Exposure**: Verify if userinfo endpoint enforces strict token audience and scope validation."
                                )
                                await self.create_alert(
                                    title=title,
                                    description=f"OpenID Connect configuration discovered on {target} (Issuer: {openid_data.get('issuer')})",
                                    target=target,
                                    risk_level=risk,
                                    details=details,
                                    exploitation_suggestions=exploitation,
                                    response_size=len(resp.content),
                                    extra_key=f"openid_{target}",
                                    alert_type="well_known_openid_configuration"
                                )

                except Exception as e:
                    logger.debug(f"Error querying {ep_url}: {e}")

        # Clean internal markers before returning
        assetlinks_data.pop("_alerted", None)
        aasa_data.pop("_alerted", None)
        openid_data.pop("_alerted", None)

        return {
            "items": discovered_items,
            "discovered_dirs": discovered_dirs,
            "extracted_paths": extracted_paths,
            "assetlinks": assetlinks_data,
            "apple_app_site_association": aasa_data,
            "openid_configuration": openid_data
        }

    async def audit_http_verbs(self, base_url: str, target: str, root_domain: str, candidate_paths: list = None):
        """
        Audits HTTP verbs and methods across root and discovered directories:
        1. Probes OPTIONS to capture Allow, Public, and Access-Control-Allow-Methods headers.
        2. Detects high-risk verbs (PUT, DELETE) and validates whether arbitrary write is permitted.
        3. Probes TRACE to detect Cross-Site Tracing (XST) via header reflection.
        4. Detects active WebDAV extensions via DAV headers and PROPFIND probes.
        """
        logger.info(f"Phase 3: Auditing HTTP methods and verbs on {base_url}")
        headers = {
            "User-Agent": self.user_agent
        }

        # Filter candidate paths: prioritize root, then up to 8 directories
        paths_to_audit = [""]
        if candidate_paths:
            for p in candidate_paths:
                p_clean = (p or "").strip("/")
                if p_clean and p_clean not in paths_to_audit and len(paths_to_audit) < 9:
                    paths_to_audit.append(p_clean)

        root_allowed = []
        dangerous_verbs_found = set()
        webdav_active = False
        trace_active = False
        trace_reflected = False
        path_results = {}

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True, headers=headers) as client:
            # 1. TRACE Probe on Root to check for Cross-Site Tracing (XST)
            try:
                trace_token = f"ReconXST_{secrets.token_hex(4)}"
                trace_resp = await client.request(
                    "TRACE",
                    f"{base_url.rstrip('/')}/",
                    headers={"X-Trace-Audit": trace_token}
                )
                if trace_resp.status_code == 200:
                    trace_active = True
                    if trace_token in trace_resp.text or "X-Trace-Audit" in trace_resp.text:
                        trace_reflected = True
                        logger.warning(f"CONFIRMED HTTP TRACE (XST) reflection on {base_url}!")

                        title = f"HTTP TRACE Enabled (Cross-Site Tracing / XST): {target}"
                        description = f"The web server on {target} accepts HTTP TRACE and echoes back request headers."
                        details = (
                            f"Target: {target}\n"
                            f"Endpoint: {base_url}/\n"
                            f"HTTP Status: {trace_resp.status_code}\n"
                            f"Header Echo Verified: Yes (`{trace_token}` reflected in response body)\n"
                            f"Server Banner: {trace_resp.headers.get('server', 'N/A')}"
                        )
                        exploitation = (
                            f"### Cross-Site Tracing (XST) Exploitation Guidance\n\n"
                            f"1. **Session Hijacking via XSS**: In traditional XSS, `HttpOnly` cookies are protected from `document.cookie`. However, an attacker exploiting XSS can issue a `TRACE` request using `XMLHttpRequest` / `fetch`, reading the raw echoed request headers (including `Cookie` and `Authorization`).\n"
                            f"2. **Remediation**: Disable the `TRACE` method in web server configuration:\n"
                            f"   - **Apache**: Set `TraceEnable Off` in `httpd.conf`.\n"
                            f"   - **Nginx**: Explicitly reject TRACE requests (`if ($request_method = TRACE) {{ return 405; }}`).\n"
                            f"   - **IIS**: Add a request filtering rule blocking verb `TRACE`."
                        )
                        await self.create_alert(
                            title=title,
                            description=description,
                            target=target,
                            risk_level="medium",
                            details=details,
                            exploitation_suggestions=exploitation,
                            alert_type="http_method_trace_xst",
                            extra_key=f"trace_xst_{target}"
                        )
            except Exception as e:
                logger.debug(f"TRACE probe error on {base_url}: {e}")

            # 2. Audit OPTIONS on candidate directories
            for path_str in paths_to_audit:
                path_url = f"{base_url.rstrip('/')}/{path_str}" if path_str else f"{base_url.rstrip('/')}/"
                path_label = f"/{path_str}" if path_str else "/"

                try:
                    opt_resp = await client.options(path_url)
                    allow_hdr = opt_resp.headers.get("allow", "")
                    public_hdr = opt_resp.headers.get("public", "")
                    cors_methods = opt_resp.headers.get("access-control-allow-methods", "")
                    dav_hdr = opt_resp.headers.get("dav", "") or opt_resp.headers.get("ms-author-via", "")

                    # Extract all declared methods
                    all_methods_str = f"{allow_hdr} {public_hdr} {cors_methods}".upper()
                    methods_declared = set(re.findall(r'\b[A-Z]{3,10}\b', all_methods_str))

                    if path_str == "":
                        root_allowed = sorted(list(methods_declared))

                    # Check for WebDAV
                    is_webdav = bool(dav_hdr) or any(m in methods_declared for m in ["PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"])
                    if is_webdav:
                        webdav_active = True
                        # Probe PROPFIND
                        try:
                            pf_resp = await client.request("PROPFIND", path_url, headers={"Depth": "0"})
                            if pf_resp.status_code in (200, 207):
                                title = f"WebDAV Extensions Active on {target} ({path_label})"
                                details = (
                                    f"Target: {target}\n"
                                    f"Endpoint: {path_url}\n"
                                    f"DAV Header: `{dav_hdr or 'Detected via PROPFIND'}`\n"
                                    f"Status Code: {pf_resp.status_code} Multi-Status\n"
                                    f"Allowed Methods: `{', '.join(sorted(list(methods_declared)))}`"
                                )
                                exploitation = (
                                    f"### WebDAV Surface Analysis\n\n"
                                    f"1. **PROPFIND Enumeration**: WebDAV `PROPFIND` requests with `Depth: 1` or `Depth: infinity` can dump entire directory trees and file metadata.\n"
                                    f"2. **Unauthorized File Upload**: If `PUT` / `MKCOL` is supported without authentication, arbitrary web files can be authored.\n"
                                    f"3. **Tooling**: Audit with `davtest` or `cadaver {path_url}`."
                                )
                                await self.create_alert(
                                    title=title,
                                    description=f"WebDAV extensions enabled on {target}{path_label} (HTTP {pf_resp.status_code})",
                                    target=target,
                                    risk_level="medium",
                                    details=details,
                                    exploitation_suggestions=exploitation,
                                    alert_type="http_method_webdav_enabled",
                                    extra_key=f"webdav_{target}_{path_str}"
                                )
                        except Exception as e:
                            logger.debug(f"PROPFIND probe error on {path_url}: {e}")

                    # Check for dangerous write methods (PUT, DELETE)
                    dangerous_in_path = [m for m in ["PUT", "DELETE"] if m in methods_declared]
                    if dangerous_in_path:
                        for d_m in dangerous_in_path:
                            dangerous_verbs_found.add(d_m)

                        # Test arbitrary file write if PUT is advertised
                        arbitrary_write_confirmed = False
                        test_file_path = f"{base_url.rstrip('/')}/{path_str.rstrip('/')}/recon_write_test_{secrets.token_hex(4)}.txt".replace("//", "/").replace(":/", "://")
                        if "PUT" in dangerous_in_path:
                            try:
                                put_resp = await client.put(test_file_path, content=b"ReconDashboard Write Test Probe", headers={"Content-Type": "text/plain"})
                                if put_resp.status_code in (200, 201, 204):
                                    arbitrary_write_confirmed = True
                                    logger.warning(f"CRITICAL: Unauthenticated HTTP PUT succeeded on {test_file_path} (HTTP {put_resp.status_code})!")
                                    # Clean up test probe
                                    try:
                                        await client.delete(test_file_path)
                                    except Exception:
                                        pass
                            except Exception as e:
                                logger.debug(f"PUT test probe error: {e}")

                        if arbitrary_write_confirmed:
                            title = f"CRITICAL: Arbitrary File Write Enabled via HTTP PUT on {target}"
                            risk = "critical"
                            desc = f"The web server allowed unauthorized file creation via HTTP PUT at {path_label}"
                        else:
                            title = f"Dangerous HTTP Methods Advertised ({', '.join(dangerous_in_path)}): {target}{path_label}"
                            risk = "medium"
                            desc = f"The web server advertises high-risk methods ({', '.join(dangerous_in_path)}) in Allow headers at {path_label}"

                        details = (
                            f"Target: {target}\n"
                            f"Endpoint: {path_url}\n"
                            f"Allow Header: `{allow_hdr or 'None'}`\n"
                            f"Public Header: `{public_hdr or 'None'}`\n"
                            f"Access-Control-Allow-Methods: `{cors_methods or 'None'}`\n"
                            f"Dangerous Methods: `{', '.join(dangerous_in_path)}`\n"
                            f"Arbitrary File Upload Confirmed: {'YES (CRITICAL)' if arbitrary_write_confirmed else 'No (Enforced/Protected)'}"
                        )
                        exploitation = (
                            f"### High-Risk HTTP Verbs Exploitation Guidance\n\n"
                            f"1. **Arbitrary File Upload (PUT)**: If `PUT` is unauthenticated, an attacker can upload web shells, HTML defacements, or phishing landing pages.\n"
                            f"2. **Unauthorized Deletion (DELETE)**: If `DELETE` is unauthenticated, an attacker can destroy web application files or user assets.\n"
                            f"3. **Remediation**: Disable unused HTTP methods in the web server or API gateway. Only permit `GET`, `POST`, and `HEAD` unless authenticated API routes specifically mandate `PUT`/`DELETE`."
                        )
                        await self.create_alert(
                            title=title,
                            description=desc,
                            target=target,
                            risk_level=risk,
                            details=details,
                            exploitation_suggestions=exploitation,
                            alert_type="http_method_arbitrary_write",
                            extra_key=f"verbs_{target}_{path_str}"
                        )

                    path_results[path_label] = {
                        "status": opt_resp.status_code,
                        "allow": allow_hdr,
                        "methods": sorted(list(methods_declared)),
                        "webdav": is_webdav,
                        "dangerous": dangerous_in_path
                    }

                except Exception as e:
                    logger.debug(f"OPTIONS probe failed on {path_url}: {e}")

        summary = {
            "root_allowed": root_allowed,
            "dangerous_methods": sorted(list(dangerous_verbs_found)),
            "webdav_active": webdav_active,
            "trace_active": trace_active,
            "trace_reflected": trace_reflected,
            "paths_audited": path_results
        }
        logger.info(f"HTTP method audit completed on {target}: Root allowed: {root_allowed}, Dangerous: {summary['dangerous_methods']}, WebDAV: {webdav_active}, TRACE: {trace_active}")
        return summary

    def detect_waf(self, headers: dict) -> str:
        """
        Detects web application firewalls and CDNs from HTTP response headers.
        """
        if not headers:
            return ""
        h_lower = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        server = h_lower.get("server", "")
        via = h_lower.get("via", "")

        if "cf-ray" in h_lower or "cloudflare" in server:
            return "Cloudflare"
        if "x-akamai-transformed" in h_lower or "akamaighost" in server:
            return "Akamai"
        if "x-amz-cf-id" in h_lower or "cloudfront" in via:
            return "AWS CloudFront"
        if "x-iinfo" in h_lower or "visid_incap" in str(h_lower):
            return "Imperva/Incapsula"
        if "fastly" in server or "x-served-by" in h_lower:
            return "Fastly"
        if "f5" in server or "bigip" in str(h_lower):
            return "F5 BIG-IP"
        if "sucuri" in str(h_lower):
            return "Sucuri"
        return ""

    async def probe_soft_404_profile(self, base_url: str) -> dict:
        """
        Probes target to detect:
        1. Baseline soft-404 / custom-404 response sizes (both raw 302 and followed responses)
        2. Web Application Firewall (WAF) signatures
        3. SPA (Single Page App) title & index markers for zero false-positive filtering
        4. Baseline redirect destinations to catch wildcard redirects
        Caches results per base_url across multiple worker requests.
        """
        cached = self.probe_cache.get(base_url)
        if cached:
            return cached

        profile = {
            "lengths": set(),
            "raw_lengths": set(),
            "redirect_destinations": set(),
            "waf": "",
            "spa_title": "",
            "spa_detected": False
        }

        test_tokens = [
            f"rnd_soft404_{secrets.token_hex(6)}",
            f"test_probe_{secrets.token_hex(6)}.html",
            f"probe_nonexistent_{secrets.token_hex(6)}.zip",
            f"probe_check_{secrets.token_hex(6)}.php"
        ]

        try:
            # 1. Probe with follow_redirects=False to catch raw 301/302 response lengths & locations (as ffuf sees them!)
            async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=False, headers={"User-Agent": self.user_agent}) as client_raw:
                for token in test_tokens:
                    probe_url = f"{base_url.rstrip('/')}/{token}"
                    try:
                        r_raw = await client_raw.get(probe_url)
                        raw_len = len(r_raw.content)
                        if raw_len > 0:
                            profile["lengths"].add(raw_len)
                            profile["raw_lengths"].add(raw_len)
                        if r_raw.status_code in (301, 302, 303, 307, 308):
                            loc = (r_raw.headers.get("location") or "").strip()
                            if loc:
                                profile["redirect_destinations"].add(loc)
                                logger.info(f"Soft-404 raw redirect probe on {base_url}: detected baseline redirect to '{loc}' ({raw_len}B, Status {r_raw.status_code})")
                    except Exception:
                        pass

            # 2. Probe with follow_redirects=True to catch root signatures, SPA baseline, and followed page sizes
            async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True, headers={"User-Agent": self.user_agent}) as client:
                try:
                    root_resp = await client.get(base_url)
                    profile["waf"] = self.detect_waf(root_resp.headers)
                    if profile["waf"]:
                        logger.info(f"[*] WAF Detected on {base_url}: {profile['waf']}")

                    root_text = root_resp.text
                    m = re.search(r'<title>(.*?)</title>', root_text, re.I)
                    if m:
                        profile["spa_title"] = m.group(1).strip()
                    if any(marker in root_text.lower() for marker in ["<div id=\"root\"", "<div id=\"app\"", "<app-root", "ng-version", "__next"]):
                        profile["spa_detected"] = True
                except Exception as e:
                    logger.debug(f"Root probe error for {base_url}: {e}")

                for token in test_tokens:
                    probe_url = f"{base_url.rstrip('/')}/{token}"
                    try:
                        resp = await client.get(probe_url)
                        body_len = len(resp.content)
                        if body_len > 0:
                            profile["lengths"].add(body_len)
                            logger.info(f"Soft-404 probe on {base_url}: detected baseline length {body_len} (Status {resp.status_code})")

                        # If a .zip probe returns 200 with text/html, target is an SPA catch-all!
                        if token.endswith(".zip") and resp.status_code == 200:
                            ct = (resp.headers.get("content-type") or "").lower()
                            if "text/html" in ct:
                                profile["spa_detected"] = True
                                logger.info(f"[*] SPA Catch-All 200 OK behavior confirmed on {base_url}")
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Soft-404 profile probe exception on {base_url}: {e}")

        self.probe_cache[base_url] = profile
        return profile

    async def probe_soft_404_lengths(self, base_url: str):
        profile = await self.probe_soft_404_profile(base_url)
        return profile.get("lengths", set())

    async def verify_discovered_file(self, base_url: str, item: dict, spa_profile: dict = None) -> bool:
        """
        Verifies if a discovery is genuine or a catch-all redirect / SPA false positive.
        Returns True if genuine, False if false positive.
        """
        status = item.get("status")
        path = item.get("path", "").lower()
        redirect_loc = (item.get("redirectlocation") or "").strip().lower()

        # 1. 3xx Redirect verification
        if status in [301, 302, 303, 307, 308]:
            if not redirect_loc:
                try:
                    file_url = f"{base_url}/{item['path']}".replace("//", "/").replace(":/", "://")
                    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False, headers={"User-Agent": self.user_agent}) as client:
                        r_hd = await client.head(file_url)
                        redirect_loc = (r_hd.headers.get("location") or "").strip().lower()
                except Exception:
                    pass

            if redirect_loc:
                # Catch-all redirect indicators (e.g. bouncing everything to /login, /, /auth, /error)
                common_targets = ["/", "/login", "/signin", "/auth", "/home", "/index", "/dashboard", "/error", "/404"]
                if redirect_loc in common_targets or any(redirect_loc.endswith(tgt) for tgt in ["/login", "/signin", "/auth"]):
                    logger.info(f"Filtering out catch-all redirect: {item['path']} redirects to common target '{redirect_loc}'")
                    return False

                # If matches baseline soft-404 redirect destination
                if spa_profile and spa_profile.get("redirect_destinations"):
                    for baseline_dest in spa_profile["redirect_destinations"]:
                        b_clean = baseline_dest.strip().lower()
                        if redirect_loc == b_clean or redirect_loc.rstrip("/") == b_clean.rstrip("/"):
                            logger.info(f"Filtering out baseline catch-all redirect: {item['path']} matches soft-404 destination '{redirect_loc}'")
                            return False

            return True

        # Non-200 non-3xx (e.g. 401, 403) are preserved as real server responses
        if status != 200:
            return True

        # 2. Status 200 OK Verification
        file_url = f"{base_url}/{item['path']}".replace("//", "/").replace(":/", "://")
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True, headers={"User-Agent": self.user_agent}) as client:
                resp = await client.get(file_url)
                ct = (resp.headers.get("content-type") or "").lower()
                body_start = resp.text[:2000].lower()
                is_html = "text/html" in ct or "<!doctype html" in body_start or "<html" in body_start

                # Non-HTML sensitive file extensions
                non_html_extensions = (
                    ".zip", ".tar.gz", ".tgz", ".sql", ".sqlite", ".db", ".env", ".key",
                    ".pem", ".crt", ".pfx", ".p12", ".bak", ".old", ".json", ".xml",
                    ".yaml", ".yml", ".ini", ".conf", ".properties", ".log", ".gz",
                    ".txt", ".toml", ".cfg"
                )
                if any(path.endswith(ext) or f"{ext}." in path for ext in non_html_extensions):
                    if is_html:
                        logger.info(f"Filtering out SPA catch-all false positive: {item['path']} returned HTML instead of data/binary file")
                        return False

                # Code file extensions (.php, .jsp, .aspx, .py, .js)
                if is_html:
                    if spa_profile and spa_profile.get("spa_title"):
                        if spa_profile["spa_title"].lower() in body_start:
                            logger.info(f"Filtering out SPA catch-all false positive: {item['path']} matches SPA title '{spa_profile['spa_title']}'")
                            return False
                    if any(marker in body_start for marker in ["<div id=\"root\"", "<div id=\"app\"", "<app-root", "ng-version"]):
                        logger.info(f"Filtering out SPA catch-all false positive: {item['path']} contains SPA root container")
                        return False

                # Structured format verification
                if path.endswith(".json") and not is_html:
                    stripped = resp.text.strip()
                    if not (stripped.startswith("{") or stripped.startswith("[")):
                        return False
                if (path.endswith(".xml") or path.endswith("web.config")) and not is_html:
                    stripped = resp.text.strip()
                    if not ("<" in stripped and ">" in stripped):
                        return False

        except Exception as e:
            logger.debug(f"Verification request failed for {file_url}: {e}")

        return True

    @staticmethod
    def filter_duplicate_lengths(items, baseline_lengths=None, threshold=3):
        """
        Exclude responses with identical lengths that indicate catch-all / soft-404 pages.
        - Any length appearing >= threshold times across the items is excluded.
        - Any length in baseline_lengths is excluded.
        - For 200 status codes with identical non-zero length, threshold is 2 (excluding custom 200 redirects).
        """
        if not items:
            return []

        baseline_lengths = set(baseline_lengths or [])

        # Count frequencies of lengths (> 0 bytes)
        length_counts = Counter(item.get("length", 0) for item in items if item.get("length", 0) > 0)
        status_200_len_counts = Counter(
            item.get("length", 0) for item in items 
            if item.get("status") == 200 and item.get("length", 0) > 0
        )

        catch_all_lengths = set(baseline_lengths)
        for length, count in length_counts.items():
            if count >= threshold:
                catch_all_lengths.add(length)

        for length, count in status_200_len_counts.items():
            if count >= 2:
                catch_all_lengths.add(length)

        if catch_all_lengths:
            suppressed_count = sum(1 for item in items if item.get("length", 0) in catch_all_lengths)
            logger.info(
                f"Soft-404 Length Filter: Excluded {suppressed_count} false positive item(s) "
                f"matching duplicate lengths: {sorted(list(catch_all_lengths))[:10]}"
            )

        return [item for item in items if item.get("length", 0) not in catch_all_lengths]

    async def run_recursive_directory_hunt(self, base_url: str, initial_dirs=None, task_id=None):
        """
        Phase 1: Recursively hunt for directories starting from initial seed directories
        (harvested from in-scope JS Collector routes/endpoints, robots.txt, sitemaps, well-known)
        using curated high-priority directory wordlists with adaptive WAF rate control.
        Explores newly discovered directories recursively up to depth 3-4 without hanging or timing out.
        """
        logger.info(f"Phase 1: Recursive directory hunting on {base_url}")
        discovered_dirs = set([""]) # Always include root
        if initial_dirs:
            for d in initial_dirs:
                if d and isinstance(d, str):
                    clean_d = d.strip('/')
                    if clean_d and not re.search(r'\.(html|htm|js|css|png|jpg|jpeg|svg|gif|ico|woff|woff2|ttf|map|json|txt|xml|pdf)$', clean_d, re.I):
                        discovered_dirs.add(clean_d)

        dir_results = []
        dir_wl = self.get_directory_wordlist()
        if not dir_wl or not os.path.exists(dir_wl):
            logger.warning("Directory wordlist not found, skipping recursive directory hunt.")
            return discovered_dirs, dir_results

        # Pre-flight probe for root baseline profile & WAF
        profile = await self.probe_soft_404_profile(base_url)
        root_baseline = profile.get("lengths", set())
        waf_name = profile.get("waf", "")
        rate = "30" if waf_name else "60"
        threads = "10" if waf_name else "20"
        if waf_name:
            logger.info(f"[*] Adaptive WAF Tuning: Throttling scan rate to {rate} req/s ({threads} threads) for {waf_name} on {base_url}")

        # Build exploration queue with BFS ordering
        priority_keywords = [
            "api", "v1", "v2", "admin", "auth", "login", "app", "portal",
            "users", "user", "account", "dashboard", "manage", "internal", "config"
        ]
        
        queue = deque([""])
        # Add high-priority seed directories into queue
        for s in sorted(discovered_dirs, key=lambda x: (0 if any(k in x.lower() for k in priority_keywords) else 1, len(x.split("/")), x)):
            if s and s not in queue and len(s.split("/")) <= 2:
                queue.append(s)

        visited_dirs = set()
        max_dirs_to_probe = 60
        max_depth = 3

        while queue and len(visited_dirs) < max_dirs_to_probe:
            curr_dir = queue.popleft()
            if curr_dir in visited_dirs:
                continue
            visited_dirs.add(curr_dir)

            if task_id:
                try:
                    await self.tasks_col.update_one(
                        {"_id": task_id},
                        {"$set": {"last_activity": datetime.datetime.utcnow()}}
                    )
                except Exception:
                    pass

            curr_url = f"{base_url}/{curr_dir}".rstrip("/")
            logger.info(f"Phase 1: Directory hunting on: {curr_url or '/'}")

            dir_baseline = await self.probe_soft_404_lengths(curr_url) if curr_dir else root_baseline

            cmd = [
                "ffuf", "-w", dir_wl, "-u", f"{curr_url}/FUZZ",
                "-H", f"User-Agent: {self.user_agent}",
                "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac", "-ic",
                "-t", str(threads), "-rate", str(rate)
            ]
            if waf_name:
                cmd.extend(["-H", "Accept-Language: en-US,en;q=0.9", "-H", "Sec-Fetch-Dest: document"])
            if dir_baseline:
                cmd.extend(["-fs", ",".join(str(l) for l in dir_baseline)])

            try:
                stdout, _ = await self.run_command(cmd, timeout=75)
                if stdout:
                    for line in stdout.splitlines():
                        try:
                            data = json.loads(line.strip())
                            res_list = data['results'] if 'results' in data else [data]
                            for r in res_list:
                                res_url = r['url']
                                rel_path = res_url.replace(base_url, "").lstrip("/")
                                res_word = rel_path.split("/")[-1].strip()
                                
                                is_redirect = r['status'] in [301, 302, 307]
                                has_file_ext = bool(re.search(r'\.[a-zA-Z0-9]{1,5}$', res_word, re.I))

                                # Reject catch-all redirects (e.g. bouncing everything to /login or /)
                                if is_redirect:
                                    red_loc = (r.get('redirectlocation') or "").strip().lower()
                                    common_redirect_targets = ["/", "/login", "/signin", "/auth", "/home", "/index", "/dashboard", "/error", "/404"]
                                    if red_loc in common_redirect_targets or any(red_loc.endswith(tgt) for tgt in ["/login", "/signin", "/auth"]):
                                        continue
                                    if profile.get("redirect_destinations"):
                                        if any(red_loc == bd.lower() or red_loc.rstrip("/") == bd.lower().rstrip("/") for bd in profile["redirect_destinations"]):
                                            continue

                                if is_redirect or not has_file_ext or res_url.endswith("/"):
                                    new_dir = f"{curr_dir}/{res_word}".strip("/")
                                    discovered_dirs.add(new_dir)
                                    dir_depth = len(new_dir.split("/"))
                                    if dir_depth <= max_depth and len(visited_dirs) < max_dirs_to_probe:
                                        # Skip queuing static asset directories to preserve recursion budget for functional branches
                                        static_asset_dirs = {"assets", "static", "images", "img", "css", "js", "fonts", "webfonts", "media", "icons", "vendor", "node_modules"}
                                        if res_word.lower() not in static_asset_dirs:
                                            if new_dir not in visited_dirs and new_dir not in queue:
                                                queue.append(new_dir)
                                
                                dir_results.append({
                                    "path": rel_path,
                                    "directory": curr_dir,
                                    "status": r['status'],
                                    "length": r.get('length', 0),
                                    "words": r.get('words', 0),
                                    "redirectlocation": r.get('redirectlocation', ""),
                                    "source": "dir_hunt"
                                })
                        except Exception:
                            continue
            except Exception as e:
                logger.error(f"Directory hunt error on {curr_url}: {e}")

        filtered_dir_results = self.filter_duplicate_lengths(dir_results, baseline_lengths=root_baseline, threshold=3)
        logger.info(f"Phase 1 Complete: Discovered {len(discovered_dirs)} total directories on {base_url} (explored {len(visited_dirs)}).")
        return discovered_dirs, filtered_dir_results

    async def run_smart_file_enumeration(self, base_url: str, target: str, root_domain: str, discovered_dirs: set, tech_stack: list = None, task_id=None):
        """
        Phase 2: Smart file enumeration across all discovered directories.
        - Dynamically selects technology-tailored wordlists (PHP, ASP.NET, Java/Spring, Node.js, Python, etc.)
        - Incorporates brand, domain, and environment contextual permutations
        - Verifies discovered files against SPA catch-all false positives
        - When a technology is identified from verified files with status == 200,
          it updates the target's tech fingerprint in MongoDB and adds the tech
          to active_tech after duplicate length filtering.
        """
        logger.info(f"Phase 2: Smart File Enumeration across {len(discovered_dirs)} discovered directories on {base_url}")
        file_results = []
        active_tech = list(dict.fromkeys(tech_stack or []))

        priority_keywords = [
            "admin", "api", "login", "auth", "config", "backup", "v1", "v2",
            "upload", "portal", "test", "dev", "private", "internal", "secret"
        ]

        def dir_priority(d: str):
            if not d:
                return (0, 0) # Root directory must ALWAYS be scanned first
            d_lower = d.lower()
            if any(kw in d_lower for kw in priority_keywords):
                return (1, len(d.split("/")))
            return (2, len(d.split("/")))

        # Explore up to 60 discovered directories with priority ordering
        sorted_dirs = sorted(list(discovered_dirs), key=dir_priority)[:60]

        spa_profile = await self.probe_soft_404_profile(base_url)
        root_baseline = spa_profile.get("lengths", set())
        waf_name = spa_profile.get("waf", "")
        rate = "30" if waf_name else "60"
        threads = "10" if waf_name else "20"

        for d_path in sorted_dirs:
            if task_id:
                try:
                    await self.tasks_col.update_one(
                        {"_id": task_id},
                        {"$set": {"last_activity": datetime.datetime.utcnow()}}
                    )
                except Exception:
                    pass

            target_url = f"{base_url}/{d_path}".rstrip("/")
            logger.info(f"Phase 2 File Scan: {target_url or '/'} (Active Tech: {active_tech})")

            dir_baseline = await self.probe_soft_404_lengths(target_url) if d_path else root_baseline

            # Build smart file wordlist using current active_tech + brand/env permutations
            active_wl = self.build_smart_file_wordlist_for_dir(d_path, tech_stack=active_tech, target=target, root_domain=root_domain)
            temp_wl_to_cleanup = active_wl

            cmd_file = [
                "ffuf", "-w", active_wl, "-u", f"{target_url}/FUZZ",
                "-H", f"User-Agent: {self.user_agent}",
                "-mc", "200,204,301,302,307,401,403", "-s", "-json", "-ac", "-ic",
                "-t", str(threads), "-rate", str(rate)
            ]
            if waf_name:
                cmd_file.extend(["-H", "Accept-Language: en-US,en;q=0.9", "-H", "Sec-Fetch-Dest: document"])
            if dir_baseline:
                cmd_file.extend(["-fs", ",".join(str(l) for l in dir_baseline)])

            try:
                stdout_f, _ = await self.run_command(cmd_file, timeout=90)
                if stdout_f:
                    for line in stdout_f.splitlines():
                        try:
                            data = json.loads(line.strip())
                            res_list = data['results'] if 'results' in data else [data]
                            for r in res_list:
                                f_url = r['url']
                                f_rel_path = f_url.replace(base_url, "").lstrip("/")

                                cand_item = {
                                    "path": f_rel_path,
                                    "directory": d_path,
                                    "status": r['status'],
                                    "length": r.get('length', 0),
                                    "words": r.get('words', 0),
                                    "redirectlocation": r.get('redirectlocation', ""),
                                    "source": "smart_file_hunt"
                                }

                                # If discovered path in file enumeration is actually a directory, add to discovered_dirs
                                if cand_item["status"] in [301, 302, 307] or f_rel_path.endswith("/"):
                                    clean_dp = f_rel_path.strip("/")
                                    if clean_dp and not bool(re.search(r'\.[a-zA-Z0-9]{1,5}$', clean_dp.split("/")[-1], re.I)):
                                        discovered_dirs.add(clean_dp)

                                # Validate against catch-all redirects & SPA false positives
                                is_genuine = await self.verify_discovered_file(base_url, cand_item, spa_profile=spa_profile)
                                if not is_genuine:
                                    continue

                                file_results.append(cand_item)
                        except Exception:
                            continue
            except Exception as e:
                logger.error(f"Smart file search error for directory {target_url}: {e}")
            finally:
                if temp_wl_to_cleanup and temp_wl_to_cleanup.startswith("/tmp/"):
                    try:
                        os.remove(temp_wl_to_cleanup)
                    except Exception:
                        pass

        # Deduplicate results by path
        unique_files = {}
        for r in file_results:
            p = r['path']
            if p not in unique_files or (not unique_files[p].get("directory") and r.get("directory")):
                unique_files[p] = r

        all_items = list(unique_files.values())
        filtered_files = self.filter_duplicate_lengths(all_items, baseline_lengths=root_baseline, threshold=3)

        # Identify technology ONLY from surviving verified files that returned HTTP 200 OK
        for f_item in filtered_files:
            if f_item.get("status") == 200:
                newly_found_techs = self.identify_tech_from_file_path(f_item["path"])
                if newly_found_techs:
                    unseen = [t for t in newly_found_techs if t not in active_tech]
                    if unseen:
                        for t in unseen:
                            active_tech.append(t)
                        logger.info(f"[+] Dynamic Tech Fingerprint: Identified {unseen} on {target} from verified 200 OK file {f_item['path']}")
                        await self.update_tech_fingerprint(target, root_domain, unseen, f_item["path"], base_url)

        logger.info(f"Phase 2 Complete: Discovered {len(filtered_files)} files on {base_url} across scanned directories.")
        return filtered_files, active_tech

    async def run_ffuf_recursive(self, base_url, task_id=None, tech_stack=None, initial_dirs=None):
        """
        Backwards-compatible wrapper executing Phase 1 (recursive directory hunt)
        followed by Phase 2 (smart file enumeration).
        """
        discovered_dirs, dir_items = await self.run_recursive_directory_hunt(
            base_url,
            initial_dirs=initial_dirs,
            task_id=task_id
        )
        parsed_target = urllib.parse.urlparse(base_url).netloc.split(":")[0]
        file_items, active_tech = await self.run_smart_file_enumeration(
            base_url,
            target=parsed_target,
            root_domain=parsed_target,
            discovered_dirs=discovered_dirs,
            tech_stack=tech_stack,
            task_id=task_id
        )
        return dir_items + file_items, discovered_dirs

    async def create_alert_for_item(self, root_domain, target, item, url):
        """Create a lead/alert for a newly discovered file/directory using the centralized alerting system."""
        full_discovery_url = f"{url}/{item['path']}".replace("//", "/").replace(":/", "://")
        path_lower = item['path'].lower()
        title = f"Sensitive Discovery: {item['path']}"
        risk = "medium"

        # Categorize sensitivity risk
        critical_patterns = [
            ".env", ".git", ".aws", "credentials", "id_rsa", "master.key", 
            "dump.sql", "backup.zip", "database.sqlite", "backup.tar", "database.sql"
        ]
        high_patterns = [
            "config", "web.config", "settings.py", "backup", "secret", "private", 
            "admin", "login", "password", ".htpasswd", ".htaccess", "shadow", "passwd"
        ]
        medium_patterns = [
            "swagger", "openapi", "actuator", "phpinfo", "info.php", "metrics", "healthz"
        ]

        alert_type = "sensitive_files_critical"
        if any(p in path_lower for p in critical_patterns):
            risk = "high"
            title = f"CRITICAL File Exposed: {item['path']}"
            alert_type = "sensitive_files_critical"
        elif any(p in path_lower for p in high_patterns):
            risk = "high"
            title = f"High-Risk File Exposed: {item['path']}"
            alert_type = "sensitive_files_high"
        elif any(p in path_lower for p in medium_patterns):
            risk = "medium"
            title = f"Diagnostic/API Endpoint Exposed: {item['path']}"
            alert_type = "sensitive_files_diagnostic"

        dir_info = f" inside directory `/{item.get('directory')}/`" if item.get('directory') else ""
        description = f"Web path discovered{dir_info}: {item['path']} (HTTP {item['status']}, {item.get('length', 0)}B)"
        details = (
            f"A sensitive file or path was discovered at {full_discovery_url} with HTTP status {item['status']} "
            f"and response size {item.get('length', 0)} bytes."
        )
        exploitation = (
            f"### Verification & Exploitation Guidance\n\n"
            f"1. **Navigate to Resource**: [{full_discovery_url}]({full_discovery_url})\n"
            f"2. **Assess Exposure**: Check if credentials, database dumps, configuration parameters, or unauthenticated admin portals are accessible.\n"
            f"3. **Remediation**: Restrict access at the web server/reverse proxy layer (return 404 or enforce IP/token authentication) or remove the sensitive file.\n"
            f"4. **Host Context**: Discovered on `{target}` ({root_domain})."
        )

        await self.create_alert(title, description, target, risk, details, exploitation, response_size=item.get('length', 0), alert_type=alert_type)

    async def dispatch_secondary_tasks(self, root_domain: str, target: str, item: dict, url: str):
        """
        Dispatches specialized secondary tasks (403 bypass, Spring Actuator, OpenAPI auto-extraction, Git extractor)
        based on specific high-value findings.
        """
        path = item.get("path", "")
        p_lower = path.lower()
        status = item.get("status")

        # 1. 403 Forbidden Bypass
        if status == 403:
            exists_bypass = await self.tasks_col.find_one({
                "root_domain": root_domain,
                "target": target,
                "path": path,
                "task_type": "bypass_403"
            })
            if not exists_bypass:
                await self.tasks_col.insert_one({
                    "root_domain": root_domain,
                    "target": target,
                    "path": path,
                    "base_url": url,
                    "task_type": "bypass_403",
                    "status": "pending",
                    "created_at": datetime.datetime.utcnow()
                })
                logger.info(f"Queued 403 BYPASS task for {url}/{path}")

        # 2. Spring Boot Actuator Audit
        if any(act in p_lower for act in ["actuator/health", "actuator/env", "actuator/metrics", "actuator/beans", "actuator"]) and status in [200, 401, 403]:
            exists_act = await self.tasks_col.find_one({
                "root_domain": root_domain,
                "target": target,
                "task_type": "actuator_audit"
            })
            if not exists_act:
                await self.tasks_col.insert_one({
                    "root_domain": root_domain,
                    "target": target,
                    "path": path,
                    "base_url": url,
                    "task_type": "actuator_audit",
                    "status": "pending",
                    "created_at": datetime.datetime.utcnow()
                })
                logger.info(f"Queued ACTUATOR_AUDIT task for {url}/{path}")

        # 3. OpenAPI / Swagger Auto-Extraction
        if any(sw in p_lower for sw in ["swagger.json", "openapi.json", "openapi.yaml", "swagger.yaml"]) and status == 200:
            try:
                schema_url = f"{url}/{path}".replace("//", "/").replace(":/", "://")
                async with httpx.AsyncClient(verify=False, timeout=8.0, headers={"User-Agent": self.user_agent}) as client:
                    resp = await client.get(schema_url)
                    if resp.status_code == 200:
                        parsed = resp.json() if "json" in p_lower else None
                        if parsed and isinstance(parsed, dict) and "paths" in parsed:
                            extracted = []
                            for ep in parsed["paths"].keys():
                                extracted.append({"path": ep, "method": "ANY", "source": "openapi_auto_extract"})
                            if extracted:
                                logger.info(f"[+] OpenAPI Auto-Extraction: Ingested {len(extracted)} API endpoints from {schema_url}")
                                await self.domains_col.update_one(
                                    {"domain": target.lower().strip()},
                                    {"$addToSet": {"extracted_endpoints": {"$each": extracted}}}
                                )
                                if root_domain.lower().strip() != target.lower().strip():
                                    await self.domains_col.update_one(
                                        {"domain": root_domain.lower().strip()},
                                        {"$addToSet": {"extracted_endpoints": {"$each": extracted}}}
                                    )
            except Exception as e:
                logger.debug(f"OpenAPI auto-extraction error on {url}/{path}: {e}")

        # 4. Git Repository Exposure Check
        if any(g in p_lower for g in [".git/head", ".git/config"]) and status == 200:
            exists_git = await self.tasks_col.find_one({
                "root_domain": root_domain,
                "target": target,
                "task_type": "git_extractor"
            })
            if not exists_git:
                await self.tasks_col.insert_one({
                    "root_domain": root_domain,
                    "target": target,
                    "path": path,
                    "base_url": url,
                    "task_type": "git_extractor",
                    "status": "pending",
                    "created_at": datetime.datetime.utcnow()
                })
                logger.info(f"Queued GIT_EXTRACTOR task for {url}/{path}")

    async def process_tasks(self):
        task = await self.get_next_task("directory_hunt")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        protocol = task.get("protocol", "http")
        port = task.get("port", 80)
        
        # Build URL. Handle standard ports cleanly.
        if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
            url = f"{protocol}://{target}"
        else:
            url = f"{protocol}://{target}:{port}"

        try:
            # Query web_applications and target document for detected tech stack
            clean_target = target.lower().strip()
            clean_root = root_domain.lower().strip()
            target_doc = await self.domains_col.find_one({"domain": clean_target})
            domain_doc = await self.domains_col.find_one({"domain": clean_root})
            target_tech = []
            if target_doc:
                target_tech.extend(target_doc.get("tech_stack", []))
            if domain_doc:
                for app in domain_doc.get("web_applications", []):
                    if (app.get("target") or "").lower().strip() == clean_target:
                        target_tech.extend(app.get("tech_stack", []))
                        break
            target_tech = list(dict.fromkeys(target_tech))

            # Phase 0: Robots.txt & Sitemap extraction
            rb_data = await self.fetch_robots_and_sitemaps(url, target)
            rb_items = rb_data.get("items", [])
            rb_dirs = set(rb_data.get("discovered_dirs", set()))

            # Harvest initial seed directories from Dynamic JS Collector findings & DB
            js_seed_dirs = await self.harvest_initial_directories(target, root_domain)
            rb_dirs.update(js_seed_dirs)

            # Phase 0.5: Favicon Fingerprinting & Well-Known Harvesting
            favicon_data = await self.fetch_favicon_fingerprint(url, target, root_domain)
            if favicon_data and favicon_data.get("url"):
                rb_items.append({
                    "path": "favicon.ico" if "/favicon.ico" in favicon_data["url"] else favicon_data["url"].replace(url, "").lstrip("/"),
                    "directory": "",
                    "status": 200,
                    "length": favicon_data.get("size", 0),
                    "source": "favicon"
                })
            if favicon_data and favicon_data.get("framework"):
                fw = favicon_data["framework"]
                if fw not in target_tech:
                    target_tech.append(fw)
                    await self.update_tech_fingerprint(target, root_domain, [fw], "favicon.ico", url)

            well_known_data = await self.harvest_well_known_profiles(url, target, root_domain)
            if well_known_data:
                rb_items.extend(well_known_data.get("items", []))
                rb_dirs.update(well_known_data.get("discovered_dirs", set()))

            # Phase 1: Recursive directory mapping using wordlists (seeded with JS routes, robots, sitemaps)
            discovered_dirs, dir_items = await self.run_recursive_directory_hunt(
                url,
                initial_dirs=rb_dirs,
                task_id=task["_id"]
            )
            discovered_dirs.update(rb_dirs)

            # Phase 2: Smart file enumeration on all discovered directories with dynamic tech identification
            file_items, updated_tech = await self.run_smart_file_enumeration(
                url,
                target=target,
                root_domain=root_domain,
                discovered_dirs=discovered_dirs,
                tech_stack=target_tech,
                task_id=task["_id"]
            )
            target_tech = list(dict.fromkeys(target_tech + updated_tech))
            found_items = dir_items + file_items

            # Phase 3: HTTP Verb & Method Auditing on root and discovered directories
            http_methods_data = await self.audit_http_verbs(
                url,
                target,
                root_domain,
                candidate_paths=list(discovered_dirs)[:8]
            )

            # Deduplicate and combine findings
            all_found_dict = {}
            for item in rb_items:
                all_found_dict[item["path"]] = item
            for item in found_items:
                p = item["path"]
                if p in all_found_dict:
                    src = all_found_dict[p].get("source")
                    all_found_dict[p] = item
                    if src:
                        all_found_dict[p]["source"] = src
                else:
                    all_found_dict[p] = item

            combined_items = list(all_found_dict.values())
            
            # Update web_applications in the domains collection (re-fetch fresh document to avoid clobbering concurrent agent updates)
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            if domain_doc:
                web_apps = domain_doc.get("web_applications", [])
                app_found = False

                # Build structured discovered_directories records
                dir_records = []
                for d in sorted(discovered_dirs):
                    files_in_d = sum(1 for item in combined_items if item.get("directory") == d)
                    dir_records.append({
                        "path": d or "/",
                        "files_found": files_in_d,
                        "scanned_at": datetime.datetime.utcnow().isoformat()
                    })

                for app in web_apps:
                    if app.get("target") == target:
                        # Update existing app
                        existing_files = {f["path"]: f for f in app.get("sensitive_files", [])}
                        
                        for item in combined_items:
                            path = item["path"]
                            if path not in existing_files:
                                # For items discovered via robots/sitemap/well-known, only alert on sensitive patterns to avoid alert spam
                                is_rb_src = item.get("source") in ["robots.txt", "sitemap.xml", "security.txt", "well-known", "favicon"]
                                is_sensitive = any(pat in path.lower() for pat in [
                                    ".env", ".git", "admin", "login", "config", "backup", "secret", "private", "api", "swagger", "actuator"
                                ])
                                if not is_rb_src or is_sensitive or item.get("status") in [401, 403]:
                                    await self.create_alert_for_item(root_domain, target, item, url)
                                
                                # Dispatch specialized secondary tasks (403 bypass, Spring Actuator, OpenAPI auto-extraction, Git extractor)
                                await self.dispatch_secondary_tasks(root_domain, target, item, url)
                            
                            # Preserve directory, length, and source in stored record
                            existing_files[path] = {
                                "path": path,
                                "directory": item.get("directory", ""),
                                "status": item["status"],
                                "length": item.get("length", 0),
                                "source": item.get("source", "dir_hunt")
                            }
                        
                        app["sensitive_files"] = list(existing_files.values())
                        app["discovered_directories"] = dir_records
                        if rb_data.get("robots_txt"):
                            app["robots_txt"] = rb_data["robots_txt"]
                        if rb_data.get("sitemap"):
                            app["sitemap"] = rb_data["sitemap"]
                        if rb_data.get("security_txt"):
                            app["security_txt"] = rb_data["security_txt"]
                        if favicon_data:
                            app["favicon"] = favicon_data
                        if well_known_data:
                            app["well_known"] = {
                                "assetlinks": well_known_data.get("assetlinks", {}),
                                "apple_app_site_association": well_known_data.get("apple_app_site_association", {}),
                                "openid_configuration": well_known_data.get("openid_configuration", {})
                            }
                        if http_methods_data:
                            app["http_methods"] = http_methods_data
                        app["tech_stack"] = list(dict.fromkeys((app.get("tech_stack") or []) + target_tech))
                        app_found = True
                        break
                
                if not app_found:
                    # Create new app entry
                    for item in combined_items:
                        path = item["path"]
                        is_rb_src = item.get("source") in ["robots.txt", "sitemap.xml", "security.txt", "well-known", "favicon"]
                        is_sensitive = any(pat in path.lower() for pat in [
                            ".env", ".git", "admin", "login", "config", "backup", "secret", "private", "api", "swagger", "actuator"
                        ])
                        if not is_rb_src or is_sensitive or item.get("status") in [401, 403]:
                            await self.create_alert_for_item(root_domain, target, item, url)

                        # Dispatch specialized secondary tasks (403 bypass, Spring Actuator, OpenAPI auto-extraction, Git extractor)
                        await self.dispatch_secondary_tasks(root_domain, target, item, url)
                        
                    web_apps.append({
                        "target": target,
                        "url": url,
                        "discovered_directories": dir_records,
                        "sensitive_files": [
                            {
                                "path": item["path"],
                                "directory": item.get("directory", ""),
                                "status": item["status"],
                                "length": item.get("length", 0),
                                "source": item.get("source", "dir_hunt")
                            }
                            for item in combined_items
                        ],
                        "robots_txt": rb_data.get("robots_txt", {}),
                        "sitemap": rb_data.get("sitemap", {}),
                        "security_txt": rb_data.get("security_txt", {}),
                        "favicon": favicon_data or {},
                        "well_known": {
                            "assetlinks": well_known_data.get("assetlinks", {}) if well_known_data else {},
                            "apple_app_site_association": well_known_data.get("apple_app_site_association", {}) if well_known_data else {},
                            "openid_configuration": well_known_data.get("openid_configuration", {}) if well_known_data else {}
                        } if well_known_data else {},
                        "http_methods": http_methods_data or {},
                        "tech_stack": target_tech or [],
                        "security_headers": {}
                    })
                
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {"web_applications": web_apps}}
                )

                if target and target.lower() != root_domain.lower():
                    t_doc = await self.domains_col.find_one({"domain": target})
                    if t_doc:
                        t_web_apps = [app for app in web_apps if app.get("target") == target]
                        await self.domains_col.update_one(
                            {"domain": target},
                            {"$set": {"web_applications": t_web_apps}}
                        )
                if target_tech:
                    await self.domains_col.update_one(
                        {"domain": clean_target},
                        {"$addToSet": {"tech_stack": {"$each": target_tech}}}
                    )
            
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            logger.info(f"Completed directory hunt for {url}. Found {len(found_items)} files across {len(discovered_dirs)} directories.")

            # Check if this was the last task for the root domain
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in directory hunt for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = DirectoryHunterAgent()
    asyncio.run(agent.main_loop())
