import asyncio
import base64
import datetime
import json
import os
import re
import sys
import urllib.parse
import httpx
from typing import Dict, List, Set, Tuple, Optional, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base_agent import BaseAgent, logger
from playwright.async_api import async_playwright
from api_schema_discovery import ApiSchemaDiscovery


class CommentExtractor:
    """
    High-performance extractor and classifier for HTML and JavaScript comments.
    Identifies sensitive secrets, developer notes/TODOs, API routes, and framework comments.
    """
    HIGH_INTEREST_PATTERNS = [
        re.compile(r'\b(?:api[_-]?key|secret|token|password|passwd|auth[_-]?token|bearer|access[_-]?token|private[_-]?key)\b', re.IGNORECASE),
        re.compile(r'\b(?:admin|root|internal|backdoor|credential|credentials|bypass|leak|database|db_pass|aws_key)\b', re.IGNORECASE),
        re.compile(r'\b(?:staging|production|prod|dev|qa|test)\b.*\b(?:url|endpoint|pass|key|host|ip)\b', re.IGNORECASE),
        re.compile(r'(?:username|user|login)\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.]+["\']?', re.IGNORECASE),
    ]

    DEV_NOTE_PATTERNS = [
        re.compile(r'\b(?:TODO|FIXME|BUG|HACK|NOTE|XXX|TEMP|TEMPORARY|DEBUG|DEPRECATED|OPTIMIZE|REFACTOR|WORKAROUND)\b', re.IGNORECASE),
    ]

    ROUTE_PATTERNS = [
        re.compile(r'(?:https?://[a-zA-Z0-9_\-\.:]+|/api/v[0-9]+/|/api/|/graphql|/rest/|/v[0-9]+/|localhost|127\.0\.0\.1)', re.IGNORECASE),
    ]

    LICENSE_PATTERNS = [
        re.compile(r'(?:@license|copyright\s+(?:\(c\)|©)?\s*[0-9]{4}|spdx-license-identifier|mit license|apache license|mozilla public license|gnu general public)', re.IGNORECASE),
    ]

    @classmethod
    def classify_comment(cls, text: str) -> Tuple[str, bool]:
        """
        Classifies comment text into:
        'High Interest', 'Developer Note', 'Route / Endpoint', 'License', or 'General'.
        Returns (category, is_interesting).
        """
        clean_text = text.strip()
        
        # Check High Interest first
        for pat in cls.HIGH_INTEREST_PATTERNS:
            if pat.search(clean_text):
                return "High Interest", True
                
        # Check Developer Notes
        for pat in cls.DEV_NOTE_PATTERNS:
            if pat.search(clean_text):
                return "Developer Note", True
                
        # Check Routes / Endpoints
        for pat in cls.ROUTE_PATTERNS:
            if pat.search(clean_text):
                return "Route / Endpoint", True

        # Check License
        for pat in cls.LICENSE_PATTERNS:
            if pat.search(clean_text):
                return "License", False

        return "General", False

    @classmethod
    def extract_html_comments(cls, html: str, source_url: str) -> List[dict]:
        """
        Extracts all HTML comments (<!-- ... -->) along with line numbers and categories.
        """
        results = []
        if not html:
            return results

        comment_regex = re.compile(r'<!--([\s\S]*?)-->')
        for match in comment_regex.finditer(html):
            raw_comment = match.group(1).strip()
            if not raw_comment or len(raw_comment) < 2:
                continue
            
            line_no = html[:match.start()].count('\n') + 1
            category, is_interesting = cls.classify_comment(raw_comment)
            
            clean_source = source_url.split('?')[0].rstrip('/')
            source_name = clean_source.split('/')[-1] if clean_source else "index.html"
            if not source_name:
                source_name = "index.html"
            
            results.append({
                "type": "html",
                "content": raw_comment,
                "category": category,
                "is_interesting": is_interesting,
                "source_url": source_url,
                "source_name": source_name,
                "line_number": line_no,
                "length": len(raw_comment)
            })
        return results

    @classmethod
    def extract_js_comments(cls, js_code: str, source_url: str) -> List[dict]:
        """
        Extracts single-line (//) and multi-line (/* ... */) comments from JavaScript.
        Accurately skips string literals and template literals to avoid false positives.
        """
        results = []
        if not js_code:
            return results

        clean_source = source_url.split('#inline-script-')[0].split('?')[0].rstrip('/')
        source_name = clean_source.split('/')[-1] if clean_source else "script.js"
        if '#inline-script-' in source_url:
            idx = source_url.split('#inline-script-')[-1]
            source_name = f"Inline Script #{idx}"

        n = len(js_code)
        i = 0
        line = 1

        while i < n:
            c = js_code[i]

            if c == '\n':
                line += 1
                i += 1
                continue

            # Check single-line comment: //
            if c == '/' and i + 1 < n and js_code[i+1] == '/':
                # Ignore :// in URLs
                if i > 0 and js_code[i-1] == ':':
                    i += 2
                    continue
                
                comment_start_line = line
                i += 2
                start_idx = i
                while i < n and js_code[i] != '\n':
                    i += 1
                raw_comment = js_code[start_idx:i].strip()
                
                if raw_comment and not raw_comment.startswith('# sourceMappingURL=') and not raw_comment.startswith('@ sourceMappingURL='):
                    category, is_interesting = cls.classify_comment(raw_comment)
                    results.append({
                        "type": "js_single",
                        "content": raw_comment,
                        "category": category,
                        "is_interesting": is_interesting,
                        "source_url": source_url,
                        "source_name": source_name,
                        "line_number": comment_start_line,
                        "length": len(raw_comment)
                    })
                continue

            # Check multi-line comment: /* ... */
            if c == '/' and i + 1 < n and js_code[i+1] == '*':
                comment_start_line = line
                i += 2
                start_idx = i
                while i + 1 < n and not (js_code[i] == '*' and js_code[i+1] == '/'):
                    if js_code[i] == '\n':
                        line += 1
                    i += 1
                
                raw_comment = js_code[start_idx:i].strip()
                if i + 1 < n:
                    i += 2  # skip */
                else:
                    i = n

                if raw_comment and not raw_comment.startswith('# sourceMappingURL=') and not raw_comment.startswith('@ sourceMappingURL='):
                    category, is_interesting = cls.classify_comment(raw_comment)
                    results.append({
                        "type": "js_multi",
                        "content": raw_comment,
                        "category": category,
                        "is_interesting": is_interesting,
                        "source_url": source_url,
                        "source_name": source_name,
                        "line_number": comment_start_line,
                        "length": len(raw_comment)
                    })
                continue

            # Skip string literals and template literals
            if c in ('"', "'", '`'):
                quote = c
                i += 1
                while i < n:
                    ch = js_code[i]
                    if ch == '\n':
                        line += 1
                    if ch == '\\':
                        if i + 1 < n and js_code[i+1] == '\n':
                            line += 1
                        i += 2
                        continue
                    if ch == quote:
                        i += 1
                        break
                    i += 1
                continue

            i += 1

        return results


class MetaTagExtractor:
    """
    Extracts and classifies HTML <meta> tags.
    Identifies framework versions, CSRF/verification tokens, build IDs,
    security policies, authors, and OpenGraph/SEO metadata.
    """
    META_TAG_REGEX = re.compile(r'<meta\s+((?:[^"\'\>]|"[^"]*"|\'[^\']*\')*?)\s*/?>', re.IGNORECASE)
    ATTR_REGEX = re.compile(r'([a-zA-Z0-9_\-:]+)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+)))?', re.IGNORECASE)

    SECURITY_KEYWORDS = {
        'csrf', 'token', 'verification', 'verify', 'csp', 'security',
        'content-security-policy', 'referrer', 'sentry-trace', 'api-key',
        'apikey', 'secret', 'auth-token', 'authenticity', 'authorization'
    }
    FRAMEWORK_KEYWORDS = {
        'generator', 'application-name', 'build', 'version', 'release',
        'revision', 'environment', 'commit', 'branch', 'next-head-count'
    }
    AUTHOR_KEYWORDS = {
        'author', 'creator', 'publisher', 'copyright', 'owner', 'contact', 'email'
    }

    @classmethod
    def classify_meta_tag(cls, key: str, value: str, http_equiv: str = "") -> Tuple[str, bool]:
        k_lower = (key or "").lower().strip()
        v_lower = (value or "").lower().strip()
        he_lower = (http_equiv or "").lower().strip()

        # Check author / owner first
        if any(w in k_lower for w in cls.AUTHOR_KEYWORDS):
            return "Author & Ownership", True

        # Check security / tokens / verification
        if any(w in k_lower or w in he_lower for w in cls.SECURITY_KEYWORDS):
            return "Security & Verification", True

        # Check framework / build
        if any(w in k_lower for w in cls.FRAMEWORK_KEYWORDS):
            return "Framework & Build", True

        # Check OpenGraph / Social
        if k_lower.startswith('og:') or k_lower.startswith('twitter:'):
            return "OpenGraph & Social", False

        # Check SEO & Indexing
        if k_lower in ('description', 'keywords', 'robots', 'googlebot'):
            return "SEO & Indexing", False

        return "Standard / Config", False

    @classmethod
    def extract_meta_tags(cls, html: str, source_url: str) -> List[dict]:
        results = []
        if not html:
            return results

        clean_source = source_url.split('?')[0].rstrip('/')
        source_name = clean_source.split('/')[-1] if clean_source else "index.html"
        if not source_name:
            source_name = "index.html"

        for match in cls.META_TAG_REGEX.finditer(html):
            raw_tag = match.group(0)
            attr_str = match.group(1) or ""
            
            attrs = {}
            for attr_match in cls.ATTR_REGEX.finditer(attr_str):
                attr_name = attr_match.group(1).lower()
                attr_val = ""
                if attr_match.group(2) is not None:
                    attr_val = attr_match.group(2)
                elif attr_match.group(3) is not None:
                    attr_val = attr_match.group(3)
                elif attr_match.group(4) is not None:
                    attr_val = attr_match.group(4)
                attrs[attr_name] = attr_val

            # Determine key and content
            key = ""
            key_type = ""
            if "name" in attrs:
                key = attrs["name"]
                key_type = "name"
            elif "property" in attrs:
                key = attrs["property"]
                key_type = "property"
            elif "http-equiv" in attrs:
                key = attrs["http-equiv"]
                key_type = "http-equiv"
            elif "itemprop" in attrs:
                key = attrs["itemprop"]
                key_type = "itemprop"
            elif "charset" in attrs:
                key = "charset"
                key_type = "charset"
            
            content = attrs.get("content", "")
            if not content and "charset" in attrs:
                content = attrs["charset"]

            if not key and not content:
                continue

            line_no = html[:match.start()].count('\n') + 1
            category, is_interesting = cls.classify_meta_tag(key, content, http_equiv=attrs.get("http-equiv", ""))

            results.append({
                "key": key or "unnamed",
                "key_type": key_type or "meta",
                "content": content,
                "category": category,
                "is_interesting": is_interesting,
                "raw_tag": raw_tag,
                "attributes": attrs,
                "source_url": source_url,
                "source_name": source_name,
                "line_number": line_no
            })

        return results


class HydrationStateExtractor:
    """
    Extracts and parses SSR / hydration / state payloads from HTML and inline scripts:
      - Next.js: <script id="__NEXT_DATA__" type="application/json">
      - Nuxt 2/3: <script id="__NUXT_DATA__" type="application/json">, window.__NUXT__
      - React SSR / Redux: window.__INITIAL_STATE__, window.__PRELOADED_STATE__
      - Apollo Client GraphQL Cache: window.__APOLLO_STATE__, <script id="__APOLLO_STATE__">
      - Remix: window.__remixContext
      - SvelteKit: data-sveltekit-fetched, __sveltekit_
    Pulls structured route patterns, environment configurations (NEXT_PUBLIC_*),
    user identity/role context, and internal API endpoints.
    """
    NEXT_DATA_REGEX = re.compile(
        r'<script[^>]*\bid=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
        re.DOTALL | re.IGNORECASE
    )
    NUXT_DATA_REGEX = re.compile(
        r'<script[^>]*\bid=["\']__NUXT_DATA__["\'][^>]*>(.*?)</script>',
        re.DOTALL | re.IGNORECASE
    )
    APOLLO_SCRIPT_REGEX = re.compile(
        r'<script[^>]*\bid=["\']__APOLLO_STATE__["\'][^>]*>(.*?)</script>',
        re.DOTALL | re.IGNORECASE
    )
    SVELTEKIT_REGEX = re.compile(
        r'<script[^>]*\bdata-sveltekit-[^>]*>(.*?)</script>',
        re.DOTALL | re.IGNORECASE
    )

    VAR_PATTERNS = [
        ("Apollo Client GraphQL", "__APOLLO_STATE__", re.compile(r'(?:window\.)?__APOLLO_STATE__\s*=\s*(\{)', re.IGNORECASE)),
        ("Redux / React SSR", "__INITIAL_STATE__", re.compile(r'(?:window\.)?__(?:INITIAL|PRELOADED)_STATE__\s*=\s*(\{)', re.IGNORECASE)),
        ("Remix SSR", "__remixContext", re.compile(r'(?:window\.)?__remixContext\s*=\s*(\{)', re.IGNORECASE)),
        ("Nuxt 2", "window.__NUXT__", re.compile(r'window\.__NUXT__\s*=\s*(?:.*?\breturn\s*)?(\{)', re.IGNORECASE | re.DOTALL)),
    ]

    ENV_KEYWORDS = {
        'api_key', 'apikey', 'client_id', 'client_secret', 'secret', 'token',
        'auth0', 'firebase', 'supabase', 'stripe', 'aws', 'backend_url',
        'api_url', 'base_url', 'endpoint', 'domain', 'app_id', 'sentry_dsn',
        'environment', 'runtime_config'
    }

    USER_KEYWORDS = {
        'user', 'currentuser', 'session', 'auth', 'account', 'profile',
        'identity', 'me', 'member'
    }

    @staticmethod
    def _extract_json_from_index(text: str, start_brace_idx: int) -> Tuple[Optional[Any], str]:
        """
        Parses JSON object starting at start_brace_idx using JSONDecoder.raw_decode
        with fallback to balanced bracket parsing.
        """
        if start_brace_idx < 0 or start_brace_idx >= len(text):
            return None, ""
        substring = text[start_brace_idx:]
        try:
            decoder = json.JSONDecoder()
            obj, end = decoder.raw_decode(substring)
            raw_snippet = substring[:end]
            return obj, raw_snippet
        except Exception:
            pass

        # Balanced brace fallback
        depth = 0
        in_string = False
        quote_char = ''
        escape = False
        end_idx = -1

        for i, ch in enumerate(substring):
            if escape:
                escape = False
                continue
            if ch == '\\':
                escape = True
                continue
            if in_string:
                if ch == quote_char:
                    in_string = False
                continue
            if ch in ('"', "'"):
                in_string = True
                quote_char = ch
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end_idx = i + 1
                    break

        if end_idx != -1:
            raw_block = substring[:end_idx]
            try:
                return json.loads(raw_block), raw_block
            except Exception:
                try:
                    cleaned = re.sub(r'([{,]\s*)([a-zA-Z0-9_$]+)\s*:', r'\1"\2":', raw_block)
                    return json.loads(cleaned), raw_block
                except Exception:
                    return None, raw_block
        return None, ""

    @classmethod
    def _walk_tree(cls, obj: Any, extracted: dict, depth: int = 0):
        if depth > 10 or obj is None:
            return

        if isinstance(obj, dict):
            for k, v in obj.items():
                k_str = str(k)
                k_lower = k_str.lower()

                # 1. Environment & Public Config
                if k_str.startswith(('NEXT_PUBLIC_', 'REACT_APP_', 'VITE_', 'NUXT_')) or any(w in k_lower for w in cls.ENV_KEYWORDS):
                    if isinstance(v, (str, int, float, bool)) and len(str(v)) < 300:
                        extracted['env_vars'][k_str] = v
                    elif isinstance(v, dict):
                        cls._walk_tree(v, extracted, depth + 1)

                # 2. Routes & Paths
                if k_lower in ('page', 'pathname', 'route', 'aspath', 'path', 'url'):
                    if isinstance(v, str) and v.startswith('/') and len(v) < 150:
                        if not any(v.lower().endswith(ext) for ext in ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ttf', '.ico')):
                            extracted['routes'].add(v)

                # 3. User Identity & Privileges
                if any(w == k_lower or k_lower.endswith('_' + w) for w in cls.USER_KEYWORDS):
                    if isinstance(v, dict):
                        user_summary = {}
                        for uk in ('id', '_id', 'uuid', 'email', 'name', 'username', 'role', 'roles', 'permissions', 'tenant_id', 'org_id'):
                            if uk in v:
                                user_summary[uk] = v[uk]
                        if user_summary:
                            extracted['user_context'].append(user_summary)
                    elif isinstance(v, str) and '@' in v and len(v) < 80:
                        extracted['user_context'].append({"email": v})

                # 4. API Endpoints
                if isinstance(v, str):
                    if (v.startswith(('/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/')) or '://' in v) and len(v) < 200:
                        extracted['api_endpoints'].add(v)

                # Continue recursion
                cls._walk_tree(v, extracted, depth + 1)

        elif isinstance(obj, list):
            for item in obj[:50]:
                cls._walk_tree(item, extracted, depth + 1)

    @classmethod
    def extract_from_html(cls, html: str, source_url: str) -> List[dict]:
        results: List[dict] = []
        if not html:
            return results

        seen_payload_types = set()

        # 1. Next.js __NEXT_DATA__
        for m in cls.NEXT_DATA_REGEX.finditer(html):
            raw_json = m.group(1).strip()
            try:
                parsed = json.loads(raw_json)
            except Exception:
                parsed = None
            if parsed and isinstance(parsed, dict):
                tree_data = {'env_vars': {}, 'routes': set(), 'user_context': [], 'api_endpoints': set()}
                cls._walk_tree(parsed, tree_data)
                if parsed.get('page') and isinstance(parsed['page'], str) and parsed['page'].startswith('/'):
                    tree_data['routes'].add(parsed['page'])

                results.append({
                    "id": "__NEXT_DATA__",
                    "framework": "Next.js",
                    "source_url": source_url,
                    "build_id": parsed.get("buildId"),
                    "page": parsed.get("page"),
                    "routes": sorted(list(tree_data['routes'])),
                    "env_vars": tree_data['env_vars'],
                    "user_context": tree_data['user_context'][:5],
                    "api_endpoints": sorted(list(tree_data['api_endpoints']))[:50],
                    "raw_snippet": raw_json[:350] + ("..." if len(raw_json) > 350 else "")
                })
                seen_payload_types.add("__NEXT_DATA__")

        # 2. Nuxt __NUXT_DATA__
        for m in cls.NUXT_DATA_REGEX.finditer(html):
            raw_json = m.group(1).strip()
            try:
                parsed = json.loads(raw_json)
            except Exception:
                parsed = None
            if parsed:
                tree_data = {'env_vars': {}, 'routes': set(), 'user_context': [], 'api_endpoints': set()}
                cls._walk_tree(parsed, tree_data)
                results.append({
                    "id": "__NUXT_DATA__",
                    "framework": "Nuxt 3",
                    "source_url": source_url,
                    "routes": sorted(list(tree_data['routes'])),
                    "env_vars": tree_data['env_vars'],
                    "user_context": tree_data['user_context'][:5],
                    "api_endpoints": sorted(list(tree_data['api_endpoints']))[:50],
                    "raw_snippet": raw_json[:350] + ("..." if len(raw_json) > 350 else "")
                })
                seen_payload_types.add("__NUXT_DATA__")

        # 3. Apollo Script Tag <script id="__APOLLO_STATE__">
        for m in cls.APOLLO_SCRIPT_REGEX.finditer(html):
            raw_json = m.group(1).strip()
            try:
                parsed = json.loads(raw_json)
            except Exception:
                parsed = None
            if parsed and isinstance(parsed, dict):
                tree_data = {'env_vars': {}, 'routes': set(), 'user_context': [], 'api_endpoints': set()}
                cls._walk_tree(parsed, tree_data)
                apollo_queries = []
                apollo_types = set()
                root_query = parsed.get("ROOT_QUERY", {})
                if isinstance(root_query, dict):
                    for q in root_query.keys():
                        if not q.startswith('__'):
                            apollo_queries.append(q.split('(')[0])
                for k in parsed.keys():
                    if ':' in k and not k.startswith('$'):
                        apollo_types.add(k.split(':')[0])

                results.append({
                    "id": "__APOLLO_STATE__",
                    "framework": "Apollo Client GraphQL",
                    "source_url": source_url,
                    "apollo_queries": sorted(list(set(apollo_queries)))[:30],
                    "apollo_entities": sorted(list(apollo_types))[:20],
                    "routes": sorted(list(tree_data['routes'])),
                    "env_vars": tree_data['env_vars'],
                    "user_context": tree_data['user_context'][:5],
                    "api_endpoints": sorted(list(tree_data['api_endpoints']))[:50],
                    "raw_snippet": raw_json[:350] + ("..." if len(raw_json) > 350 else "")
                })
                seen_payload_types.add("__APOLLO_STATE__")

        # 4. Variable assignments (Apollo, Redux, Remix, Nuxt 2)
        for framework, var_id, pattern in cls.VAR_PATTERNS:
            if var_id in seen_payload_types:
                continue
            for m in pattern.finditer(html):
                brace_idx = m.start(1) if m.group(1) else -1
                if brace_idx == -1:
                    continue
                parsed, raw_snippet = cls._extract_json_from_index(html, brace_idx)
                if parsed and isinstance(parsed, dict):
                    tree_data = {'env_vars': {}, 'routes': set(), 'user_context': [], 'api_endpoints': set()}
                    cls._walk_tree(parsed, tree_data)

                    extra = {}
                    if var_id == "__APOLLO_STATE__":
                        apollo_queries = []
                        apollo_types = set()
                        root_query = parsed.get("ROOT_QUERY", {})
                        if isinstance(root_query, dict):
                            for q in root_query.keys():
                                if not q.startswith('__'):
                                    apollo_queries.append(q.split('(')[0])
                        for k in parsed.keys():
                            if ':' in k and not k.startswith('$'):
                                apollo_types.add(k.split(':')[0])
                        extra["apollo_queries"] = sorted(list(set(apollo_queries)))[:30]
                        extra["apollo_entities"] = sorted(list(apollo_types))[:20]

                    elif var_id == "__remixContext":
                        manifest_routes = parsed.get("manifest", {}).get("routes", {})
                        if isinstance(manifest_routes, dict):
                            for r_val in manifest_routes.values():
                                if isinstance(r_val, dict) and r_val.get("path"):
                                    tree_data['routes'].add("/" + r_val["path"].lstrip("/"))

                    res_item = {
                        "id": var_id,
                        "framework": framework,
                        "source_url": source_url,
                        "routes": sorted(list(tree_data['routes'])),
                        "env_vars": tree_data['env_vars'],
                        "user_context": tree_data['user_context'][:5],
                        "api_endpoints": sorted(list(tree_data['api_endpoints']))[:50],
                        "raw_snippet": raw_snippet[:350] + ("..." if len(raw_snippet) > 350 else ""),
                        **extra
                    }
                    results.append(res_item)
                    seen_payload_types.add(var_id)
                    break

        return results


class ClientRouterExtractor:
    """
    Extracts client-side SPA routing declarations (React Router, Vue Router,
    Angular Router, Next.js SPA navigation & page manifests).
    Classifies discovered routes by privilege level and functionality.
    """
    JSX_ROUTE_REGEX = re.compile(
        r'<Route\b[^>]*\bpath\s*=\s*(?:["\']([^"\'\s>]+)["\']|\{["\']([^"\'\s}]+)["\']\}|\{`([^`\s]+)`\})',
        re.IGNORECASE
    )
    OBJECT_ROUTE_REGEX = re.compile(
        r'\bpath\s*:\s*["\'](/[^"\'\s?#\n\r]{1,120})["\']',
        re.IGNORECASE
    )
    NAVIGATE_REGEX = re.compile(
        r'\b(?:navigate|push|replace|routerLink)\s*(?:\.push|\.replace)?\s*(?:\(\s*["\']|:\s*["\']|=\s*["\'])(/[^"\'\s?#\n\r]{1,120})["\']',
        re.IGNORECASE
    )

    STATIC_EXTENSIONS = (
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.woff',
        '.woff2', '.ttf', '.ico', '.map', '.webp', '.wasm'
    )

    CATEGORY_PATTERNS = [
        ("🔥 Admin / Privileged", re.compile(r'/(?:admin|administrator|super|internal|manage|control-panel|root|staff|backoffice|sysadmin)\b', re.IGNORECASE)),
        ("💳 Billing & Commercial", re.compile(r'/(?:billing|subscription|invoice|payment|stripe|checkout|plan|pricing)\b', re.IGNORECASE)),
        ("🔑 Auth & Identity", re.compile(r'/(?:login|signin|signup|register|oauth|sso|callback|reset-password|forgot-password|mfa|2fa|verify|logout)\b', re.IGNORECASE)),
        ("⚙️ Settings & Security", re.compile(r'/(?:settings|preferences|config|security|keys|api-keys|tokens|integrations|webhooks)\b', re.IGNORECASE)),
        ("👥 User & Org Management", re.compile(r'/(?:users|teams|members|organizations|orgs|roles|permissions|tenants|accounts)\b', re.IGNORECASE)),
        ("📊 Analytics & Reports", re.compile(r'/(?:analytics|metrics|telemetry|reports|audit|logs|monitoring)\b', re.IGNORECASE)),
    ]

    @classmethod
    def classify_route(cls, path: str) -> str:
        for cat, pat in cls.CATEGORY_PATTERNS:
            if pat.search(path):
                return cat
        return "📄 App Route"

    @classmethod
    def normalize_route(cls, raw_path: str) -> Tuple[str, str]:
        """
        Returns (clean_route, base_path).
        Example: '/users/:userId/settings' -> ('/users/:userId/settings', '/users/settings')
        """
        p = raw_path.strip().split('?')[0].split('#')[0]
        p = re.sub(r'/+', '/', p)
        if len(p) > 1 and p.endswith('/'):
            p = p.rstrip('/')
        
        base_clean = re.sub(r'/(?::[a-zA-Z0-9_]+|\[[a-zA-Z0-9_]+\]|\{[a-zA-Z0-9_]+\})', '', p)
        base_clean = re.sub(r'/+', '/', base_clean)
        return p, (base_clean if base_clean else "/")

    @classmethod
    def extract_from_code(cls, code: str, script_url: str) -> List[dict]:
        results: List[dict] = []
        if not code or len(code) < 10:
            return results

        raw_candidates = set()

        # 1. JSX Route matches
        for m in cls.JSX_ROUTE_REGEX.finditer(code):
            p = m.group(1) or m.group(2) or m.group(3)
            if p and p.startswith('/'):
                raw_candidates.add(p)

        # 2. Object literal path matches
        for m in cls.OBJECT_ROUTE_REGEX.finditer(code):
            raw_candidates.add(m.group(1))

        # 3. Navigation matches
        for m in cls.NAVIGATE_REGEX.finditer(code):
            raw_candidates.add(m.group(1))

        # Deduplicate and classify
        seen_paths = set()
        for cand in raw_candidates:
            if any(cand.lower().endswith(ext) for ext in cls.STATIC_EXTENSIONS):
                continue
            if cand in ('/', '/*', '/*/', ''):
                continue

            clean_route, base_path = cls.normalize_route(cand)
            if clean_route in seen_paths or len(clean_route) < 2:
                continue
            seen_paths.add(clean_route)

            category = cls.classify_route(clean_route)
            is_privileged = category in ("🔥 Admin / Privileged", "💳 Billing & Commercial", "⚙️ Settings & Security")

            results.append({
                "path": clean_route,
                "base_path": base_path,
                "category": category,
                "is_privileged": is_privileged,
                "source_script": script_url
            })

        priority = {
            "🔥 Admin / Privileged": 0,
            "💳 Billing & Commercial": 1,
            "⚙️ Settings & Security": 2,
            "🔑 Auth & Identity": 3,
            "👥 User & Org Management": 4,
            "📊 Analytics & Reports": 5,
            "📄 App Route": 6
        }
        results.sort(key=lambda x: (priority.get(x["category"], 99), x["path"]))
        return results


class TrackerSdkExtractor:
    """
    Extracts third-party marketing, telemetry, APM, and customer support tracker IDs
    (Google Tag Manager, GA4, Sentry DSNs, Datadog, Segment, Intercom, Mixpanel, etc.)
    and generates OSINT search engine pivot links (PublicWWW, Censys, BuiltWith, Shodan).
    """
    TRACKER_SPECS = [
        {
            "name": "Google Tag Manager",
            "category": "Tag Management & Telemetry",
            "pattern": re.compile(r'\b(GTM-[A-Z0-9]{4,10})\b'),
            "risk": "info"
        },
        {
            "name": "Google Analytics 4",
            "category": "Analytics",
            "pattern": re.compile(r'\b(G-[A-Z0-9]{8,12})\b'),
            "risk": "info"
        },
        {
            "name": "Google Universal Analytics",
            "category": "Legacy Analytics",
            "pattern": re.compile(r'\b(UA-\d{4,10}-\d{1,4})\b'),
            "risk": "info"
        },
        {
            "name": "Google AdSense / Publisher",
            "category": "Monetization",
            "pattern": re.compile(r'\b((?:ca-)?pub-\d{10,20})\b'),
            "risk": "info"
        },
        {
            "name": "Segment",
            "category": "Customer Data Platform",
            "pattern": re.compile(r'\banalytics\.load\(["\']([a-zA-Z0-9]{20,40})["\']\)'),
            "risk": "low"
        },
        {
            "name": "Sentry DSN",
            "category": "Error Monitoring & APM",
            "pattern": re.compile(r'https://[a-f0-9]{32}@[a-z0-9.-]+\.sentry\.io/\d+'),
            "risk": "medium"
        },
        {
            "name": "Datadog RUM / APM",
            "category": "Telemetry & APM",
            "pattern": re.compile(r'(?:applicationId|clientToken)\s*:\s*["\']([a-f0-9-]{32,40})["\']', re.IGNORECASE),
            "risk": "low"
        },
        {
            "name": "Intercom",
            "category": "Customer Engagement",
            "pattern": re.compile(r'(?:app_id|intercomSettings\s*=\s*\{[^}]*app_id)\s*:\s*["\']([a-z0-9]{6,12})["\']', re.IGNORECASE),
            "risk": "low"
        },
        {
            "name": "Mixpanel",
            "category": "Product Analytics",
            "pattern": re.compile(r'mixpanel\.init\(["\']([a-f0-9]{32})["\']'),
            "risk": "info"
        },
        {
            "name": "Hotjar",
            "category": "Session Recording",
            "pattern": re.compile(r'\bhjid\s*:\s*(\d{5,9})\b'),
            "risk": "info"
        },
        {
            "name": "HubSpot",
            "category": "CRM & Marketing",
            "pattern": re.compile(r'(?:portalId\s*:\s*["\']?(\d{6,10})["\']?|hs-script-loader.*\/(\d{6,10})\.js)'),
            "risk": "info"
        },
        {
            "name": "Meta Pixel",
            "category": "Advertising & Tracking",
            "pattern": re.compile(r'fbq\([\'"]init[\'"],\s*[\'"](\d{12,18})[\'"]\)'),
            "risk": "info"
        },
        {
            "name": "Amplitude",
            "category": "Product Analytics",
            "pattern": re.compile(r'amplitude\.getInstance\(\)\.init\(["\']([a-f0-9]{32})["\']'),
            "risk": "info"
        },
        {
            "name": "Microsoft Clarity",
            "category": "Behavior Analytics",
            "pattern": re.compile(r'clarity\([\'"]init[\'"],\s*[\'"]([a-z0-9]{8,12})[\'"]\)'),
            "risk": "info"
        },
        {
            "name": "PostHog",
            "category": "Product Analytics",
            "pattern": re.compile(r'posthog\.init\(["\'](phc_[a-zA-Z0-9_-]{30,60})["\']'),
            "risk": "info"
        },
        {
            "name": "New Relic",
            "category": "APM & Telemetry",
            "pattern": re.compile(r'(?:accountID\s*:\s*["\']?(\d{5,10})["\']?|applicationID\s*:\s*["\']?(\d{6,12})["\']?)'),
            "risk": "low"
        }
    ]

    @staticmethod
    def generate_pivot_links(tracker_id: str) -> dict:
        clean_id = tracker_id.strip()
        encoded = urllib.parse.quote(clean_id)
        return {
            "publicwww": f"https://publicwww.com/websites/%22{encoded}%22/",
            "censys": f"https://search.censys.io/search?q=%22{encoded}%22&resource=hosts",
            "builtwith": f"https://builtwith.com/relationships/tag/{encoded}",
            "shodan": f"https://www.shodan.io/search?query=http.html:%22{encoded}%22"
        }

    @classmethod
    def extract_from_text(cls, text: str, source_url: str) -> List[dict]:
        results: List[dict] = []
        if not text or len(text) < 10:
            return results

        seen_keys = set()
        for spec in cls.TRACKER_SPECS:
            for m in spec["pattern"].finditer(text):
                tracker_id = m.group(1) if m.groups() else m.group(0)
                tracker_id = tracker_id.strip().strip('"\'`')

                if spec["name"] == "Google Tag Manager":
                    if tracker_id in ("GTM-XXXX", "GTM-XXXXXX", "GTM-TEMPLATE"):
                        continue
                elif spec["name"] == "Google Analytics 4":
                    if tracker_id in ("G-XXXXXXXX", "G-MEASUREMENT_ID"):
                        continue

                key = (spec["name"], tracker_id)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                results.append({
                    "provider": spec["name"],
                    "category": spec["category"],
                    "id": tracker_id,
                    "risk_level": spec["risk"],
                    "source_url": source_url,
                    "pivot_links": cls.generate_pivot_links(tracker_id),
                    "correlated_domains": []
                })

        return results


class DynamicJsCollectorAgent(BaseAgent):
    """
    Dynamic JavaScript Collector & Extractor Agent.
    
    Navigates to live target web applications using headless Chromium, intercepts
    all runtime network requests for JavaScript files (including Webpack chunks and
    dynamically loaded modules), retrieves full script contents, and extracts:
      1. In-scope subdomains & cloud storage assets
      2. Hidden API routes & endpoints
      3. Sensitive secrets, tokens, and credentials
      4. Exposed Source Map files (.js.map)
      5. OpenAPI / Swagger & GraphQL schemas
    """

    def __init__(self):
        super().__init__("dynamic_js_collector", "Dynamic JS Recon & Extractor")
        self.api_discovery = ApiSchemaDiscovery()
        
        # High-confidence regex for common credentials / tokens in JS
        self.secret_patterns = {
            "Google API Key": re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b'),
            "AWS Access Key": re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
            "AWS Secret Key": re.compile(r'(?i)(?:aws_secret_access_key|aws_secret_key|secret[_-]?access[_-]?key|aws_sec(?:ret)?|secret[_-]?key)[\s:=\x22\x27\`]+([A-Za-z0-9/+=]{40})(?:[^\w/+=]|$)'),
            "JWT Token": re.compile(r'\beyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*\b'),
            "Bearer Token": re.compile(r'\bBearer\s+(eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*|[A-Za-z0-9_\-\.]{25,})\b'),
            "Stripe Key": re.compile(r'\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b'),
            "Firebase Key": re.compile(r'\b[a-zA-Z0-9]{40}:APA91b[a-zA-Z0-9-_]{134}\b'),
            "Slack Webhook": re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'),
            "GitHub Token": re.compile(r'\bgh[opsu]_[0-9a-zA-Z]{36}\b'),
            "SSH Private Key": re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
        }

        # Comprehensive regex patterns for Cloud Object Storage and Providers
        self.cloud_patterns = [
            # AWS S3 (virtual-hosted style)
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.s3(?:[.-][a-zA-Z0-9\-]+)?\.amazonaws\.com\b', re.IGNORECASE),
                "provider": "AWS S3",
                "type": "virtual_host",
                "url_template": "https://{bucket}.s3.amazonaws.com/"
            },
            # AWS S3 (path-style)
            {
                "pattern": re.compile(r'(?<![.\w])s3(?:[.-][a-zA-Z0-9\-]+)?\.amazonaws\.com/([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
                "provider": "AWS S3",
                "type": "path_style",
                "url_template": "https://s3.amazonaws.com/{bucket}/"
            },
            # Google Cloud Storage (virtual-host)
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.storage\.googleapis\.com\b', re.IGNORECASE),
                "provider": "Google Cloud Storage",
                "type": "virtual_host",
                "url_template": "https://{bucket}.storage.googleapis.com/"
            },
            # Google Cloud Storage (path-style)
            {
                "pattern": re.compile(r'(?<![.\w])storage\.googleapis\.com/([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
                "provider": "Google Cloud Storage",
                "type": "path_style",
                "url_template": "https://storage.googleapis.com/{bucket}/"
            },
            # Azure Blob Storage
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.blob\.core\.windows\.net\b', re.IGNORECASE),
                "provider": "Azure Blob",
                "type": "virtual_host",
                "url_template": "https://{bucket}.blob.core.windows.net/?comp=list"
            },
            # Azure Edge CDN
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.azureedge\.net\b', re.IGNORECASE),
                "provider": "Azure Edge",
                "type": "virtual_host",
                "url_template": "https://{bucket}.azureedge.net/"
            },
            # DigitalOcean Spaces
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.([a-z0-9\-]+)\.digitaloceanspaces\.com\b', re.IGNORECASE),
                "provider": "DigitalOcean Spaces",
                "type": "do_spaces",
                "url_template": "https://{bucket}.{region}.digitaloceanspaces.com/"
            },
            # Backblaze B2 S3 API
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.s3\.[a-z0-9\-]+\.backblazeb2\.com\b', re.IGNORECASE),
                "provider": "Backblaze B2",
                "type": "virtual_host",
                "url_template": "https://{raw}/"
            },
            # Wasabi Cloud Storage
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.s3(?:[.-][a-zA-Z0-9\-]+)?\.wasabisys\.com\b', re.IGNORECASE),
                "provider": "Wasabi",
                "type": "virtual_host",
                "url_template": "https://{raw}/"
            },
            # Cloudflare R2
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.r2\.cloudflarestorage\.com\b', re.IGNORECASE),
                "provider": "Cloudflare R2",
                "type": "virtual_host",
                "url_template": "https://{bucket}.r2.cloudflarestorage.com/"
            },
            # Firebase Realtime DB
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.firebaseio\.com\b', re.IGNORECASE),
                "provider": "Firebase",
                "type": "virtual_host",
                "url_template": "https://{bucket}.firebaseio.com/.json"
            },
            # CloudFront Distributions
            {
                "pattern": re.compile(r'\b([a-zA-Z0-9_\-\.]+)\.cloudfront\.net\b', re.IGNORECASE),
                "provider": "AWS CloudFront",
                "type": "cdn",
                "url_template": "https://{bucket}.cloudfront.net/"
            },
        ]

        # Regex for API endpoints
        self.api_endpoint_regex = re.compile(
            r'(?:["\'`])((?:/api/|/v[0-9]+/|/graphql|/rest/|/auth/|/oauth/|/v[0-9]+\.[0-9]+/)[a-zA-Z0-9_\-\./?=&%#]+)(?:["\'`])'
        )

        # Source Map directive regex
        self.sourcemap_regex = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)')

    @staticmethod
    def decode_jwt(jwt_str: str) -> dict:
        """
        Decode header and payload of a JWT token using base64url.
        Preserves original raw token even if decoding fails.
        """
        parts = jwt_str.strip().split('.')
        result = {
            "type": "jwt",
            "raw": jwt_str,
            "header": None,
            "payload": None,
            "signature": parts[2] if len(parts) > 2 else "",
            "error": None
        }

        def b64url_decode(s: str) -> str:
            pad = '=' * ((4 - len(s) % 4) % 4)
            return base64.urlsafe_b64decode(s + pad).decode('utf-8', errors='replace')

        if len(parts) >= 1 and parts[0]:
            try:
                h_text = b64url_decode(parts[0])
                try:
                    result["header"] = json.loads(h_text)
                except Exception:
                    result["header"] = h_text
            except Exception as e:
                result["error"] = f"Header decode error: {e}"

        if len(parts) >= 2 and parts[1]:
            try:
                p_text = b64url_decode(parts[1])
                try:
                    result["payload"] = json.loads(p_text)
                except Exception:
                    result["payload"] = p_text
            except Exception as e:
                err_msg = f"Payload decode error: {e}"
                result["error"] = f"{result['error']}; {err_msg}" if result.get("error") else err_msg

        return result

    @staticmethod
    def decode_base64(candidate: str) -> Optional[dict]:
        """
        Validate and decode candidate base64 strings with false-positive filtering.
        Threshold: minimum 12 characters, valid length, non-hex, printable UTF-8.
        """
        cand = candidate.strip()
        if len(cand) < 12 or len(cand) % 4 == 1:
            return None
        # Reject pure hex hashes (MD5, SHA1, SHA256)
        if re.fullmatch(r'[0-9a-fA-F]+', cand):
            return None
        # Reject repetitive character strings (e.g. AAAA...)
        if len(set(cand)) <= 3:
            return None
        # Reject pure lowercase or pure uppercase alphabetic identifiers
        if cand.isalpha() and (cand.islower() or cand.isupper()):
            return None

        pad_len = (4 - len(cand) % 4) % 4
        padded = cand + ('=' * pad_len)
        try:
            raw_bytes = base64.b64decode(padded, validate=True)
            if len(raw_bytes) < 4:
                return None

            decoded_text = raw_bytes.decode('utf-8', errors='strict')
            # Check printable characters ratio (rejects binary blobs, images, compiled code)
            printable = sum(1 for c in decoded_text if 32 <= ord(c) <= 126 or c in '\r\n\t')
            if printable / len(decoded_text) < 0.90:
                return None

            trimmed = decoded_text.strip()
            if len(trimmed) < 3:
                return None

            category = "text"
            parsed_json = None
            if (trimmed.startswith('{') and trimmed.endswith('}')) or (trimmed.startswith('[') and trimmed.endswith(']')):
                try:
                    parsed_json = json.loads(trimmed)
                    category = "json"
                except Exception:
                    pass
            elif re.match(r'^https?://', trimmed) or (trimmed.startswith('/') and '/' in trimmed[1:]):
                category = "url"
            elif any(k in trimmed.lower() for k in ["bearer ", "token", "key=", "secret", "password", "api_key", "auth:"]):
                category = "credential"

            return {
                "type": "base64",
                "category": category,
                "raw": cand,
                "decoded": trimmed,
                "json": parsed_json,
                "error": None
            }
        except Exception:
            return None

    async def probe_cloud_asset(self, client: httpx.AsyncClient, asset_info: dict) -> dict:
        """
        Active security probe for a discovered cloud storage asset.
        Evaluates whether the bucket is:
          - 'open': publicly readable / directory listing exposed (ALERT)
          - 'vulnerable_takeover': 404 NoSuchBucket, claimable/hijackable (ALERT)
          - 'secured': 401/403 AccessDenied or private (NO ALERT per configuration)
          - 'cdn': CDN distribution endpoint
        """
        probe_url = asset_info["probe_url"]
        provider = asset_info["provider"]
        raw = asset_info["raw"]

        result = {
            **asset_info,
            "status": "secured",
            "http_status": None,
            "is_open": False,
            "is_takeover": False,
            "is_secured": False,
            "details": ""
        }

        # Don't probe CloudFront distributions for bucket directory listing
        if provider == "AWS CloudFront" or asset_info.get("type") == "cdn":
            result["status"] = "cdn"
            result["is_secured"] = True
            result["details"] = "CDN distribution endpoint"
            return result

        try:
            res = await client.get(
                probe_url,
                timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                follow_redirects=True
            )
            result["http_status"] = res.status_code
            text = res.text[:2500]

            if provider in ["AWS S3", "DigitalOcean Spaces", "Backblaze B2", "Wasabi", "Cloudflare R2"]:
                if res.status_code == 200 and ("<ListBucketResult" in text or "<ListAllMyBucketsResult" in text or "<Key>" in text):
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Public directory listing allowed (HTTP 200). Objects and keys readable unauthenticated."
                elif res.status_code == 404 and ("<Code>NoSuchBucket</Code>" in text or "BucketDoesNotExist" in text):
                    result["status"] = "vulnerable_takeover"
                    result["is_takeover"] = True
                    result["details"] = "Bucket does not exist (HTTP 404 NoSuchBucket). Dangling reference vulnerable to bucket takeover."
                elif res.status_code in [401, 403] or "<Code>AccessDenied</Code>" in text:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"Bucket is private and protected (HTTP {res.status_code} AccessDenied)."
                else:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"HTTP {res.status_code} (access restricted)."

            elif provider == "Google Cloud Storage":
                if res.status_code == 200 and ("<ListBucketResult" in text or '"items":' in text):
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "GCS bucket is publicly listable (HTTP 200)."
                elif res.status_code == 404 and ("NoSuchBucket" in text or "Not Found" in text):
                    result["status"] = "vulnerable_takeover"
                    result["is_takeover"] = True
                    result["details"] = "GCS bucket does not exist (HTTP 404). Vulnerable to bucket claiming/takeover."
                else:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"GCS bucket is private/restricted (HTTP {res.status_code})."

            elif provider == "Azure Blob":
                if res.status_code == 200 and "<EnumerationResults" in text:
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Azure Blob container allows public enumeration (HTTP 200)."
                elif res.status_code == 404 and ("AccountNotFound" in text or "ResourceNotFound" in text):
                    result["status"] = "vulnerable_takeover"
                    result["is_takeover"] = True
                    result["details"] = "Azure storage account not found (HTTP 404). Potential bucket takeover."
                else:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"Azure Blob is private/restricted (HTTP {res.status_code})."

            elif provider == "Firebase":
                if res.status_code == 200 and "error" not in text and text.strip() not in ["null", ""]:
                    result["status"] = "open"
                    result["is_open"] = True
                    result["details"] = "Firebase Realtime DB allows public unauthenticated reads (HTTP 200)."
                elif "Permission denied" in text or res.status_code in [401, 403]:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = "Firebase security rules active (Permission denied)."
                else:
                    result["status"] = "secured"
                    result["is_secured"] = True
                    result["details"] = f"Firebase restricted (HTTP {res.status_code})."

            else:
                result["status"] = "secured"
                result["is_secured"] = True
                result["details"] = f"HTTP {res.status_code}"

        except Exception as e:
            # Network failure or timeout: treat as non-accessible / secured to avoid false alarms
            result["status"] = "secured"
            result["is_secured"] = True
            result["details"] = f"Probe connection error: {str(e)}"

        return result

    async def capture_via_crawler(self, url: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Direct high-speed network crawler: fetches HTML with modern browser headers,
        extracts all external script sources, preloaded module scripts, and inline
        scripts, and recursively discovers dynamic JavaScript chunks.
        Returns (captured_scripts, captured_html_pages).
        """
        captured: Dict[str, str] = {}
        captured_html: Dict[str, str] = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0, headers=headers) as client:
                res = await client.get(url)
                if res.status_code != 200 and res.status_code != 304:
                    return captured, captured_html
                
                base_url = str(res.url)
                html = res.text
                captured_html[base_url] = html
                
                # 1. Extract inline scripts
                inline_matches = re.findall(r'<script(?:\s+[^>]*)?>([\s\S]*?)</script>', html, re.IGNORECASE)
                for idx, code in enumerate(inline_matches):
                    code_clean = code.strip()
                    if len(code_clean) >= 25:
                        captured[f"{base_url}#inline-script-{idx+1}"] = code_clean

                # 2. Extract external script tags & modulepreloads
                script_urls = set()
                for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                    src = match.group(1).strip()
                    if src and not src.startswith("data:"):
                        script_urls.add(urllib.parse.urljoin(base_url, src))
                
                for match in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\'][^>]+(?:rel=["\'](?:modulepreload|preload)["\']|as=["\']script["\'])', html, re.IGNORECASE):
                    href = match.group(1).strip()
                    if href and not href.startswith("data:"):
                        script_urls.add(urllib.parse.urljoin(base_url, href))
                
                for match in re.finditer(r'<link[^>]+(?:rel=["\'](?:modulepreload|preload)["\']|as=["\']script["\'])[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
                    href = match.group(1).strip()
                    if href and not href.startswith("data:"):
                        script_urls.add(urllib.parse.urljoin(base_url, href))

                # 3. Fetch external scripts concurrently
                async def fetch_one(s_url):
                    try:
                        r = await client.get(s_url, timeout=12.0)
                        if r.status_code == 200 and r.text:
                            return s_url, r.text
                    except Exception:
                        pass
                    return s_url, None

                if script_urls:
                    tasks = [fetch_one(u) for u in script_urls]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for res_tuple in results:
                        if isinstance(res_tuple, tuple) and res_tuple[1]:
                            s_url, text = res_tuple
                            captured[s_url] = text

                # 4. Secondary dynamic chunk discovery from downloaded scripts
                chunk_urls = set()
                chunk_pattern = re.compile(r'["\']((?:/(?:static|assets|chunks|js)/|[a-zA-Z0-9_\-\.]+/)[a-zA-Z0-9_\-\.]+\.(?:chunk\.)?js(?:\?[^"\']*)?)["\']')
                for s_url, text in list(captured.items()):
                    for m in chunk_pattern.finditer(text):
                        rel = m.group(1)
                        if not rel.startswith("http") and not rel.startswith("//"):
                            full = urllib.parse.urljoin(s_url, rel)
                            if full not in captured:
                                chunk_urls.add(full)

                if chunk_urls:
                    chunk_tasks = [fetch_one(u) for u in list(chunk_urls)[:30]]
                    chunk_results = await asyncio.gather(*chunk_tasks, return_exceptions=True)
                    for res_tuple in chunk_results:
                        if isinstance(res_tuple, tuple) and res_tuple[1]:
                            s_url, text = res_tuple
                            captured[s_url] = text

        except Exception as e:
            logger.debug(f"Crawler script extraction exception for {url}: {e}")

        return captured, captured_html

    async def capture_dynamic_scripts(self, url: str, timeout_ms: int = 15000) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Capture all JavaScript files requested by target URL and page HTML.
        Executes hybrid interception: runs Playwright headless browser for runtime scripts,
        augmented with direct high-speed HTTP chunk & script crawling.
        Returns (captured_scripts, captured_html_pages).
        """
        captured_scripts: Dict[str, str] = {}
        captured_html: Dict[str, str] = {}
        
        # 1. Direct Network & Chunk Crawler (Fast & Resilient)
        crawler_scripts, crawler_html = await self.capture_via_crawler(url)
        captured_scripts.update(crawler_scripts)
        captured_html.update(crawler_html)
        logger.info(f"Direct crawler captured {len(crawler_scripts)} JavaScript sources and {len(crawler_html)} HTML pages from {url}")

        # 2. Attempt Headless Browser Interception (to catch deferred Webpack/Vite runtime requests)
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    executable_path="/usr/bin/chromium",
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--single-process",
                        "--disable-blink-features=AutomationControlled",
                        "--ignore-certificate-errors",
                        "--ignore-ssl-errors=yes",
                        "--ignore-certificate-errors-spki-list",
                        "--allow-insecure-localhost",
                        "--allow-running-insecure-content",
                        "--disable-web-security"
                    ]
                )
                
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                    viewport={"width": 1280, "height": 800},
                    ignore_https_errors=True
                )
                
                page = await context.new_page()

                async def on_response(response):
                    try:
                        ct = response.headers.get("content-type", "").lower()
                        req_type = response.request.resource_type
                        clean_url = response.url.split("?")[0].lower()
                        
                        is_js = (
                            "javascript" in ct
                            or req_type == "script"
                            or clean_url.endswith(".js")
                            or clean_url.endswith(".mjs")
                        )
                        
                        if is_js and response.status == 200:
                            body_text = await response.text()
                            if body_text and len(body_text.strip()) > 0:
                                captured_scripts[response.url] = body_text
                    except Exception:
                        pass

                page.on("response", on_response)

                try:
                    logger.info(f"Navigating to {url} to capture dynamic scripts...")
                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                    try:
                        await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
                    except Exception:
                        pass
                    await asyncio.sleep(2)
                    
                    try:
                        dom_html = await page.content()
                        if dom_html and len(dom_html.strip()) > 50:
                            captured_html[page.url] = dom_html
                    except Exception:
                        pass
                except Exception as e:
                    logger.debug(f"Browser navigation notice for {url}: {e}")
                finally:
                    await browser.close()
        except Exception as e:
            logger.debug(f"Headless browser notice for {url}: {e}")

        logger.info(f"Total JavaScript files collected from {url}: {len(captured_scripts)}, HTML documents: {len(captured_html)}")
        return captured_scripts, captured_html

    def extract_from_script(self, script_url: str, content: str, root_domain: str, target_url: str = "") -> dict:
        """
        Analyze the full text of a JavaScript file for subdomains, endpoints,
        secrets, and source map references.
        """
        subdomains: Set[str] = set()
        cloud_assets: Set[str] = set()
        endpoints: Dict[str, dict] = {}
        secrets: List[dict] = []
        sourcemaps: List[str] = []

        # Determine origin domain / base URL for relative paths
        is_inline = "#inline-script-" in script_url
        clean_script_url = script_url.split("#inline-script-")[0]
        parsed_script = urllib.parse.urlparse(clean_script_url)
        script_host = parsed_script.hostname or ""

        target_base = target_url.rstrip("/") if target_url else ""
        if target_base:
            parsed_target = urllib.parse.urlparse(target_base)
            target_host = parsed_target.hostname or ""
            target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        else:
            target_host = ""
            target_origin = ""

        # Check if the script itself is 1st-party
        is_first_party_script = is_inline or (
            script_host == root_domain
            or script_host.endswith("." + root_domain)
            or (target_host and (script_host == target_host or script_host.endswith("." + target_host)))
        )

        # 1. In-Scope Subdomains: *.root_domain
        escaped_root = re.escape(root_domain)
        subdomain_pattern = re.compile(
            rf'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?)*\.{escaped_root})\b',
            re.IGNORECASE
        )
        for match in subdomain_pattern.finditer(content):
            sub = match.group(1).lower().strip(".")
            if sub and sub != root_domain:
                subdomains.add(sub)

        # 2. Third-Party Cloud Assets & Object Storage Buckets
        cloud_assets_dict: Dict[str, dict] = {}
        for rule in self.cloud_patterns:
            for match in rule["pattern"].finditer(content):
                raw_match = match.group(0).lower().strip("/")
                bucket_name = match.group(1).lower()

                # Filter out common false-positive names / noise
                if bucket_name in ["s3", "storage", "blob", "com", "www", "static", "assets", "public", "dev", "prod", "null", "undefined"]:
                    continue

                if rule["type"] == "do_spaces":
                    region = match.group(2).lower()
                    probe_url = rule["url_template"].format(bucket=bucket_name, region=region)
                elif "{bucket}" in rule["url_template"]:
                    probe_url = rule["url_template"].format(bucket=bucket_name)
                else:
                    probe_url = rule["url_template"].format(raw=raw_match)

                cloud_assets_dict[raw_match] = {
                    "raw": raw_match,
                    "bucket_name": bucket_name,
                    "provider": rule["provider"],
                    "probe_url": probe_url,
                    "type": rule["type"]
                }

        # 3. API Endpoints
        # Helper to register an endpoint
        def add_endpoint(full_url: str, path: str, host: str, is_in_scope: bool):
            if full_url and full_url not in endpoints:
                endpoints[full_url] = {
                    "url": full_url,
                    "path": path,
                    "host": host,
                    "is_in_scope": is_in_scope,
                    "source_script": script_url
                }

        # 3a. From relative quoted paths
        for match in self.api_endpoint_regex.finditer(content):
            ep_path = match.group(1)
            if len(ep_path) < 150 and not ep_path.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.svg', '.woff', '.woff2', '.ttf')):
                # Ensure clean path format
                clean_path = ep_path if ep_path.startswith('/') else f"/{ep_path}"
                if is_first_party_script:
                    base_origin = target_origin or f"https://{root_domain}"
                    host = target_host or root_domain
                    full_url = f"{base_origin}{clean_path}"
                    add_endpoint(full_url, clean_path, host, True)
                else:
                    # 3rd-party vendor script (e.g., gstatic.com / recaptcha, cookielaw.org)
                    script_origin = f"{parsed_script.scheme}://{parsed_script.netloc}" if parsed_script.netloc else ""
                    full_url = f"{script_origin}{clean_path}" if script_origin else clean_path
                    add_endpoint(full_url, clean_path, script_host, False)

        # 3b. From absolute URLs
        abs_urls = re.findall(r'https?://[^\s"\'`<>]+', content)
        for u in abs_urls:
            try:
                parsed = urllib.parse.urlparse(u)
                path = parsed.path
                if any(path.startswith(prefix) for prefix in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/auth/', '/oauth/']):
                    full_ep_url = u.split('#')[0]
                    u_host = parsed.hostname or ""
                    is_scope = (
                        u_host == root_domain
                        or u_host.endswith("." + root_domain)
                        or (target_host and (u_host == target_host or u_host.endswith("." + target_host)))
                    )
                    if len(full_ep_url) < 250:
                        add_endpoint(full_ep_url, path, u_host, is_scope)
            except Exception:
                pass

        # 4. Secrets
        for sec_name, pattern in self.secret_patterns.items():
            for match in pattern.finditer(content):
                m_str = match.group(0).strip()
                if match.groups():
                    m_str = match.group(1).strip()
                
                # Strip wrapping quotes
                m_str = m_str.strip('"\'`')

                # Reject URLs, file paths, and assets
                if m_str.startswith(("http://", "https://", "/", "./", "../")) or "://" in m_str:
                    continue
                if any(m_str.lower().endswith(ext) for ext in [".js", ".css", ".html", ".png", ".jpg", ".jpeg", ".svg", ".json", ".map", ".wasm"]):
                    continue

                # Reject code identifiers, function names, and common false positives
                low = m_str.lower()
                if any(kw in low for kw in ["recaptcha", "challenge", "qrcode", "hidden", "javascript", "function", "undefined", "null", "placeholder", "default"]):
                    continue

                # Bearer Token validation
                if sec_name == "Bearer Token":
                    token_part = m_str[7:].strip() if m_str.lower().startswith("bearer ") else m_str
                    if token_part.lower() in ["token", "undefined", "null", "string", "test", "bearer", "accesstoken", "access_token", "jwt", "auth"]:
                        continue
                    if len(token_part) < 20:
                        continue

                # Reject pure alphabetical camelCase/PascalCase identifiers
                if re.match(r'^[a-zA-Z]+$', m_str) and sec_name not in ["SSH Private Key"]:
                    continue

                if len(m_str) >= 8 and not any(ch in m_str for ch in ["{", "}", "[", "]", ";", " "]):
                    # Real AWS Secret Keys are base64-encoded random bytes (160-bit) with high entropy
                    if sec_name == "AWS Secret Key":
                        if not (any(c.isupper() for c in m_str) and any(c.islower() for c in m_str) and any(c.isdigit() for c in m_str)):
                            continue

                    # Capture surrounding context for precise location & searching
                    start_idx = max(0, match.start() - 70)
                    end_idx = min(len(content), match.end() + 70)
                    raw_context = content[start_idx:end_idx].replace('\r', ' ').replace('\n', ' ').strip()

                    secrets.append({
                        "type": sec_name,
                        "value": m_str,
                        "source_script": script_url,
                        "context": raw_context
                    })

        # 5. Source Maps
        for match in self.sourcemap_regex.finditer(content):
            map_ref = match.group(1).strip()
            # If relative, resolve against script_url
            full_map_url = urllib.parse.urljoin(script_url, map_ref)
            sourcemaps.append(full_map_url)

        # 6. JWT Tokens (extract, decode header & payload, preserve raw even if decoding error)
        jwt_pattern = self.secret_patterns.get("JWT Token")
        seen_jwt_raw = set()
        jwts: List[dict] = []
        if jwt_pattern:
            for m in jwt_pattern.findall(content):
                jwt_str = str(m).strip()
                if jwt_str not in seen_jwt_raw and len(jwt_str) > 20:
                    seen_jwt_raw.add(jwt_str)
                    jwt_obj = self.decode_jwt(jwt_str)
                    jwt_obj["source_script"] = script_url
                    jwts.append(jwt_obj)

        # 7. Base64 Strings (extract, decode, validate, and preserve high-value tokens)
        base64_strings: List[dict] = []
        seen_b64_raw = set()

        # Match quoted candidate strings of length >= 12
        for match in re.finditer(r'["\'`]([A-Za-z0-9+/]{12,}={0,2})["\'`]', content):
            cand = match.group(1).strip()
            if cand in seen_b64_raw or cand in seen_jwt_raw or cand.startswith('eyJ'):
                continue
            seen_b64_raw.add(cand)
            b64_info = self.decode_base64(cand)
            if b64_info:
                b64_info["source_script"] = script_url
                base64_strings.append(b64_info)
                # If the decoded string is an API endpoint or URL, add it to endpoints
                dec_text = b64_info.get("decoded", "")
                if dec_text.startswith("http://") or dec_text.startswith("https://"):
                    try:
                        parsed_u = urllib.parse.urlparse(dec_text)
                        u_host = parsed_u.hostname or ""
                        is_scope = (
                            u_host == root_domain
                            or u_host.endswith("." + root_domain)
                            or (target_host and (u_host == target_host or u_host.endswith("." + target_host)))
                        )
                        add_endpoint(dec_text, parsed_u.path or "/", u_host, is_scope)
                    except Exception:
                        pass
                elif dec_text.startswith("/") and len(dec_text) < 150 and not dec_text.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.svg', '.woff', '.ttf')):
                    base_origin = target_origin or f"https://{root_domain}"
                    add_endpoint(f"{base_origin}{dec_text}", dec_text, target_host or root_domain, is_first_party_script)

        # Also check for HTTP Authorization Basic headers or atob() calls
        for match in re.finditer(r'(?:Basic\s+|atob\s*\(\s*["\'`])([A-Za-z0-9+/=]{8,})', content, re.IGNORECASE):
            cand = match.group(1).strip()
            if cand not in seen_b64_raw and cand not in seen_jwt_raw and not cand.startswith('eyJ'):
                seen_b64_raw.add(cand)
                b64_info = self.decode_base64(cand)
                if not b64_info:
                    # Keep high-value token even if non-printable
                    b64_info = {
                        "type": "base64",
                        "category": "credential",
                        "raw": cand,
                        "decoded": None,
                        "error": "Non-standard or binary encoding"
                    }
                b64_info["source_script"] = script_url
                base64_strings.append(b64_info)

        return {
            "subdomains": sorted(list(subdomains)),
            "cloud_assets": list(cloud_assets_dict.values()),
            "endpoints": list(endpoints.values()),
            "secrets": secrets,
            "sourcemaps": sourcemaps,
            "jwts": jwts,
            "base64_strings": base64_strings,
        }

    async def correlate_trackers_in_workspace(self, trackers: List[dict], current_target: str, root_domain: str) -> List[dict]:
        """
        Cross-correlate tracker IDs across all web applications and domains in the database
        to uncover shared tracking infrastructure, shadow portals, or related subdomains.
        """
        if not trackers:
            return trackers

        tracker_ids = [t["id"] for t in trackers if t.get("id")]
        if not tracker_ids:
            return trackers

        try:
            matches_by_id = {t_id: set() for t_id in tracker_ids}
            cursor = self.domains_col.find(
                {
                    "$or": [
                        {"web_applications.dynamic_js.trackers.id": {"$in": tracker_ids}},
                        {"web_applications.trackers.id": {"$in": tracker_ids}},
                        {"infrastructure.dynamic_js.trackers.id": {"$in": tracker_ids}}
                    ]
                },
                {
                    "domain": 1,
                    "web_applications.target": 1,
                    "web_applications.url": 1,
                    "web_applications.dynamic_js.trackers": 1,
                    "web_applications.trackers": 1,
                    "infrastructure.dynamic_js.trackers": 1
                }
            )

            async for doc in cursor:
                d_name = doc.get("domain", "")
                for app in doc.get("web_applications", []):
                    app_target = app.get("target") or app.get("url") or d_name
                    if app_target:
                        app_target = app_target.strip().lower()
                    app_trackers = (app.get("dynamic_js", {}) or {}).get("trackers", []) + (app.get("trackers", []) or [])
                    for at in app_trackers:
                        at_id = at.get("id")
                        if at_id in matches_by_id and app_target and app_target != current_target.strip().lower():
                            matches_by_id[at_id].add(app_target)

                infra_trackers = (doc.get("infrastructure", {}) or {}).get("dynamic_js", {}).get("trackers", [])
                for it in infra_trackers:
                    it_id = it.get("id")
                    if it_id in matches_by_id and d_name and d_name.lower() != current_target.strip().lower():
                        matches_by_id[it_id].add(d_name)

            for t in trackers:
                matched = sorted(list(matches_by_id.get(t["id"], set())))
                t["correlated_domains"] = matched
        except Exception as e:
            logger.debug(f"Tracker workspace correlation error: {e}")

        return trackers

    async def process_tasks(self):
        """Process queued dynamic_js_extract tasks."""
        task = await self.get_next_task("dynamic_js_extract")
        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        target_url = task.get("url")

        if not target_url:
            target_url = f"https://{target}"

        logger.info(f"Starting Dynamic JS Extraction on {target_url} (Root: {root_domain})")

        try:
            # 1. Capture dynamic scripts and HTML via headless browser & direct crawler
            scripts, html_pages = await self.capture_dynamic_scripts(target_url)
            
            # If HTTPS fails with 0 scripts and 0 html, attempt HTTP fallback
            if not scripts and not html_pages and target_url.startswith("https://"):
                fallback_url = f"http://{target}"
                logger.info(f"No scripts or HTML captured on HTTPS, trying HTTP fallback: {fallback_url}")
                scripts, html_pages = await self.capture_dynamic_scripts(fallback_url)
                if scripts or html_pages:
                    target_url = fallback_url

            # 2. Extract HTML and JavaScript comments
            all_comments: List[dict] = []
            for page_url, html_content in html_pages.items():
                try:
                    html_comments = CommentExtractor.extract_html_comments(html_content, page_url)
                    all_comments.extend(html_comments)
                except Exception as ce:
                    logger.debug(f"Error extracting HTML comments from {page_url}: {ce}")

            for script_url, js_content in scripts.items():
                try:
                    js_comments = CommentExtractor.extract_js_comments(js_content, script_url)
                    all_comments.extend(js_comments)
                except Exception as ce:
                    logger.debug(f"Error extracting JS comments from {script_url}: {ce}")

            # Deduplicate comments
            seen_comments = set()
            unique_comments = []
            for c in all_comments:
                if c["category"] == "License":
                    key = ("license", c["content"])
                else:
                    key = (c["type"], c["content"], c["source_url"])
                if key in seen_comments:
                    continue
                seen_comments.add(key)
                unique_comments.append(c)

            category_priority = {
                "High Interest": 0,
                "Developer Note": 1,
                "Route / Endpoint": 2,
                "General": 3,
                "License": 4
            }
            unique_comments.sort(key=lambda x: category_priority.get(x["category"], 99))
            final_comments = unique_comments[:500]
            high_interest_count = sum(1 for c in final_comments if c["category"] == "High Interest")
            dev_notes_count = sum(1 for c in final_comments if c["category"] == "Developer Note")
            interesting_count = sum(1 for c in final_comments if c.get("is_interesting"))
            logger.info(f"Extracted {len(final_comments)} comments ({interesting_count} interesting, {high_interest_count} high-interest) from {target}")

            # Alert on critical sensitive comments
            critical_comment_secrets = [
                c for c in final_comments
                if c["category"] == "High Interest"
                and any(k in c["content"].lower() for k in ["password", "passwd", "secret", "private_key", "bearer", "api_key", "apikey", "credential"])
            ]
            for hc in critical_comment_secrets[:5]:
                await self.create_alert(
                    title=f"Sensitive Comment in Client Source: {hc['source_name']}",
                    description=f"Potential credential or sensitive note found in {hc['type'].upper()} comment on {target}.",
                    target=target,
                    risk_level="high",
                    details=(
                        f"**Target:** {target}\n"
                        f"**Source File:** [{hc['source_url']}]({hc['source_url']})\n"
                        f"**Line Number:** {hc['line_number']}\n"
                        f"**Comment Type:** `{hc['type']}`\n\n"
                        f"**Extracted Comment:**\n```\n{hc['content'][:400]}\n```"
                    ),
                    exploitation_suggestions=(
                        "1. Review comment content for leaked credentials, private keys, or internal API routes.\n"
                        "2. If passwords or tokens are exposed, rotate credentials immediately.\n"
                        "3. Strip developer comments and debug notes in production build pipelines (e.g., using Terser or SWC)."
                    ),
                    alert_type="sensitive_comment_leak"
                )

            # 3. Extract HTML <meta> tags
            all_meta_tags: List[dict] = []
            for page_url, html_content in html_pages.items():
                try:
                    meta_tags = MetaTagExtractor.extract_meta_tags(html_content, page_url)
                    all_meta_tags.extend(meta_tags)
                except Exception as me:
                    logger.debug(f"Error extracting <meta> tags from {page_url}: {me}")

            # Deduplicate meta tags by (key, content)
            seen_meta = set()
            unique_meta_tags = []
            for m in all_meta_tags:
                meta_key = (m.get("key", "").lower().strip(), m.get("content", "").strip())
                if meta_key in seen_meta:
                    continue
                seen_meta.add(meta_key)
                unique_meta_tags.append(m)

            meta_category_priority = {
                "Security & Verification": 0,
                "Framework & Build": 1,
                "Author & Ownership": 2,
                "OpenGraph & Social": 3,
                "SEO & Indexing": 4,
                "Standard / Config": 5
            }
            unique_meta_tags.sort(key=lambda x: meta_category_priority.get(x["category"], 99))
            final_meta_tags = unique_meta_tags[:300]
            interesting_meta_count = sum(1 for m in final_meta_tags if m.get("is_interesting"))
            logger.info(f"Extracted {len(final_meta_tags)} <meta> tags ({interesting_meta_count} interesting) from {target}")

            # 4. Extract SSR & Hydration State Payloads (__NEXT_DATA__, __NUXT_DATA__, __INITIAL_STATE__, __APOLLO_STATE__, __remixContext)
            all_hydration_payloads: List[dict] = []
            all_trackers: List[dict] = []

            for page_url, html_content in html_pages.items():
                try:
                    h_payloads = HydrationStateExtractor.extract_from_html(html_content, page_url)
                    all_hydration_payloads.extend(h_payloads)
                except Exception as he:
                    logger.debug(f"Error extracting hydration payloads from {page_url}: {he}")

                try:
                    html_trackers = TrackerSdkExtractor.extract_from_text(html_content, page_url)
                    all_trackers.extend(html_trackers)
                except Exception as te:
                    logger.debug(f"Error extracting trackers from HTML {page_url}: {te}")

            if all_hydration_payloads:
                logger.info(f"Extracted {len(all_hydration_payloads)} hydration/state payloads from {target}")

            all_subdomains: Set[str] = set()
            all_cloud_assets: Dict[str, dict] = {}
            all_endpoints: Dict[str, dict] = {}
            all_secrets: List[dict] = []
            all_sourcemaps: List[str] = []
            all_jwts: Dict[str, dict] = {}
            all_base64: Dict[str, dict] = {}
            all_client_routes: List[dict] = []
            script_summaries: List[dict] = []

            # 5. Analyze all captured scripts
            for script_url, content in scripts.items():
                analysis = self.extract_from_script(script_url, content, root_domain, target_url=target_url)
                
                all_subdomains.update(analysis["subdomains"])
                for ca in analysis["cloud_assets"]:
                    all_cloud_assets[ca["raw"]] = ca
                for ep_item in analysis["endpoints"]:
                    ep_url = ep_item["url"]
                    if ep_url not in all_endpoints:
                        all_endpoints[ep_url] = ep_item
                all_secrets.extend(analysis["secrets"])
                all_sourcemaps.extend(analysis["sourcemaps"])
                for j in analysis.get("jwts", []):
                    if j["raw"] not in all_jwts:
                        all_jwts[j["raw"]] = j
                for b in analysis.get("base64_strings", []):
                    if b["raw"] not in all_base64:
                        all_base64[b["raw"]] = b

                # Extract Client-Side SPA Routes
                try:
                    c_routes = ClientRouterExtractor.extract_from_code(content, script_url)
                    all_client_routes.extend(c_routes)
                except Exception as cre:
                    logger.debug(f"Error extracting client routes from {script_url}: {cre}")

                # Extract Trackers & SDK telemetry IDs
                try:
                    js_trackers = TrackerSdkExtractor.extract_from_text(content, script_url)
                    all_trackers.extend(js_trackers)
                except Exception as te:
                    logger.debug(f"Error extracting trackers from script {script_url}: {te}")

                script_summaries.append({
                    "url": script_url,
                    "is_inline": "#inline-script-" in script_url,
                    "size_bytes": len(content),
                    "subdomains_found": len(analysis["subdomains"]),
                    "endpoints_found": len(analysis["endpoints"]),
                    "secrets_found": len(analysis["secrets"]),
                    "jwts_found": len(analysis.get("jwts", [])),
                    "base64_found": len(analysis.get("base64_strings", [])),
                    "has_sourcemap": len(analysis["sourcemaps"]) > 0,
                })

            # Deduplicate and sort client routes
            seen_cr = set()
            unique_client_routes = []
            for cr in all_client_routes:
                p = cr["path"]
                if p in seen_cr:
                    continue
                seen_cr.add(p)
                unique_client_routes.append(cr)

            # Deduplicate and workspace-correlate trackers
            seen_trackers = set()
            unique_trackers = []
            for tr in all_trackers:
                t_key = (tr["provider"], tr["id"])
                if t_key in seen_trackers:
                    continue
                seen_trackers.add(t_key)
                unique_trackers.append(tr)

            if unique_trackers:
                unique_trackers = await self.correlate_trackers_in_workspace(unique_trackers, target, root_domain)
                logger.info(f"Identified {len(unique_trackers)} unique tracker/telemetry SDK IDs on {target}")

            # Merge Client SPA routes & Hydration routes into global endpoint catalog
            target_base = target_url.rstrip("/") if target_url else ""
            if target_base:
                parsed_t = urllib.parse.urlparse(target_base)
                target_origin = f"{parsed_t.scheme}://{parsed_t.netloc}"
                target_host = parsed_t.hostname or target
            else:
                target_origin = f"https://{target}"
                target_host = target

            for cr in unique_client_routes:
                clean_p = cr["path"]
                full_ep_url = f"{target_origin}{clean_p}"
                if full_ep_url not in all_endpoints:
                    all_endpoints[full_ep_url] = {
                        "url": full_ep_url,
                        "path": clean_p,
                        "host": target_host,
                        "is_in_scope": True,
                        "source_script": cr.get("source_script", ""),
                        "category": cr.get("category", "📄 App Route"),
                        "discovered_via": "client_spa_router"
                    }

            for hyd in all_hydration_payloads:
                for r in hyd.get("routes", []):
                    clean_p = r if r.startswith('/') else f"/{r}"
                    full_ep_url = f"{target_origin}{clean_p}"
                    if full_ep_url not in all_endpoints:
                        all_endpoints[full_ep_url] = {
                            "url": full_ep_url,
                            "path": clean_p,
                            "host": target_host,
                            "is_in_scope": True,
                            "source_script": hyd.get("source_url", ""),
                            "category": "Hydration Route",
                            "discovered_via": "hydration_payload"
                        }
                for ep in hyd.get("api_endpoints", []):
                    clean_p = ep if ep.startswith('/') else (urllib.parse.urlparse(ep).path if ep.startswith('http') else f"/{ep}")
                    full_ep_url = ep if ep.startswith('http') else f"{target_origin}{clean_p}"
                    if full_ep_url not in all_endpoints:
                        all_endpoints[full_ep_url] = {
                            "url": full_ep_url,
                            "path": clean_p,
                            "host": target_host,
                            "is_in_scope": True,
                            "source_script": hyd.get("source_url", ""),
                            "category": "Hydration API Endpoint",
                            "discovered_via": "hydration_payload"
                        }

            # Active Cloud Storage Permission Probing
            probed_cloud_assets: List[dict] = []
            if all_cloud_assets:
                logger.info(f"Active probing {len(all_cloud_assets)} discovered cloud storage assets for {target}...")
                async with httpx.AsyncClient(verify=False, timeout=10.0) as probe_client:
                    probe_tasks = [self.probe_cloud_asset(probe_client, ca) for ca in all_cloud_assets.values()]
                    probed_results = await asyncio.gather(*probe_tasks, return_exceptions=True)
                    for res in probed_results:
                        if isinstance(res, dict):
                            probed_cloud_assets.append(res)

            # 3. Auto-Register newly discovered subdomains into MongoDB and Queue for Scanning
            new_subdomains_added = 0
            if all_subdomains:
                domain_doc = await self.domains_col.find_one({"domain": root_domain})
                is_single = (domain_doc or {}).get("single_domain_only", False)

                if not is_single:
                    existing_subs = set()
                    if domain_doc:
                        infra = domain_doc.get("infrastructure", {})
                        if isinstance(infra, dict):
                            for s in infra.get("subdomains", []):
                                if isinstance(s, dict) and s.get("name"):
                                    existing_subs.add(s["name"].strip().lower())
                                elif isinstance(s, str) and s.strip():
                                    existing_subs.add(s.strip().lower())
                        for s in domain_doc.get("subdomains", []):
                            if isinstance(s, dict) and s.get("subdomain"):
                                existing_subs.add(s["subdomain"].strip().lower())
                            elif isinstance(s, str) and s.strip():
                                existing_subs.add(s.strip().lower())
                        for sys_item in domain_doc.get("systems", []):
                            if isinstance(sys_item, dict) and sys_item.get("target"):
                                existing_subs.add(sys_item["target"].strip().lower())
                        for w in domain_doc.get("web_applications", []):
                            if isinstance(w, dict) and w.get("target"):
                                existing_subs.add(w["target"].strip().lower())

                    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    subs_to_push = []
                    tasks_to_queue = []

                    for s in all_subdomains:
                        s_clean = s.strip().lower().rstrip(".")
                        # Strict scope check: must strictly match root_domain (*.root_domain)
                        if not self.is_in_scope(s_clean, root_domain, single_domain_only=False):
                            continue
                        if s_clean == root_domain.strip().lower():
                            continue
                        # Deduplication: avoid duplicates
                        if s_clean in existing_subs:
                            continue

                        existing_subs.add(s_clean)
                        subs_to_push.append({
                            "name": s_clean,
                            "added_at": now_str,
                            "discovered_by": "dynamic_js_collector"
                        })

                        # Queue for verification/scan if not already queued
                        exists_task = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": s_clean,
                            "task_type": {"$in": ["verification", "scan"]}
                        })
                        if not exists_task:
                            tasks_to_queue.append({
                                "root_domain": root_domain,
                                "target": s_clean,
                                "task_type": "verification",
                                "status": "pending",
                                "priority": 0,
                                "created_at": datetime.datetime.utcnow()
                            })

                    if subs_to_push:
                        new_subdomains_added = 0
                        for sub_item in subs_to_push:
                            res = await self.domains_col.update_one(
                                {"domain": root_domain, "infrastructure.subdomains.name": {"$ne": sub_item["name"]}},
                                {"$push": {"infrastructure.subdomains": sub_item}}
                            )
                            if res.modified_count > 0:
                                new_subdomains_added += 1
                        logger.info(f"Registered {new_subdomains_added} new in-scope subdomains into inventory for {root_domain}.")

                    if tasks_to_queue:
                        await self.tasks_col.insert_many(tasks_to_queue)
                        logger.info(f"Queued {len(tasks_to_queue)} verification tasks for newly found subdomains of {root_domain}.")

            # 4. Generate Centralized Hunting Leads
            # Subdomain discovery alerts omitted per configuration (subdomains are directly queued for scanning).

            # B) Cloud Storage Assets Alerting

            # IMPORTANT: Per configuration, do NOT alert if secured.
            # Only alert if the bucket is unauthenticated public (leak) or 404 (takeover).
            for probed in probed_cloud_assets:
                if probed.get("is_secured") or probed.get("status") in ["secured", "cdn"]:
                    logger.info(f"Cloud storage asset '{probed['raw']}' ({probed['provider']}) is SECURED - added to domain inventory, skipping alert.")
                    continue

                if probed.get("is_open"):
                    await self.create_alert(
                        title=f"Cloud Storage Leak: Publicly Accessible {probed['provider']} Bucket",
                        description=f"{probed['provider']} bucket '{probed['raw']}' was found in JavaScript on {target} and allows UNRESTRICTED public listing and object downloads.",
                        target=probed["raw"],
                        risk_level="critical",
                        details=f"Target: {target}\nBucket URL: {probed['probe_url']}\nProvider: {probed['provider']}\nStatus: {probed.get('details')}\nSource: Dynamic JS Analysis ({target_url})",
                        exploitation_suggestions=(
                            "### Public Cloud Storage Exploitation & Remediation\n\n"
                            "1. **Enumerate Bucket Contents**: Inspect the bucket XML/JSON directory listing to identify exposed backups, database dumps, customer files, or credentials.\n"
                            "2. **Check Write Permissions**: Test whether unauthenticated HTTP PUT or AWS CLI `aws s3 cp` allows uploading files.\n"
                            "3. **Remediation**: Enable 'Block Public Access' and enforce restricted IAM access policies immediately."
                        ),
                        alert_type="js_cloud_storage_leaks"
                    )
                elif probed.get("is_takeover"):
                    await self.create_alert(
                        title=f"Cloud Storage Takeover: Unclaimed {probed['provider']} Bucket",
                        description=f"{probed['provider']} bucket '{probed['raw']}' referenced in JavaScript on {target} returned 404 (NoSuchBucket). An attacker can register this bucket to hijack frontend assets or host payloads.",
                        target=probed["raw"],
                        risk_level="high",
                        details=f"Target: {target}\nBucket URL: {probed['probe_url']}\nProvider: {probed['provider']}\nStatus: {probed.get('details')}\nSource: Dynamic JS Analysis ({target_url})",
                        exploitation_suggestions=(
                            "### Cloud Bucket Takeover Remediation\n\n"
                            "1. **Register Name Immediately**: Claim the bucket name in the relevant cloud provider before external threat actors discover it.\n"
                            "2. **Code Cleanup**: Remove obsolete dangling references from frontend JavaScript bundles."
                        ),
                        alert_type="js_cloud_storage_takeover"
                    )

            # C) Sensitive Secrets & Credentials
            seen_secrets = set()
            for sec in all_secrets:
                sec_val = sec["value"]
                sec_source = sec.get("source_script") or target_url
                sec_context = sec.get("context", "")

                sec_key = (sec["type"], sec_val, sec_source)
                if sec_key in seen_secrets:
                    continue
                seen_secrets.add(sec_key)

                context_section = f"\n\n**Code Snippet / Surrounding Context:**\n```javascript\n...{sec_context}...\n```" if sec_context else ""

                details_text = (
                    f"**Secret Type:** `{sec['type']}`\n\n"
                    f"**Secret Value:** `{sec_val}`\n\n"
                    f"**Script File:** [{sec_source}]({sec_source})\n\n"
                    f"**Target Application:** [{target_url}]({target_url})"
                    f"{context_section}"
                )

                await self.create_alert(
                    title=f"JS Discovery: Hardcoded {sec['type']}",
                    description=f"Potential sensitive credential or API token ({sec['type']}) found in {sec_source} on {target}.",
                    target=target,
                    risk_level="high",
                    details=details_text,
                    exploitation_suggestions=(
                        "### Credential Verification & Search Guide\n\n"
                        f"1. **Locate in Script**: Open [{sec_source}]({sec_source}) in your browser or DevTools and search (`Ctrl+F` / `Cmd+F`) for:\n"
                        f"   ```text\n   {sec_val}\n   ```\n\n"
                        "2. **Verify Token Scope**: Check permissions, authorized APIs, and access limits granted to this token.\n\n"
                        "3. **Revocation & Remediation**: Rotate exposed credentials immediately and remove them from client-side bundles."
                    ),
                    alert_type="js_hardcoded_secrets"
                )

            # D) Exposed Source Maps (.js.map)
            for sm in all_sourcemaps:
                await self.create_alert(
                    title=f"JS Discovery: Exposed Source Map",
                    description=f"JavaScript source map reference detected at {sm}. Source maps can expose unminified original source trees.",
                    target=target,
                    risk_level="medium",
                    details=f"Source Map URL: {sm}\nHost: {target}",
                    exploitation_suggestions=(
                        "### Source Map Decompilation\n\n"
                        "1. **Unpack Source**: Use tools like `shuji` or `sourcemapper` to reconstruct original TypeScript/JavaScript source files.\n"
                        "2. **Code Audit**: Inspect comments, internal API paths, and developer notes in the reconstructed source."
                    ),
                    extra_key=sm,
                    alert_type="js_source_maps"
                )
                # Automatically recover and decompile source code from exposed source map
                try:
                    from source_map_unpacker import SourceMapUnpacker
                    unpacker = SourceMapUnpacker()
                    await unpacker.unpack_url(sm, target=target)
                except Exception as sm_err:
                    logger.warning(f"Auto source map unpacking error for {sm}: {sm_err}")

            # E) Exposed JWT Tokens
            for jwt in list(all_jwts.values())[:10]:
                payload_summary = ""
                if jwt.get("decoded_payload"):
                    if isinstance(jwt["decoded_payload"], dict):
                        payload_summary = ", ".join(f"{k}={v}" for k, v in list(jwt["decoded_payload"].items())[:4])
                    else:
                        payload_summary = str(jwt["decoded_payload"])[:80]
                await self.create_alert(
                    title=f"JS Discovery: Exposed JWT Token",
                    description=f"Exposed JSON Web Token (JWT) identified in JavaScript on {target}." + (f" Claims: {payload_summary}" if payload_summary else ""),
                    target=target,
                    risk_level="medium",
                    details=f"Target: {target}\nRaw Token: {jwt['raw'][:40]}...\nHeader: {jwt.get('decoded_header')}\nPayload: {jwt.get('decoded_payload')}\nSource: {jwt.get('source_script')}",
                    exploitation_suggestions=(
                        "### JWT Security Review\n\n"
                        "1. **Inspect Claims**: Check if token grants unauthorized roles, admin claims, or sensitive scopes.\n"
                        "2. **Expiration**: Verify if token has expired or remains active indefinitely.\n"
                        "3. **Signature Flaws**: Check if 'alg' header allows 'none' or if secret key is weak."
                    ),
                    alert_type="js_jwt_tokens"
                )

            # F) Auto-discover OpenAPI / Swagger specifications and GraphQL endpoints
            api_res = None
            try:
                logger.info(f"Probing OpenAPI & GraphQL endpoints on {target_url}...")
                api_res = await self.api_discovery.discover(target_url)

                # Emit alerts if Swagger/OpenAPI spec found
                if api_res.get("openapi_specs"):
                    for spec in api_res["openapi_specs"]:
                        await self.create_alert(
                            title="API Discovery: Exposed OpenAPI/Swagger Spec",
                            description=f"Exposed API Specification found at {spec['url']} with {spec.get('routes_count', 0)} endpoints documented.",
                            target=target,
                            risk_level="medium",
                            details=(
                                f"Specification URL: {spec['url']}\n"
                                f"Title: {spec.get('title')}\n"
                                f"Version: {spec.get('version')}\n"
                                f"Total Routes: {spec.get('routes_count', 0)}\n"
                                f"Sample Routes:\n" + "\n".join([f"  {r.get('method')} {r.get('path')}" for r in spec.get('routes', [])[:10]])
                            ),
                            exploitation_suggestions=(
                                "### API Specification Security Review\n\n"
                                "1. **Analyze Endpoints**: Review uncovered internal, admin, or debug endpoints.\n"
                                "2. **Check Authentication**: Verify whether all sensitive routes enforce authentication/authorization tokens.\n"
                                "3. **Test Parameter Tampering**: Review request parameter schemas for missing server-side validation or mass assignment vulnerabilities."
                            ),
                            alert_type="api_spec_discovered"
                        )

                # Emit alerts if GraphQL introspection is enabled
                if api_res.get("graphql_endpoints"):
                    for gql in api_res["graphql_endpoints"]:
                        if gql.get("introspection_enabled"):
                            await self.create_alert(
                                title="API Discovery: GraphQL Schema Introspection Enabled",
                                description=f"GraphQL endpoint at {gql['url']} has public schema introspection enabled ({gql.get('queries_count', 0)} queries, {gql.get('mutations_count', 0)} mutations).",
                                target=target,
                                risk_level="medium",
                                details=(
                                    f"GraphQL Endpoint: {gql['url']}\n"
                                    f"Introspection Enabled: True\n"
                                    f"Available Queries ({gql.get('queries_count', 0)}): {', '.join(gql.get('queries', [])[:15])}\n"
                                    f"Available Mutations ({gql.get('mutations_count', 0)}): {', '.join(gql.get('mutations', [])[:15])}\n"
                                    f"Total Types: {gql.get('total_types', 0)}"
                                ),
                                exploitation_suggestions=(
                                    "### GraphQL Security Review\n\n"
                                    "1. **Audit Mutations**: Check sensitive mutation operations (e.g. user creation, password resets, payment updates) for authorization bypass.\n"
                                    "2. **Production Hardening**: Disable schema introspection in production environments to prevent schema disclosure."
                                ),
                                alert_type="graphql_introspection_enabled"
                            )
                        elif gql.get("ide_exposed"):
                            await self.create_alert(
                                title="API Discovery: GraphQL IDE Exposed",
                                description=f"GraphQL interactive IDE/Playground exposed at {gql['url']}.",
                                target=target,
                                risk_level="low",
                                details=f"Target URL: {gql['url']}\nIDE Exposed: True",
                                exploitation_suggestions="Disable public interactive GraphQL playground/GraphiQL console on production systems.",
                                alert_type="graphql_ide_exposed"
                            )
            except Exception as api_err:
                logger.warning(f"API & GraphQL auto-discovery error on {target_url}: {api_err}")

            # G) SSR & Hydration State Payload Leaks
            for hyd in all_hydration_payloads:
                has_sensitive_env = any(
                    k.startswith(('NEXT_PUBLIC_', 'REACT_APP_', 'VITE_', 'NUXT_'))
                    or any(w in k.lower() for w in ['api_key', 'auth', 'secret', 'token', 'backend', 'client_id', 'stripe', 'firebase', 'supabase'])
                    for k in hyd.get("env_vars", {}).keys()
                )
                has_user_ctx = bool(hyd.get("user_context"))
                if has_sensitive_env or has_user_ctx or hyd.get("routes"):
                    env_snippet = "\n".join([f"- `{k}`: `{v}`" for k, v in list(hyd.get("env_vars", {}).items())[:12]])
                    user_snippet = "\n".join([f"- {u}" for u in hyd.get("user_context", [])[:5]])
                    routes_snippet = ", ".join(f"`{r}`" for r in hyd.get("routes", [])[:8])

                    details_text = (
                        f"**Framework:** {hyd['framework']} (`{hyd['id']}`)\n\n"
                        f"**Source URL:** [{hyd['source_url']}]({hyd['source_url']})\n\n"
                        + (f"**Exposed Environment & Config Variables:**\n{env_snippet}\n\n" if env_snippet else "")
                        + (f"**Exposed User Identity Context:**\n{user_snippet}\n\n" if user_snippet else "")
                        + (f"**Pre-rendered Routes in State:** {routes_snippet}\n\n" if routes_snippet else "")
                        + (f"**Discovered Apollo Queries:** {', '.join(hyd.get('apollo_queries', [])[:10])}\n\n" if hyd.get('apollo_queries') else "")
                        + f"**Raw Payload Snippet:**\n```json\n{hyd['raw_snippet']}\n```"
                    )

                    is_high = has_user_ctx or any('secret' in k.lower() or 'key' in k.lower() or 'token' in k.lower() for k in hyd.get("env_vars", {}).keys())
                    await self.create_alert(
                        title=f"JS Discovery: Exposed State Payload ({hyd['framework']})",
                        description=f"Server-side rendered state blob (`{hyd['id']}`) on {target} exposes application config variables or user identity context.",
                        target=target,
                        risk_level="high" if is_high else "medium",
                        details=details_text,
                        exploitation_suggestions=(
                            "1. **Review Exposed Configuration**: Check if runtime configs expose private microservice URLs, cloud project keys, or API tokens.\n"
                            "2. **State Payload Hardening**: Ensure user role claims and internal user IDs are sanitized from SSR HTML payloads.\n"
                            "3. **Server-Side Isolation**: Move private secrets to server-side only runtime configs (e.g. `serverRuntimeConfig` in Next.js)."
                        ),
                        extra_key=f"{hyd['source_url']}|{hyd['id']}",
                        alert_type="js_hydration_payload_leak"
                    )

            # H) Client SPA Privileged Routes
            privileged_routes = [r for r in unique_client_routes if r.get("is_privileged")]
            if privileged_routes:
                routes_md = "\n".join([f"- `{r['path']}` ({r['category']})" for r in privileged_routes[:15]])
                await self.create_alert(
                    title=f"JS Discovery: Client SPA Route Catalog ({len(privileged_routes)} Privileged Routes)",
                    description=f"Single Page Application client router on {target} defines {len(privileged_routes)} administrative, billing, or security management paths.",
                    target=target,
                    risk_level="medium",
                    details=(
                        f"**Target:** {target}\n\n"
                        f"**Discovered Privileged Routes ({len(privileged_routes)}):**\n{routes_md}\n\n"
                        f"**Total SPA Routes Found:** {len(unique_client_routes)}"
                    ),
                    exploitation_suggestions=(
                        "1. **Audit Route Permissions**: Verify that all administrative and settings routes enforce strict server-side authorization checks on their underlying APIs.\n"
                        "2. **Check for Insecure Direct Object References (IDOR)**: Inspect parameterized routes (e.g. `/users/:id/settings`, `/billing/invoices/:id`) for lack of horizontal access control.\n"
                        "3. **Catalog Shadow Endpoints**: Incorporate discovered administrative paths into backend route fuzzing catalogs."
                    ),
                    extra_key=f"{target}|spa_routes",
                    alert_type="js_client_framework_routes"
                )

            # I) Third-Party Trackers & SDK Telemetry Pivots
            for tr in unique_trackers:
                if tr["provider"] in ["Google Tag Manager", "Segment", "Sentry DSN", "Datadog RUM / APM", "Intercom"] or tr.get("correlated_domains"):
                    pivot_md = (
                        f"- [PublicWWW Search]({tr['pivot_links']['publicwww']})\n"
                        f"- [Censys Search]({tr['pivot_links']['censys']})\n"
                        f"- [BuiltWith Tag Relationships]({tr['pivot_links']['builtwith']})\n"
                        f"- [Shodan Query]({tr['pivot_links']['shodan']})"
                    )
                    corr_text = f"\n\n**Correlated Domains in Workspace:** {', '.join(tr['correlated_domains'])}" if tr.get("correlated_domains") else ""
                    await self.create_alert(
                        title=f"OSINT Pivoting: Tracker ID Discovered ({tr['provider']})",
                        description=f"Third-party tracking / telemetry key `{tr['id']}` identified on {target}." + (f" Shared across {len(tr['correlated_domains'])} other assets in workspace." if tr.get("correlated_domains") else ""),
                        target=target,
                        risk_level="medium" if tr["provider"] == "Sentry DSN" else "low",
                        details=(
                            f"**Provider:** {tr['provider']} ({tr['category']})\n\n"
                            f"**Tracker / Telemetry ID:** `{tr['id']}`\n\n"
                            f"**Source URL:** [{tr['source_url']}]({tr['source_url']})"
                            f"{corr_text}\n\n"
                            f"**OSINT Search Engine Pivots:**\n{pivot_md}"
                        ),
                        exploitation_suggestions=(
                            "1. **Pivot Across Organization Footprint**: Click the PublicWWW or Censys links to identify other web assets, shadow IT, or internal staging portals sharing this tracking key.\n"
                            "2. **Track Cross-Origin Infrastructure**: Identify acquisition targets or subsidiaries connected to the same analytics account."
                        ),
                        extra_key=f"{tr['provider']}|{tr['id']}",
                        alert_type="js_third_party_tracker_pivots"
                    )

            # 5. Store aggregated findings in domain document & web application inventory
            s3_items = []
            azure_items = []
            gcp_items = []
            other_items = []

            for c in probed_cloud_assets:
                asset_obj = {
                    "name": c.get("bucket_name") or c["raw"],
                    "raw": c["raw"],
                    "url": c.get("probe_url") or f"https://{c['raw']}",
                    "provider": c["provider"],
                    "status": c["status"],           # "secured", "open", "vulnerable_takeover", "cdn"
                    "http_status": c.get("http_status"),
                    "details": c.get("details", ""),
                    "source_app": target,
                    "discovered_by": "dynamic_js_collector",
                    "discovered_at": datetime.datetime.utcnow().isoformat()
                }
                if c["provider"] == "AWS S3":
                    s3_items.append(asset_obj)
                elif c["provider"] in ["Azure Blob", "Azure Edge"]:
                    azure_items.append(asset_obj)
                elif c["provider"] == "Google Cloud Storage":
                    gcp_items.append(asset_obj)
                else:
                    other_items.append(asset_obj)

            # A) Update infrastructure.cloud_footprint (Domain Inventory with URL & source deduplication)
            if s3_items or azure_items or gcp_items or other_items:
                doc = await self.domains_col.find_one({"domain": root_domain}, {"infrastructure.cloud_footprint": 1})
                existing_cf = (doc or {}).get("infrastructure", {}).get("cloud_footprint") or {}

                def merge_buckets(existing_list, new_items):
                    merged = {}
                    for item in (existing_list or []):
                        if isinstance(item, dict):
                            u = (item.get("url") or item.get("raw") or item.get("name") or "").strip().lower().rstrip("/")
                            src = (item.get("source_app") or "").strip().lower()
                            if u:
                                merged[(u, src)] = item
                    for item in new_items:
                        u = (item.get("url") or item.get("raw") or item.get("name") or "").strip().lower().rstrip("/")
                        src = (item.get("source_app") or "").strip().lower()
                        if u:
                            merged[(u, src)] = item
                    return list(merged.values())

                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {
                        "infrastructure.cloud_footprint.s3_buckets": merge_buckets(existing_cf.get("s3_buckets"), s3_items),
                        "infrastructure.cloud_footprint.azure_blobs": merge_buckets(existing_cf.get("azure_blobs"), azure_items),
                        "infrastructure.cloud_footprint.gcp_buckets": merge_buckets(existing_cf.get("gcp_buckets"), gcp_items),
                        "infrastructure.cloud_footprint.other_buckets": merge_buckets(existing_cf.get("other_buckets"), other_items),
                    }}
                )

                if target and target.lower() != root_domain.lower():
                    t_doc = await self.domains_col.find_one({"domain": target}, {"infrastructure.cloud_footprint": 1})
                    if t_doc:
                        t_existing_cf = (t_doc or {}).get("infrastructure", {}).get("cloud_footprint") or {}
                        await self.domains_col.update_one(
                            {"domain": target},
                            {"$set": {
                                "infrastructure.cloud_footprint.s3_buckets": merge_buckets(t_existing_cf.get("s3_buckets"), s3_items),
                                "infrastructure.cloud_footprint.azure_blobs": merge_buckets(t_existing_cf.get("azure_blobs"), azure_items),
                                "infrastructure.cloud_footprint.gcp_buckets": merge_buckets(t_existing_cf.get("gcp_buckets"), gcp_items),
                                "infrastructure.cloud_footprint.other_buckets": merge_buckets(t_existing_cf.get("other_buckets"), other_items),
                            }}
                        )

            # C) Store dynamic JS summary
            recon_summary = {
                "scanned_at": datetime.datetime.utcnow().isoformat(),
                "target_url": target_url,
                "total_scripts_intercepted": len(scripts),
                "scripts": script_summaries,
                "extracted_subdomains": sorted(list(all_subdomains)),
                "extracted_cloud_assets": [
                    {
                        "raw": p["raw"],
                        "name": p.get("bucket_name") or p["raw"],
                        "provider": p["provider"],
                        "status": p["status"],
                        "http_status": p.get("http_status"),
                        "url": p.get("probe_url"),
                        "details": p.get("details", "")
                    }
                    for p in probed_cloud_assets
                ],
                "cloud_assets_count": len(probed_cloud_assets),
                "cloud_open_count": sum(1 for p in probed_cloud_assets if p.get("is_open")),
                "cloud_takeover_count": sum(1 for p in probed_cloud_assets if p.get("is_takeover")),
                "cloud_secured_count": sum(1 for p in probed_cloud_assets if p.get("is_secured")),
                "extracted_endpoints": sorted(
                    list(all_endpoints.values()),
                    key=lambda x: (not x.get("is_in_scope", False), x.get("url", ""))
                )[:500],
                "extracted_secrets": all_secrets[:200],
                "extracted_secrets_count": len(all_secrets),
                "extracted_jwts": list(all_jwts.values())[:50],
                "jwt_count": len(all_jwts),
                "extracted_base64": list(all_base64.values())[:100],
                "base64_count": len(all_base64),
                "sourcemaps": all_sourcemaps,
                "comments": final_comments,
                "comments_count": len(final_comments),
                "interesting_comments_count": interesting_count,
                "high_interest_comments_count": high_interest_count,
                "dev_notes_comments_count": dev_notes_count,
                "meta_tags": final_meta_tags,
                "meta_tags_count": len(final_meta_tags),
                "interesting_meta_tags_count": interesting_meta_count,
                "hydration_payloads": all_hydration_payloads,
                "hydration_payloads_count": len(all_hydration_payloads),
                "client_routes": unique_client_routes,
                "client_routes_count": len(unique_client_routes),
                "privileged_client_routes_count": len([r for r in unique_client_routes if r.get("is_privileged")]),
                "trackers": unique_trackers,
                "trackers_count": len(unique_trackers),
                "api_specifications": (api_res.get("openapi_specs") if api_res else []) or [],
                "api_ui_endpoints": (api_res.get("api_ui_endpoints") if api_res else []) or [],
                "graphql_endpoints": (api_res.get("graphql_endpoints") if api_res else []) or [],
                "api_discovered_routes": (api_res.get("discovered_routes") if api_res else []) or []
            }

            # Attach findings to the specific web application entry in web_applications
            webapp_set = {
                "web_applications.$.dynamic_js": recon_summary,
                "web_applications.$.comments": final_comments,
                "web_applications.$.comments_count": len(final_comments),
                "web_applications.$.interesting_comments_count": interesting_count,
                "web_applications.$.high_interest_comments_count": high_interest_count,
                "web_applications.$.dev_notes_comments_count": dev_notes_count,
                "web_applications.$.meta_tags": final_meta_tags,
                "web_applications.$.meta_tags_count": len(final_meta_tags),
                "web_applications.$.interesting_meta_tags_count": interesting_meta_count,
                "web_applications.$.hydration_payloads": all_hydration_payloads,
                "web_applications.$.hydration_payloads_count": len(all_hydration_payloads),
                "web_applications.$.client_routes": unique_client_routes,
                "web_applications.$.client_routes_count": len(unique_client_routes),
                "web_applications.$.trackers": unique_trackers,
                "web_applications.$.trackers_count": len(unique_trackers),
            }
            if probed_cloud_assets:
                webapp_set["web_applications.$.cloud_assets"] = [
                    {
                        "name": p.get("bucket_name") or p["raw"],
                        "raw": p["raw"],
                        "url": p.get("probe_url") or f"https://{p['raw']}",
                        "provider": p["provider"],
                        "status": p["status"],
                        "http_status": p.get("http_status"),
                        "details": p.get("details", "")
                    }
                    for p in probed_cloud_assets
                ]
            res = await self.domains_col.update_one(
                {"domain": root_domain, "web_applications.target": target},
                {"$set": webapp_set}
            )
            if res.matched_count == 0:
                # If target was not found by exact web_applications.target, try by URL hostname
                res2 = await self.domains_col.update_one(
                    {"domain": root_domain, "web_applications.url": {"$regex": f"://{re.escape(target)}(/|$|:)"}},
                    {"$set": webapp_set}
                )
                if res2.matched_count == 0:
                    # Push as a web application entry so findings are strictly preserved on this specific target
                    new_app = {
                        "target": target,
                        "url": target_url,
                        "dynamic_js": recon_summary,
                        "comments": final_comments,
                        "comments_count": len(final_comments),
                        "interesting_comments_count": interesting_count,
                        "high_interest_comments_count": high_interest_count,
                        "dev_notes_comments_count": dev_notes_count,
                        "meta_tags": final_meta_tags,
                        "meta_tags_count": len(final_meta_tags),
                        "interesting_meta_tags_count": interesting_meta_count,
                        "hydration_payloads": all_hydration_payloads,
                        "hydration_payloads_count": len(all_hydration_payloads),
                        "client_routes": unique_client_routes,
                        "client_routes_count": len(unique_client_routes),
                        "trackers": unique_trackers,
                        "trackers_count": len(unique_trackers),
                    }
                    if probed_cloud_assets:
                        new_app["cloud_assets"] = webapp_set.get("web_applications.$.cloud_assets", [])
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$push": {"web_applications": new_app}}
                    )

            # Store in domain-level document ONLY if the scanned target was the root domain itself
            if target.strip().lower() == root_domain.strip().lower():
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {
                        "infrastructure.dynamic_js": recon_summary,
                        "dynamic_js": recon_summary,
                        "comments": final_comments,
                        "comments_count": len(final_comments),
                        "interesting_comments_count": interesting_count,
                        "meta_tags": final_meta_tags,
                        "meta_tags_count": len(final_meta_tags),
                        "interesting_meta_tags_count": interesting_meta_count,
                        "infrastructure.dynamic_js.hydration_payloads": all_hydration_payloads,
                        "infrastructure.dynamic_js.client_routes": unique_client_routes,
                        "infrastructure.dynamic_js.trackers": unique_trackers,
                    }}
                )

            # Store any discovered API specs and GraphQL endpoints at the domain level for fast querying
            if api_res and (api_res.get("openapi_specs") or api_res.get("graphql_endpoints") or api_res.get("api_ui_endpoints")):
                add_to_set = {}
                if api_res.get("openapi_specs"):
                    add_to_set["api_specifications"] = {"$each": api_res["openapi_specs"]}
                if api_res.get("graphql_endpoints"):
                    add_to_set["graphql_endpoints"] = {"$each": api_res["graphql_endpoints"]}
                if api_res.get("api_ui_endpoints"):
                    add_to_set["api_ui_endpoints"] = {"$each": api_res["api_ui_endpoints"]}
                if add_to_set:
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$addToSet": add_to_set}
                    )

            logger.info(
                f"Dynamic JS Recon Complete for {target}: "
                f"{len(scripts)} scripts, {len(all_subdomains)} subdomains, "
                f"{len(all_endpoints)} endpoints, {len(all_secrets)} secrets."
            )

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error during Dynamic JS extraction on {target}: {e}", exc_info=True)
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )


if __name__ == "__main__":
    agent = DynamicJsCollectorAgent()
    asyncio.run(agent.main_loop())
