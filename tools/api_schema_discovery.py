"""
api_schema_discovery.py - Automated OpenAPI / Swagger & GraphQL Schema Discovery & Introspection
Part of the RDash Reconnaissance Platform.

Enhancements (see notes.md §api_schema_discovery.py):
  1. Postman / Insomnia Collection Discovery & Parsing
  2. GraphQL Field Suggestion Harvesting (introspection-bypass)
  3. API Endpoint & Parameter Testing Matrix generation
"""

import asyncio
import json
import logging
import re
from typing import Dict, List, Optional, Any, Tuple
import urllib.parse
import httpx

logger = logging.getLogger("api_schema_discovery")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


# ---------------------------------------------------------------------------
# GraphQL introspection query (standard – used when introspection is enabled)
# ---------------------------------------------------------------------------
GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type { name kind }
        }
      }
    }
  }
}
"""

# Canary probe fields used to elicit "Did you mean ...?" suggestions from a
# hardened GraphQL endpoint that has introspection disabled.
_GQL_CANARY_SEEDS = [
    "canary_fuzz_probe_zzz",
    "user", "users", "account", "accounts",
    "auth", "login", "logout", "me", "profile",
    "admin", "adminUser", "viewer", "node", "nodes",
    "search", "query", "get", "list", "create",
    "update", "delete", "mutation", "data", "api",
    "system", "config", "settings", "role", "permission",
    "token", "session", "order", "product", "item",
]

# Regex to extract quoted identifiers from GraphQL suggestion messages
_GQL_QUOTED_WORD_RE = re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")


# ---------------------------------------------------------------------------
# REST / OpenAPI discovery paths
# ---------------------------------------------------------------------------
COMMON_API_DOC_PATHS = [
    # OpenAPI 3.x
    "/openapi.json", "/openapi.yaml", "/openapi/v3",
    "/api/openapi.json", "/api/openapi.yaml",
    "/v3/api-docs", "/v3/openapi.json", "/docs/openapi.json",
    # Swagger 2.x
    "/swagger.json", "/swagger.yaml",
    "/v2/api-docs", "/api-docs",
    "/api/v1/swagger.json", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    # Versioned
    "/api/v1/openapi.json", "/api/v2/openapi.json", "/api/v3/openapi.json",
    "/api/v1/api-docs", "/api/v2/api-docs",
]

COMMON_API_UI_PATHS = [
    "/swagger-ui.html", "/swagger-ui/", "/swagger/",
    "/docs", "/redoc", "/api/docs", "/api-docs/", "/explorer",
]

COMMON_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql",
    "/v1/graphql", "/v2/graphql",
    "/graphiql", "/playground",
    "/api/v1/graphql", "/api/v2/graphql",
]

# ---------------------------------------------------------------------------
# Postman / Insomnia collection discovery paths  (Enhancement #2)
# ---------------------------------------------------------------------------
COMMON_COLLECTION_PATHS = [
    # Postman variants
    "/postman_collection.json", "/postman.json", "/collection.json",
    "/api-collection.json", "/api_collection.json",
    "/api/postman_collection.json", "/api/collection.json", "/api/postman.json",
    "/v2/postman_collection.json", "/v2/postman.json", "/v2/collection.json",
    "/swagger/collection.json", "/.postman/collection.json",
    "/postman/collection.json", "/docs/postman_collection.json",
    "/docs/collection.json", "/postman-collection.json",
    # Insomnia variants
    "/insomnia.json", "/insomnia.yaml",
    "/insomnia_collection.json", "/api/insomnia.json",
    "/docs/insomnia.json", "/.insomnia/Requests.json",
]

# Suggested fuzzing payloads keyed by parameter type  (Enhancement #3)
_FUZZ_PAYLOADS: Dict[str, List[str]] = {
    "string":  ["' OR '1'='1", "{{7*7}}", "../../../etc/passwd",
                "__proto__[x]=1", "<script>x</script>"],
    "integer": ["0", "-1", "9999999999", "1e308"],
    "boolean": ["true", "false", "1", "0"],
    "array":   ["[]", "[null]", "[\"x\",\"x\"]"],
    "object":  ["{}", "{\"__proto__\":{\"polluted\":1}}"],
}


# ===========================================================================
# Main class
# ===========================================================================
class ApiSchemaDiscovery:
    """
    Automated inspector for REST OpenAPI/Swagger specs, GraphQL schemas,
    and Postman/Insomnia API collections.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/html, */*",
        }

    # -----------------------------------------------------------------------
    # Public entry-point
    # -----------------------------------------------------------------------
    async def discover(self, base_url: str) -> Dict[str, Any]:
        """
        Probe a base URL for OpenAPI/Swagger specs, GraphQL endpoints, and
        Postman/Insomnia API collections.  Returns a unified result dict.
        """
        clean_base = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(clean_base)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or clean_base.replace("http://", "").replace("https://", "")
        root_url = f"{scheme}://{netloc}"

        result: Dict[str, Any] = {
            "target": root_url,
            "openapi_specs": [],
            "api_ui_endpoints": [],
            "graphql_endpoints": [],
            "postman_collections": [],                # Enhancement #2
            "graphql_reconstructed_suggestions": [],  # Enhancement #1
            "parameter_matrix": [],                   # Enhancement #3
            "discovered_routes": [],
            "total_routes_count": 0,
        }

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers=self.headers,
        ) as client:
            spec_tasks    = [self._probe_spec(client, f"{root_url}{p}")       for p in COMMON_API_DOC_PATHS]
            ui_tasks      = [self._probe_ui(client, f"{root_url}{p}")         for p in COMMON_API_UI_PATHS]
            gql_tasks     = [self._probe_graphql(client, f"{root_url}{p}")    for p in COMMON_GRAPHQL_PATHS]
            coll_tasks    = [self._probe_collection(client, f"{root_url}{p}") for p in COMMON_COLLECTION_PATHS]

            all_tasks   = spec_tasks + ui_tasks + gql_tasks + coll_tasks
            all_results = await asyncio.gather(*all_tasks, return_exceptions=True)

            n_spec = len(spec_tasks)
            n_ui   = len(ui_tasks)
            n_gql  = len(gql_tasks)

            spec_results = all_results[:n_spec]
            ui_results   = all_results[n_spec : n_spec + n_ui]
            gql_results  = all_results[n_spec + n_ui : n_spec + n_ui + n_gql]
            coll_results = all_results[n_spec + n_ui + n_gql :]

            for s in spec_results:
                if isinstance(s, dict) and s:
                    result["openapi_specs"].append(s)
                    result["discovered_routes"].extend(s.get("routes", []))

            for u in ui_results:
                if isinstance(u, dict) and u:
                    result["api_ui_endpoints"].append(u)

            # GraphQL: harvest field suggestions when introspection is blocked
            gql_suggestion_coros = []
            for g in gql_results:
                if not (isinstance(g, dict) and g):
                    continue
                result["graphql_endpoints"].append(g)
                if not g.get("introspection_enabled", True):
                    gql_suggestion_coros.append(
                        self._harvest_graphql_suggestions(client, g["url"])
                    )

            if gql_suggestion_coros:
                harvest_results = await asyncio.gather(*gql_suggestion_coros, return_exceptions=True)
                for hr in harvest_results:
                    if isinstance(hr, dict) and hr:
                        result["graphql_reconstructed_suggestions"].append(hr)

            for c in coll_results:
                if isinstance(c, dict) and c:
                    result["postman_collections"].append(c)
                    result["discovered_routes"].extend(c.get("routes", []))

        # Deduplicate routes
        unique_routes: Dict[Tuple, dict] = {}
        for r in result["discovered_routes"]:
            key = (r.get("method", "GET"), r.get("path", ""))
            if key not in unique_routes:
                unique_routes[key] = r
        result["discovered_routes"]  = list(unique_routes.values())
        result["total_routes_count"] = len(result["discovered_routes"])

        # Build parameter testing matrix from specs + collections
        result["parameter_matrix"] = self.generate_parameter_testing_matrix(
            result["openapi_specs"],
            result["postman_collections"],
        )

        return result

    # -----------------------------------------------------------------------
    # OpenAPI / Swagger spec probing
    # -----------------------------------------------------------------------
    async def _probe_spec(self, client: httpx.AsyncClient, url: str) -> Optional[Dict[str, Any]]:
        """Probe and parse a JSON OpenAPI/Swagger document."""
        try:
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return None
            text = resp.text.strip()
            if not (text.startswith("{") and text.endswith("}")):
                return None
            data = json.loads(text)
            is_openapi = (
                "openapi" in data
                or "swagger" in data
                or ("paths" in data and isinstance(data["paths"], dict))
            )
            if not is_openapi:
                return None

            title   = (data.get("info") or {}).get("title", "API Spec")
            version = (data.get("info") or {}).get("version", "1.0")
            parsed_routes: List[dict] = []

            paths = data.get("paths", {})
            if isinstance(paths, dict):
                for path_key, path_obj in paths.items():
                    if not isinstance(path_obj, dict):
                        continue
                    for method, op in path_obj.items():
                        if method.lower() not in {"get", "post", "put", "delete", "patch", "options", "head"}:
                            continue
                        summary = op.get("summary") or op.get("description") or ""
                        tags    = op.get("tags", [])
                        params  = [
                            p.get("name")
                            for p in op.get("parameters", [])
                            if isinstance(p, dict) and p.get("name")
                        ]
                        parsed_routes.append({
                            "method":  method.upper(),
                            "path":    path_key,
                            "summary": summary[:120],
                            "tags":    tags,
                            "params":  params,
                            "source":  url,
                        })

            return {
                "url":          url,
                "type":         "openapi" if "openapi" in data else "swagger",
                "title":        title,
                "version":      version,
                "routes_count": len(parsed_routes),
                "routes":       parsed_routes,
                "_raw":         data,   # retained for parameter matrix builder
            }
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Swagger / Redoc UI probing
    # -----------------------------------------------------------------------
    async def _probe_ui(self, client: httpx.AsyncClient, url: str) -> Optional[Dict[str, Any]]:
        """Probe for interactive Swagger UI / Redoc documentation pages."""
        try:
            resp = await client.get(url, headers={"Accept": "text/html"})
            if resp.status_code != 200:
                return None
            html    = resp.text
            ui_type = None
            if "swagger-ui" in html or "Swagger UI" in html:
                ui_type = "Swagger UI"
            elif "redoc" in html or "<redoc" in html:
                ui_type = "ReDoc"
            elif "api-documentation" in html or "rapidoc" in html:
                ui_type = "API Documentation"

            if ui_type:
                return {"url": url, "ui_type": ui_type, "title": ui_type, "status": 200}
        except Exception:
            pass
        return None

    # -----------------------------------------------------------------------
    # GraphQL endpoint probing
    # -----------------------------------------------------------------------
    async def _probe_graphql(self, client: httpx.AsyncClient, url: str) -> Optional[Dict[str, Any]]:
        """Probe a GraphQL endpoint; attempt standard introspection first."""
        try:
            resp = await client.post(
                url,
                json={"query": GRAPHQL_INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = {}
                schema = (data.get("data") or {}).get("__schema")

                if schema and isinstance(schema, dict):
                    types         = schema.get("types", [])
                    query_type    = (schema.get("queryType")    or {}).get("name")
                    mutation_type = (schema.get("mutationType") or {}).get("name")
                    queries:   List[str] = []
                    mutations: List[str] = []
                    for t in types:
                        if not isinstance(t, dict):
                            continue
                        name = t.get("name")
                        if name == query_type:
                            queries   = [f.get("name") for f in (t.get("fields") or []) if isinstance(f, dict) and f.get("name")]
                        elif name == mutation_type:
                            mutations = [f.get("name") for f in (t.get("fields") or []) if isinstance(f, dict) and f.get("name")]

                    return {
                        "url":                   url,
                        "introspection_enabled": True,
                        "queries_count":         len(queries),
                        "queries":               queries[:100],
                        "mutations_count":       len(mutations),
                        "mutations":             mutations[:100],
                        "total_types":           len(types),
                    }

                # Introspection blocked – check for GraphQL error signature
                errors = data.get("errors", [])
                if errors:
                    return {
                        "url":                   url,
                        "introspection_enabled": False,
                        "ide_exposed":           False,
                        "title":                "GraphQL (introspection disabled)",
                    }

            # GET probe: look for exposed IDE
            get_resp = await client.get(url, headers={"Accept": "text/html"})
            if get_resp.status_code == 200:
                body = get_resp.text
                if "GraphQL" in body or "GraphiQL" in body or "Apollo" in body or "playground" in body.lower():
                    return {
                        "url":                   url,
                        "introspection_enabled": False,
                        "ide_exposed":           True,
                        "title":                "Exposed GraphiQL / GraphQL IDE",
                    }
        except Exception:
            pass
        return None

    # -----------------------------------------------------------------------
    # Enhancement #1 – GraphQL Field Suggestion Harvesting
    # -----------------------------------------------------------------------
    async def _harvest_graphql_suggestions(
        self, client: httpx.AsyncClient, url: str
    ) -> Optional[Dict[str, Any]]:
        """
        When standard GraphQL introspection is disabled, probe the endpoint with
        deliberately invalid field names and parse "Did you mean ...?" error
        messages to reconstruct the available query and mutation surface.

        Algorithm:
          Pass 1 – fire all canary seed probes concurrently (query + mutation roots).
          Pass 2 – expand any newly discovered fields not in the original seed list.
        """
        discovered_queries:   Dict[str, bool] = {}
        discovered_mutations: Dict[str, bool] = {}

        async def _probe_field(field: str, is_mutation: bool) -> List[str]:
            gql = f"mutation {{ {field} }}" if is_mutation else f"{{ {field} }}"
            try:
                resp = await client.post(
                    url,
                    json={"query": gql},
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    timeout=self.timeout,
                )
                if resp.status_code not in (200, 400):
                    return []
                try:
                    body = resp.json()
                except Exception:
                    return []
                suggestions: List[str] = []
                for err in (body.get("errors") or []):
                    msg = err.get("message", "") if isinstance(err, dict) else str(err)
                    if "did you mean" not in msg.lower():
                        continue
                    suggestions.extend(_GQL_QUOTED_WORD_RE.findall(msg))
                return list(dict.fromkeys(suggestions))
            except Exception:
                return []

        # Pass 1
        seed_coros = (
            [(_probe_field(s, False), s, False) for s in _GQL_CANARY_SEEDS]
            + [(_probe_field(s, True),  s, True)  for s in _GQL_CANARY_SEEDS[:10]]
        )
        pass1 = await asyncio.gather(*[t[0] for t in seed_coros], return_exceptions=True)

        for (_, _, is_mut), suggestions in zip(seed_coros, pass1):
            if not isinstance(suggestions, list):
                continue
            for s in suggestions:
                (discovered_mutations if is_mut else discovered_queries)[s] = True

        # Pass 2 – expand newly found fields
        known = set(_GQL_CANARY_SEEDS)
        expand_q = [f for f in discovered_queries   if f not in known]
        expand_m = [f for f in discovered_mutations if f not in known]

        if expand_q or expand_m:
            expand_coros = [_probe_field(f, False) for f in expand_q] + [_probe_field(f, True) for f in expand_m]
            expand_results = await asyncio.gather(*expand_coros, return_exceptions=True)
            for i, field in enumerate(expand_q):
                res = expand_results[i]
                if isinstance(res, list):
                    for s in res:
                        discovered_queries[s] = True
            for j, field in enumerate(expand_m):
                res = expand_results[len(expand_q) + j]
                if isinstance(res, list):
                    for s in res:
                        discovered_mutations[s] = True

        all_queries   = sorted(discovered_queries.keys())
        all_mutations = sorted(discovered_mutations.keys())

        if not all_queries and not all_mutations:
            return None

        return {
            "url":             url,
            "method":         "suggestion_harvesting",
            "queries":        all_queries,
            "queries_count":  len(all_queries),
            "mutations":      all_mutations,
            "mutations_count":len(all_mutations),
            "note": (
                "Schema reconstructed via GraphQL error-message suggestion harvesting. "
                "Introspection was disabled/blocked on this endpoint."
            ),
        }

    # -----------------------------------------------------------------------
    # Enhancement #2 – Postman / Insomnia Collection Probing & Parsing
    # -----------------------------------------------------------------------
    async def _probe_collection(
        self, client: httpx.AsyncClient, url: str
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch a URL and try to interpret it as a Postman v2/v2.1 or Insomnia
        collection export.  Extracts routes, methods, headers, query params,
        and body structures.
        """
        try:
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return None
            text = resp.text.strip()
            if not text.startswith("{"):
                return None
            data = json.loads(text)
        except Exception:
            return None

        # Postman v2 / v2.1
        if "info" in data and "_postman_id" in (data.get("info") or {}):
            return self._parse_postman_collection(url, data)

        # Postman v1 (flat requests list)
        if "requests" in data and isinstance(data.get("requests"), list):
            return self._parse_postman_v1(url, data)

        # Insomnia export
        if data.get("_type") == "export" and "resources" in data:
            return self._parse_insomnia_export(url, data)

        return None

    def _parse_postman_collection(self, url: str, data: dict) -> Dict[str, Any]:
        """Parse a Postman Collection Schema v2 / v2.1 JSON."""
        info   = data.get("info", {})
        name   = info.get("name", "Postman Collection")
        schema = info.get("schema", "")
        routes: List[dict] = []

        def _walk_items(items: list) -> None:
            for item in items:
                if not isinstance(item, dict):
                    continue
                if "item" in item:               # folder – recurse
                    _walk_items(item["item"])
                    continue
                req = item.get("request")
                if not req or not isinstance(req, dict):
                    continue

                method  = (req.get("method") or "GET").upper()
                raw_url = req.get("url") or {}

                if isinstance(raw_url, str):
                    path        = urllib.parse.urlparse(raw_url).path or raw_url
                    query_params: List[dict] = []
                elif isinstance(raw_url, dict):
                    parts = raw_url.get("path") or []
                    path  = "/" + "/".join(str(p) for p in parts) if parts else raw_url.get("raw", "")
                    query_params = [
                        {"name": q.get("key", ""), "value": q.get("value", ""), "disabled": q.get("disabled", False)}
                        for q in (raw_url.get("query") or [])
                        if isinstance(q, dict)
                    ]
                else:
                    path, query_params = str(raw_url), []

                headers = [
                    {"name": h.get("key", ""), "value": h.get("value", "")}
                    for h in (req.get("header") or [])
                    if isinstance(h, dict)
                ]

                body_info: Optional[dict] = None
                body = req.get("body") or {}
                if isinstance(body, dict) and body.get("mode"):
                    mode = body["mode"]
                    if mode == "raw":
                        raw_body = body.get("raw", "")
                        try:
                            body_info = {"mode": "json", "schema": _json_schema_from_example(json.loads(raw_body))}
                        except Exception:
                            body_info = {"mode": "raw", "content_preview": raw_body[:200]}
                    elif mode == "urlencoded":
                        body_info = {"mode": "urlencoded", "fields": [f.get("key") for f in (body.get("urlencoded") or []) if isinstance(f, dict)]}
                    elif mode == "formdata":
                        body_info = {"mode": "formdata", "fields": [f.get("key") for f in (body.get("formdata") or []) if isinstance(f, dict)]}

                routes.append({
                    "method":       method,
                    "path":         path,
                    "summary":      item.get("name", "")[:120],
                    "tags":         [],
                    "params":       [q["name"] for q in query_params],
                    "headers":      headers,
                    "query_params": query_params,
                    "body":         body_info,
                    "source":       url,
                })

        _walk_items(data.get("item", []))
        return {
            "url":             url,
            "collection_type": "postman",
            "schema_version":  schema,
            "name":            name,
            "routes_count":    len(routes),
            "routes":          routes,
        }

    def _parse_postman_v1(self, url: str, data: dict) -> Dict[str, Any]:
        """Parse an older Postman Collection v1 JSON (flat 'requests' list)."""
        name   = data.get("name", "Postman Collection v1")
        routes: List[dict] = []

        for req in (data.get("requests") or []):
            if not isinstance(req, dict):
                continue
            method     = (req.get("method") or "GET").upper()
            raw_url    = req.get("url", "")
            parsed_url = urllib.parse.urlparse(raw_url)
            path       = parsed_url.path or raw_url
            qs_params  = [
                {"name": k, "value": v[0] if v else ""}
                for k, v in urllib.parse.parse_qs(parsed_url.query).items()
            ]

            header_raw = req.get("headers", "")
            headers: List[dict] = []
            if isinstance(header_raw, str):
                for line in header_raw.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        headers.append({"name": k.strip(), "value": v.strip()})

            routes.append({
                "method": method, "path": path,
                "summary": req.get("name", "")[:120],
                "tags": [], "params": [p["name"] for p in qs_params],
                "headers": headers, "query_params": qs_params,
                "body": None, "source": url,
            })

        return {
            "url": url, "collection_type": "postman_v1",
            "schema_version": "v1", "name": name,
            "routes_count": len(routes), "routes": routes,
        }

    def _parse_insomnia_export(self, url: str, data: dict) -> Dict[str, Any]:
        """Parse an Insomnia export JSON (v4 format)."""
        version   = data.get("__export_format", data.get("__export_source", "insomnia"))
        resources = data.get("resources", [])

        folder_names: Dict[str, str] = {
            r.get("_id", ""): r.get("name", "")
            for r in resources
            if isinstance(r, dict) and r.get("_type") == "request_group"
        }

        routes: List[dict] = []
        for r in resources:
            if not isinstance(r, dict) or r.get("_type") != "request":
                continue
            method     = (r.get("method") or "GET").upper()
            raw_url    = r.get("url", "")
            parsed_url = urllib.parse.urlparse(raw_url)
            path       = parsed_url.path or raw_url

            qs_params = [
                {"name": p.get("name", ""), "value": p.get("value", ""), "disabled": p.get("disabled", False)}
                for p in (r.get("parameters") or [])
                if isinstance(p, dict)
            ]
            headers = [
                {"name": h.get("name", ""), "value": h.get("value", "")}
                for h in (r.get("headers") or [])
                if isinstance(h, dict)
            ]

            body_info: Optional[dict] = None
            body = r.get("body") or {}
            if isinstance(body, dict):
                mime = body.get("mimeType", "")
                text = body.get("text", "")
                if "json" in mime and text:
                    try:
                        body_info = {"mode": "json", "schema": _json_schema_from_example(json.loads(text))}
                    except Exception:
                        body_info = {"mode": "raw", "content_preview": text[:200]}
                elif text:
                    body_info = {"mode": "raw", "content_preview": text[:200]}

            folder_name = folder_names.get(r.get("parentId", ""), "")
            routes.append({
                "method": method, "path": path,
                "summary": r.get("name", "")[:120],
                "tags": [folder_name] if folder_name else [],
                "params": [p["name"] for p in qs_params],
                "headers": headers, "query_params": qs_params,
                "body": body_info, "source": url,
            })

        return {
            "url": url, "collection_type": "insomnia",
            "schema_version": str(version),
            "name": f"Insomnia Export ({url.split('/')[-1]})",
            "routes_count": len(routes), "routes": routes,
        }

    # -----------------------------------------------------------------------
    # Enhancement #3 – API Endpoint & Parameter Testing Matrix
    # -----------------------------------------------------------------------
    def generate_parameter_testing_matrix(
        self,
        openapi_specs: List[Dict[str, Any]],
        collections: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Build a comprehensive parameter testing catalog from discovered
        OpenAPI specs and Postman/Insomnia collections.

        Each row describes a single parameter with: endpoint, method, name,
        location (query/header/body/path), type, required flag, example value,
        and suggested fuzzing payloads.
        """
        matrix: List[Dict[str, Any]] = []

        # ---- OpenAPI / Swagger specs ----------------------------------------
        for spec in openapi_specs:
            raw        = spec.get("_raw") or {}
            paths      = raw.get("paths", {})
            source     = spec.get("url", "")
            components = raw.get("components", {}) if isinstance(raw.get("components"), dict) else {}
            schemas    = components.get("schemas", {})

            if not isinstance(paths, dict):
                continue

            for path_key, path_obj in paths.items():
                if not isinstance(path_obj, dict):
                    continue
                for method, op in path_obj.items():
                    if not isinstance(op, dict) or method.lower() not in {
                        "get", "post", "put", "delete", "patch", "options", "head"
                    }:
                        continue

                    # query / header / path / cookie parameters
                    for param in (op.get("parameters") or []):
                        if not isinstance(param, dict):
                            continue
                        p_in      = param.get("in", "query")
                        p_schema  = param.get("schema") or {}
                        p_type    = p_schema.get("type", "string")
                        p_example = param.get("example") or p_schema.get("example") or p_schema.get("default")
                        matrix.append(_matrix_entry(
                            source=source, method=method.upper(), endpoint=path_key,
                            param_name=param.get("name", ""), location=p_in,
                            param_type=p_type,
                            required=param.get("required", p_in == "path"),
                            example=p_example,
                        ))

                    # request body (OpenAPI 3.x requestBody)
                    req_body = op.get("requestBody") or {}
                    if isinstance(req_body, dict):
                        for mime, media_obj in (req_body.get("content") or {}).items():
                            if not isinstance(media_obj, dict):
                                continue
                            body_schema = media_obj.get("schema") or {}
                            ref = body_schema.get("$ref", "")
                            if ref:
                                body_schema = schemas.get(ref.split("/")[-1], body_schema)
                            props          = body_schema.get("properties") or {}
                            required_props = body_schema.get("required") or []
                            for prop_name, prop_schema in props.items():
                                if not isinstance(prop_schema, dict):
                                    continue
                                matrix.append(_matrix_entry(
                                    source=source, method=method.upper(), endpoint=path_key,
                                    param_name=prop_name, location="body",
                                    param_type=prop_schema.get("type", "string"),
                                    required=prop_name in required_props,
                                    example=prop_schema.get("example") or prop_schema.get("default"),
                                ))

        # ---- Postman / Insomnia collections ---------------------------------
        for coll in collections:
            source = coll.get("url", "")
            for route in (coll.get("routes") or []):
                method   = route.get("method", "GET")
                endpoint = route.get("path", "")

                for qp in (route.get("query_params") or []):
                    if isinstance(qp, dict) and not qp.get("disabled"):
                        matrix.append(_matrix_entry(
                            source=source, method=method, endpoint=endpoint,
                            param_name=qp.get("name", ""), location="query",
                            param_type="string", required=False, example=qp.get("value"),
                        ))

                for hdr in (route.get("headers") or []):
                    if isinstance(hdr, dict) and hdr.get("name", "").lower() not in {
                        "content-type", "accept", "content-length"
                    }:
                        matrix.append(_matrix_entry(
                            source=source, method=method, endpoint=endpoint,
                            param_name=hdr.get("name", ""), location="header",
                            param_type="string", required=False, example=hdr.get("value"),
                        ))

                body = route.get("body") or {}
                if isinstance(body, dict) and isinstance(body.get("schema"), dict):
                    for prop_name, prop_info in (body["schema"].get("properties") or {}).items():
                        p_type    = prop_info.get("type", "string") if isinstance(prop_info, dict) else "string"
                        p_example = prop_info.get("example") if isinstance(prop_info, dict) else None
                        matrix.append(_matrix_entry(
                            source=source, method=method, endpoint=endpoint,
                            param_name=prop_name, location="body",
                            param_type=p_type, required=False, example=p_example,
                        ))

        return matrix


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------
def _matrix_entry(
    *,
    source: str,
    method: str,
    endpoint: str,
    param_name: str,
    location: str,
    param_type: str,
    required: bool,
    example: Any,
) -> Dict[str, Any]:
    """Return a single parameter testing matrix row with fuzz payloads."""
    fuzz_type = param_type if param_type in _FUZZ_PAYLOADS else "string"
    return {
        "source":        source,
        "method":        method,
        "endpoint":      endpoint,
        "param":         param_name,
        "location":      location,   # query | header | body | path | cookie
        "type":          param_type,
        "required":      required,
        "example":       example,
        "fuzz_payloads": _FUZZ_PAYLOADS[fuzz_type],
    }


def _json_schema_from_example(obj: Any, _depth: int = 0) -> Dict[str, Any]:
    """
    Derive a minimal JSON-Schema description from a concrete JSON example.
    Used to describe Postman/Insomnia request body structures.  Capped at
    depth 4 to avoid unbounded recursion on deeply nested payloads.
    """
    if _depth > 4:
        return {"type": "any"}
    if isinstance(obj, dict):
        return {"type": "object", "properties": {k: _json_schema_from_example(v, _depth + 1) for k, v in obj.items()}}
    if isinstance(obj, list):
        return {"type": "array", "items": _json_schema_from_example(obj[0], _depth + 1) if obj else {"type": "any"}}
    if isinstance(obj, bool):
        return {"type": "boolean", "example": obj}
    if isinstance(obj, int):
        return {"type": "integer", "example": obj}
    if isinstance(obj, float):
        return {"type": "number", "example": obj}
    if isinstance(obj, str):
        return {"type": "string", "example": obj}
    return {"type": "null"}
