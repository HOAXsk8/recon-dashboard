"""
api_schema_discovery.py - Automated OpenAPI / Swagger & GraphQL Schema Discovery & Introspection
Part of the RDash Reconnaissance Platform.
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

COMMON_API_DOC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/api-docs",
    "/api/v1/swagger.json",
    "/api/swagger.json",
    "/v3/api-docs",
    "/api/openapi.json",
    "/docs/openapi.json",
    "/swagger/v1/swagger.json"
]

COMMON_API_UI_PATHS = [
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger/",
    "/docs",
    "/redoc",
    "/api/docs"
]

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphiql"
]


class ApiSchemaDiscovery:
    """
    Automated inspector for REST OpenAPI/Swagger specifications and GraphQL schema introspection.
    """

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/json, text/html, */*"
        }

    async def discover(self, base_url: str) -> Dict[str, Any]:
        """
        Probe a base web application URL for OpenAPI/Swagger specs and GraphQL endpoints.
        """
        clean_base = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(clean_base)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or clean_base.replace("http://", "").replace("https://", "")
        root_url = f"{scheme}://{netloc}"

        result = {
            "target": root_url,
            "openapi_specs": [],
            "api_ui_endpoints": [],
            "graphql_endpoints": [],
            "discovered_routes": [],
            "total_routes_count": 0
        }

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False, headers=self.headers) as client:
            # 1. Probe OpenAPI / Swagger JSON specs
            spec_tasks = [self._probe_spec(client, f"{root_url}{path}") for path in COMMON_API_DOC_PATHS]
            # 2. Probe API Documentation UIs
            ui_tasks = [self._probe_ui(client, f"{root_url}{path}") for path in COMMON_API_UI_PATHS]
            # 3. Probe GraphQL Endpoints
            gql_tasks = [self._probe_graphql(client, f"{root_url}{path}") for path in COMMON_GRAPHQL_PATHS]

            all_tasks = spec_tasks + ui_tasks + gql_tasks
            probe_results = await asyncio.gather(*all_tasks, return_exceptions=True)

            spec_results = probe_results[:len(spec_tasks)]
            ui_results = probe_results[len(spec_tasks):len(spec_tasks) + len(ui_tasks)]
            gql_results = probe_results[len(spec_tasks) + len(ui_tasks):]

            for s in spec_results:
                if isinstance(s, dict) and s:
                    result["openapi_specs"].append(s)
                    result["discovered_routes"].extend(s.get("routes", []))

            for u in ui_results:
                if isinstance(u, dict) and u:
                    result["api_ui_endpoints"].append(u)

            for g in gql_results:
                if isinstance(g, dict) and g:
                    result["graphql_endpoints"].append(g)

        # Deduplicate routes
        unique_routes = {}
        for r in result["discovered_routes"]:
            key = (r.get("method", "GET"), r.get("path", ""))
            if key not in unique_routes:
                unique_routes[key] = r
        result["discovered_routes"] = list(unique_routes.values())
        result["total_routes_count"] = len(result["discovered_routes"])

        return result

    async def _probe_spec(self, client: httpx.AsyncClient, url: str) -> Optional[Dict[str, Any]]:
        """Probe and parse a JSON OpenAPI/Swagger document."""
        try:
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "").lower()
                text = resp.text.strip()
                if text.startswith("{") and text.endswith("}"):
                    data = json.loads(text)
                    is_openapi = "openapi" in data or "swagger" in data or ("paths" in data and isinstance(data["paths"], dict))
                    if is_openapi:
                        title = (data.get("info") or {}).get("title", "API Spec")
                        version = (data.get("info") or {}).get("version", "1.0")
                        parsed_routes = []

                        paths = data.get("paths", {})
                        if isinstance(paths, dict):
                            for path_key, path_obj in paths.items():
                                if not isinstance(path_obj, dict):
                                    continue
                                for method, op in path_obj.items():
                                    if method.lower() in ["get", "post", "put", "delete", "patch", "options", "head"]:
                                        summary = op.get("summary") or op.get("description") or ""
                                        tags = op.get("tags", [])
                                        params = [p.get("name") for p in op.get("parameters", []) if isinstance(p, dict) and p.get("name")]
                                        parsed_routes.append({
                                            "method": method.upper(),
                                            "path": path_key,
                                            "summary": summary[:120],
                                            "tags": tags,
                                            "params": params,
                                            "source": url
                                        })

                        return {
                            "url": url,
                            "type": "openapi" if "openapi" in data else "swagger",
                            "title": title,
                            "version": version,
                            "routes_count": len(parsed_routes),
                            "routes": parsed_routes
                        }
        except Exception:
            pass
        return None

    async def _probe_ui(self, client: httpx.AsyncClient, url: str) -> Optional[Dict[str, Any]]:
        """Probe for interactive Swagger UI / Redoc documentation pages."""
        try:
            resp = await client.get(url, headers={"Accept": "text/html"})
            if resp.status_code == 200:
                html = resp.text
                ui_type = None
                if "swagger-ui" in html or "Swagger UI" in html:
                    ui_type = "Swagger UI"
                elif "redoc" in html or "<redoc" in html:
                    ui_type = "ReDoc"
                elif "api-documentation" in html or "rapidoc" in html:
                    ui_type = "API Documentation"

                if ui_type:
                    return {
                        "url": url,
                        "ui_type": ui_type,
                        "title": ui_type,
                        "status": 200
                    }
        except Exception:
            pass
        return None

    async def _probe_graphql(self, client: httpx.AsyncClient, url: str) -> Optional[Dict[str, Any]]:
        """Probe GraphQL endpoint and execute standard introspection query."""
        try:
            # 1. Send test POST with introspection query
            resp = await client.post(
                url,
                json={"query": GRAPHQL_INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )

            if resp.status_code == 200:
                data = resp.json()
                schema = (data.get("data") or {}).get("__schema")
                if schema and isinstance(schema, dict):
                    types = schema.get("types", [])
                    query_type = (schema.get("queryType") or {}).get("name")
                    mutation_type = (schema.get("mutationType") or {}).get("name")

                    # Extract query names and mutation names
                    queries = []
                    mutations = []

                    for t in types:
                        if not isinstance(t, dict):
                            continue
                        name = t.get("name")
                        if name == query_type:
                            queries = [f.get("name") for f in (t.get("fields") or []) if isinstance(f, dict) and f.get("name")]
                        elif name == mutation_type:
                            mutations = [f.get("name") for f in (t.get("fields") or []) if isinstance(f, dict) and f.get("name")]

                    return {
                        "url": url,
                        "introspection_enabled": True,
                        "queries_count": len(queries),
                        "queries": queries[:100],
                        "mutations_count": len(mutations),
                        "mutations": mutations[:100],
                        "total_types": len(types)
                    }

            # 2. Check if GET returns GraphQL IDE (GraphiQL or Apollo Playground)
            get_resp = await client.get(url, headers={"Accept": "text/html"})
            if get_resp.status_code == 200:
                body = get_resp.text
                if "GraphQL" in body or "GraphiQL" in body or "Apollo" in body:
                    return {
                        "url": url,
                        "introspection_enabled": False,
                        "ide_exposed": True,
                        "title": "Exposed GraphiQL / GraphQL IDE"
                    }
        except Exception:
            pass
        return None
