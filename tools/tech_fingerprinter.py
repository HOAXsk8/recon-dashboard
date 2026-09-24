import asyncio
import datetime
import logging
import json
import os
import re
import urllib.parse
from base_agent import BaseAgent, logger

try:
    import httpx
except ImportError:
    httpx = None

IGNORE_PLUGINS = {
    "country", "ip", "title", "uncommonheaders", "strict-transport-security",
    "x-frame-options", "x-xss-protection", "x-content-type-options", "frame",
    "html5", "script", "cookies", "redirectlocation", "email", "allow",
    "meta-author", "open-graph-protocol", "content-security-policy",
    "access-control-allow-origin", "metagenerator", "x-ua-compatible",
    "passwordfield", "httponly", "x-powered-by", "httpserver", "hsts",
    "via", "x-backend-server", "x-forwarded-for"
}

# ---------------------------------------------------------------------------
# Enhancement #1: Known Vulnerabilities & CISA KEV Intelligence Database
# ---------------------------------------------------------------------------
_KNOWN_VULNERABILITIES = [
    # Apache HTTP Server
    {
        "tech": "apache",
        "name": "Apache HTTP Server",
        "cve": "CVE-2021-41773",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "exact_versions": ["2.4.49"],
        "description": "Path traversal and remote code execution flaw in Apache HTTP Server 2.4.49 path normalization.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or higher."
    },
    {
        "tech": "apache",
        "name": "Apache HTTP Server",
        "cve": "CVE-2021-42013",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "exact_versions": ["2.4.50"],
        "description": "Incomplete fix for CVE-2021-41773 allowing remote code execution via mod_cgi in Apache HTTP Server 2.4.50.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or higher."
    },
    {
        "tech": "apache",
        "name": "Apache HTTP Server",
        "cve": "CVE-2022-22720",
        "severity": "high",
        "cvss": 7.5,
        "cisa_kev": False,
        "min_version": "2.4.0",
        "max_version": "2.4.52",
        "description": "HTTP request smuggling vulnerability in Apache HTTP Server 2.4.52 and earlier via large request bodies.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.53 or higher."
    },
    {
        "tech": "apache",
        "name": "Apache HTTP Server",
        "cve": "CVE-2022-31813",
        "severity": "high",
        "cvss": 7.5,
        "cisa_kev": False,
        "min_version": "2.4.0",
        "max_version": "2.4.53",
        "description": "Apache HTTP Server mod_proxy IP address spoofing / X-Forwarded-For truncation vulnerability.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.54 or higher."
    },
    {
        "tech": "apache",
        "name": "Apache HTTP Server",
        "cve": "CVE-2024-27316",
        "severity": "high",
        "cvss": 7.5,
        "cisa_kev": False,
        "min_version": "2.4.0",
        "max_version": "2.4.58",
        "description": "HTTP/2 CONTINUATION frame flood denial of service in Apache HTTP Server.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.59 or higher."
    },

    # Nginx
    {
        "tech": "nginx",
        "name": "Nginx",
        "cve": "CVE-2023-44487",
        "severity": "high",
        "cvss": 7.5,
        "cisa_kev": True,
        "min_version": "1.0.0",
        "max_version": "1.25.2",
        "description": "HTTP/2 Rapid Reset distributed denial of service attack susceptibility.",
        "remediation": "Upgrade Nginx to version 1.25.3 or later and tune keepalive / limit_req directives."
    },
    {
        "tech": "nginx",
        "name": "Nginx",
        "cve": "CVE-2021-23017",
        "severity": "high",
        "cvss": 8.5,
        "cisa_kev": False,
        "min_version": "0.6.18",
        "max_version": "1.20.0",
        "description": "1-byte memory overwrite flaw in Nginx DNS resolver code allowing remote denial of service or code execution.",
        "remediation": "Upgrade Nginx to version 1.20.1, 1.21.0 or higher."
    },
    {
        "tech": "nginx",
        "name": "Nginx",
        "cve": "CVE-2017-7529",
        "severity": "high",
        "cvss": 7.5,
        "cisa_kev": False,
        "min_version": "0.5.6",
        "max_version": "1.13.2",
        "description": "Integer overflow in Nginx range filter module leading to sensitive cache memory disclosure.",
        "remediation": "Upgrade Nginx to version 1.13.3, 1.12.1 or higher."
    },

    # PHP
    {
        "tech": "php",
        "name": "PHP",
        "cve": "CVE-2024-4577",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "custom_matcher": lambda v: (
            _version_matches(v, min_v="8.1.0", max_v="8.1.28") or
            _version_matches(v, min_v="8.2.0", max_v="8.2.19") or
            _version_matches(v, min_v="8.3.0", max_v="8.3.7")
        ),
        "description": "PHP CGI Argument Injection vulnerability enabling unauthenticated Remote Code Execution on Windows environments.",
        "remediation": "Upgrade PHP to 8.1.29, 8.2.20, 8.3.8 or later."
    },
    {
        "tech": "php",
        "name": "PHP",
        "cve": "CVE-2019-11043",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "min_version": "7.1.0",
        "max_version": "7.3.10",
        "description": "PHP-FPM env_path_info buffer underflow vulnerability allowing remote code execution under specific Nginx FastCGI configurations.",
        "remediation": "Upgrade PHP to 7.3.11, 7.2.24 or higher."
    },
    {
        "tech": "php",
        "name": "PHP",
        "cve": "CVE-2012-1823",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "min_version": "5.3.0",
        "max_version": "5.4.1",
        "description": "PHP CGI query string command-line argument injection enabling remote code execution via -d allow_url_include=1.",
        "remediation": "Upgrade PHP to a currently supported release branch."
    },
    {
        "tech": "php",
        "name": "PHP",
        "cve": "PHP-EOL",
        "severity": "medium",
        "cvss": 6.5,
        "cisa_kev": False,
        "max_version": "7.4.99",
        "description": "PHP version detected has reached official End-of-Life (EOL) and receives no security maintenance updates.",
        "remediation": "Upgrade PHP runtime to a supported version (PHP 8.2 or 8.3+)."
    },

    # WordPress
    {
        "tech": "wordpress",
        "name": "WordPress",
        "cve": "CVE-2022-21661",
        "severity": "high",
        "cvss": 8.8,
        "cisa_kev": False,
        "min_version": "4.7.0",
        "max_exclusive": "5.8.3",
        "description": "SQL Injection vulnerability in WP_Query in WordPress Core.",
        "remediation": "Upgrade WordPress Core to 5.8.3 or later release."
    },
    {
        "tech": "wordpress",
        "name": "WordPress",
        "cve": "CVE-2022-21663",
        "severity": "high",
        "cvss": 8.0,
        "cisa_kev": False,
        "min_version": "3.7.0",
        "max_exclusive": "5.8.3",
        "description": "Object Injection vulnerability via WP_Meta_Query in WordPress Core.",
        "remediation": "Upgrade WordPress Core to 5.8.3 or later release."
    },
    {
        "tech": "wordpress",
        "name": "WordPress",
        "cve": "CVE-2024-4439",
        "severity": "high",
        "cvss": 7.2,
        "cisa_kev": False,
        "min_version": "6.0.0",
        "max_exclusive": "6.5.5",
        "description": "Stored Cross-Site Scripting (XSS) via Avatar Block in WordPress Core.",
        "remediation": "Upgrade WordPress Core to 6.5.5 or later."
    },

    # OpenSSL
    {
        "tech": "openssl",
        "name": "OpenSSL",
        "cve": "CVE-2014-0160",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "exact_versions": ["1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"],
        "description": "Heartbleed memory disclosure flaw in OpenSSL TLS heartbeat extension.",
        "remediation": "Upgrade OpenSSL to 1.0.1g or later and reissue all private keys and certificates."
    },
    {
        "tech": "openssl",
        "name": "OpenSSL",
        "cve": "CVE-2022-3602",
        "severity": "high",
        "cvss": 7.5,
        "cisa_kev": False,
        "min_version": "3.0.0",
        "max_version": "3.0.6",
        "description": "X.509 email address 4-byte buffer overflow in OpenSSL 3.0.0 through 3.0.6.",
        "remediation": "Upgrade OpenSSL to 3.0.7 or later."
    },
    {
        "tech": "openssl",
        "name": "OpenSSL",
        "cve": "CVE-2021-3449",
        "severity": "high",
        "cvss": 7.5,
        "cisa_kev": False,
        "min_version": "1.1.1",
        "max_version": "1.1.1k",
        "description": "NULL pointer dereference crash during TLS renegotiation in OpenSSL.",
        "remediation": "Upgrade OpenSSL to 1.1.1l or later."
    },

    # Drupal
    {
        "tech": "drupal",
        "name": "Drupal",
        "cve": "CVE-2018-7600",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "custom_matcher": lambda v: (
            _version_matches(v, min_v="7.0", max_exclusive="7.58") or
            _version_matches(v, min_v="8.0", max_exclusive="8.5.1")
        ),
        "description": "Drupalgeddon2 unauthenticated Remote Code Execution in Drupal Core Form API.",
        "remediation": "Upgrade Drupal to 7.58, 8.5.1, or apply vendor security patch immediately."
    },
    {
        "tech": "drupal",
        "name": "Drupal",
        "cve": "CVE-2019-6340",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "min_version": "8.0",
        "max_exclusive": "8.6.10",
        "description": "Remote Code Execution in Drupal 8 Core when RESTful Web Services module is enabled.",
        "remediation": "Upgrade Drupal to version 8.6.10 or 8.5.11."
    },

    # Joomla
    {
        "tech": "joomla",
        "name": "Joomla",
        "cve": "CVE-2015-8562",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "min_version": "1.5.0",
        "max_version": "3.4.5",
        "description": "Object injection flaw in HTTP User-Agent / X-Forwarded-For headers enabling remote code execution.",
        "remediation": "Upgrade Joomla to version 3.4.6 or later."
    },
    {
        "tech": "joomla",
        "name": "Joomla",
        "cve": "CVE-2023-23752",
        "severity": "high",
        "cvss": 7.5,
        "cisa_kev": True,
        "min_version": "4.0.0",
        "max_version": "4.2.7",
        "description": "Improper access control in Joomla 4.x REST API leaking database credentials and superadmin username.",
        "remediation": "Upgrade Joomla to version 4.2.8 or later."
    },

    # Apache Tomcat
    {
        "tech": "tomcat",
        "name": "Apache Tomcat",
        "cve": "CVE-2020-1938",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "custom_matcher": lambda v: (
            _version_matches(v, min_v="7.0.0", max_version="7.0.99") or
            _version_matches(v, min_v="8.5.0", max_version="8.5.50") or
            _version_matches(v, min_v="9.0.0", max_version="9.0.30")
        ),
        "description": "Ghostcat AJP protocol arbitrary file read / inclusion and remote code execution in Apache Tomcat.",
        "remediation": "Upgrade Tomcat to 7.0.100, 8.5.51, 9.0.31 or disable/firewall AJP connector port 8009."
    },
    {
        "tech": "tomcat",
        "name": "Apache Tomcat",
        "cve": "CVE-2017-12615",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "min_version": "7.0.0",
        "max_version": "7.0.79",
        "description": "Remote code execution via HTTP PUT method when readonly parameter is set to false in web.xml.",
        "remediation": "Upgrade Tomcat to 7.0.81 or later and verify readonly init-param is true."
    },

    # Spring Framework / Spring Boot
    {
        "tech": "spring",
        "name": "Spring Framework",
        "cve": "CVE-2022-22965",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "custom_matcher": lambda v: (
            _version_matches(v, min_v="5.3.0", max_version="5.3.17") or
            _version_matches(v, min_v="5.2.0", max_version="5.2.19")
        ),
        "description": "Spring4Shell Remote Code Execution via Data Binding on JDK 9+.",
        "remediation": "Upgrade Spring Framework to 5.3.18, 5.2.20 or upgrade Spring Boot to 2.6.6+."
    },
    {
        "tech": "spring",
        "name": "Spring Cloud Function",
        "cve": "CVE-2022-22963",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "min_version": "3.0.0",
        "max_version": "3.2.2",
        "description": "Remote code execution in Spring Cloud Function via malicious spring.cloud.function.routing-expression SpEL header.",
        "remediation": "Upgrade Spring Cloud Function to 3.1.7, 3.2.3 or higher."
    },

    # Log4j
    {
        "tech": "log4j",
        "name": "Apache Log4j",
        "cve": "CVE-2021-44228",
        "severity": "critical",
        "cvss": 10.0,
        "cisa_kev": True,
        "min_version": "2.0.0",
        "max_version": "2.14.1",
        "description": "Log4Shell JNDI LDAP lookup injection enabling unauthenticated Remote Code Execution.",
        "remediation": "Upgrade Apache Log4j to 2.17.1 or higher."
    },

    # Atlassian Confluence
    {
        "tech": "confluence",
        "name": "Atlassian Confluence",
        "cve": "CVE-2022-26134",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "max_exclusive": "7.18.1",
        "description": "OGNL injection vulnerability in Atlassian Confluence Server & Data Center allowing unauthenticated remote code execution.",
        "remediation": "Upgrade Confluence to 7.18.1, 7.17.4, 7.16.4 or later."
    },
    {
        "tech": "confluence",
        "name": "Atlassian Confluence",
        "cve": "CVE-2023-22515",
        "severity": "critical",
        "cvss": 10.0,
        "cisa_kev": True,
        "min_version": "8.0.0",
        "max_version": "8.5.3",
        "description": "Broken access control vulnerability allowing unauthenticated attackers to create administrator accounts in Confluence.",
        "remediation": "Upgrade Confluence to 8.3.3, 8.4.3, 8.5.2 or later immediately."
    },
    {
        "tech": "confluence",
        "name": "Atlassian Confluence",
        "cve": "CVE-2023-22518",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "min_version": "8.0.0",
        "max_version": "8.5.4",
        "description": "Improper authorization vulnerability in Confluence Data Center & Server leading to data loss and admin takeover.",
        "remediation": "Upgrade Confluence to 8.5.4 or later."
    },

    # Atlassian Jira
    {
        "tech": "jira",
        "name": "Atlassian Jira",
        "cve": "CVE-2022-26135",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "custom_matcher": lambda v: (
            _version_matches(v, max_exclusive="8.13.18") or
            _version_matches(v, min_v="8.14.0", max_exclusive="8.20.6")
        ),
        "description": "Authentication bypass vulnerability in Jira Mobile Plugin and Insight asset management.",
        "remediation": "Upgrade Jira to 8.13.18, 8.20.6, 8.22.0 or later."
    },

    # GitLab
    {
        "tech": "gitlab",
        "name": "GitLab",
        "cve": "CVE-2021-22205",
        "severity": "critical",
        "cvss": 10.0,
        "cisa_kev": True,
        "min_version": "11.9.0",
        "max_version": "13.10.2",
        "description": "Unauthenticated Remote Code Execution in GitLab CE/EE via ExifTool image parser vulnerability.",
        "remediation": "Upgrade GitLab to 13.10.3, 13.9.6, 13.8.8 or later."
    },
    {
        "tech": "gitlab",
        "name": "GitLab",
        "cve": "CVE-2023-7028",
        "severity": "critical",
        "cvss": 10.0,
        "cisa_kev": True,
        "min_version": "16.1.0",
        "max_version": "16.7.1",
        "description": "Improper password reset validation allowing unauthenticated takeover of arbitrary user accounts via secondary email.",
        "remediation": "Upgrade GitLab to 16.7.2, 16.6.4, 16.5.6 or later."
    },

    # Microsoft IIS
    {
        "tech": "iis",
        "name": "Microsoft IIS",
        "cve": "CVE-2021-31166",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "exact_versions": ["10.0"],
        "description": "Remote code execution vulnerability in HTTP Protocol Stack (http.sys) on Windows / IIS 10.0.",
        "remediation": "Apply Microsoft Windows cumulative security patch KB5003173."
    },
    {
        "tech": "iis",
        "name": "Microsoft IIS",
        "cve": "CVE-2017-7269",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "exact_versions": ["6.0"],
        "description": "Buffer overflow in ScStoragePathFromUrl function in WebDAV service in Microsoft IIS 6.0 enabling RCE.",
        "remediation": "Decommission legacy Windows Server 2003 / IIS 6.0 or disable WebDAV extension."
    },

    # Apache Struts
    {
        "tech": "struts",
        "name": "Apache Struts",
        "cve": "CVE-2017-5638",
        "severity": "critical",
        "cvss": 10.0,
        "cisa_kev": True,
        "custom_matcher": lambda v: (
            _version_matches(v, min_v="2.3.5", max_version="2.3.31") or
            _version_matches(v, min_v="2.5.0", max_version="2.5.10")
        ),
        "description": "Jakarta Multipart parser OGNL injection unauthenticated Remote Code Execution in Apache Struts 2.",
        "remediation": "Upgrade Apache Struts to 2.3.32, 2.5.10.1 or later."
    },

    # Grafana
    {
        "tech": "grafana",
        "name": "Grafana",
        "cve": "CVE-2021-43798",
        "severity": "high",
        "cvss": 7.5,
        "cisa_kev": True,
        "min_version": "8.0.0",
        "max_version": "8.3.0",
        "description": "Directory traversal vulnerability in Grafana plugins path allowing unauthenticated arbitrary file read.",
        "remediation": "Upgrade Grafana to version 8.3.1, 8.2.7, 8.1.8 or later."
    },

    # F5 BIG-IP
    {
        "tech": "big-ip",
        "name": "F5 BIG-IP",
        "cve": "CVE-2020-5902",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "custom_matcher": lambda v: (
            _version_matches(v, min_v="11.6.1", max_version="11.6.5") or
            _version_matches(v, min_v="12.1.0", max_version="12.1.5") or
            _version_matches(v, min_v="13.1.0", max_version="13.1.3") or
            _version_matches(v, min_v="14.1.0", max_version="14.1.2") or
            _version_matches(v, min_v="15.0.0", max_version="15.1.0")
        ),
        "description": "Traffic Management User Interface (TMUI) unauthenticated Remote Code Execution flaw.",
        "remediation": "Upgrade BIG-IP software to patched release or block external access to TMUI port 443."
    },
    {
        "tech": "big-ip",
        "name": "F5 BIG-IP",
        "cve": "CVE-2022-1388",
        "severity": "critical",
        "cvss": 9.8,
        "cisa_kev": True,
        "min_version": "13.1.0",
        "max_version": "16.1.2",
        "description": "iControl REST authentication bypass vulnerability leading to unauthenticated command execution.",
        "remediation": "Upgrade BIG-IP or block access to iControl REST interface."
    },

    # Node.js
    {
        "tech": "node.js",
        "name": "Node.js",
        "cve": "CVE-2024-21892",
        "severity": "high",
        "cvss": 8.1,
        "cisa_kev": False,
        "custom_matcher": lambda v: (
            _version_matches(v, min_v="18.0.0", max_exclusive="18.19.1") or
            _version_matches(v, min_v="20.0.0", max_exclusive="20.11.1")
        ),
        "description": "Code execution through HTTP request smuggling and permission model bypass in Node.js.",
        "remediation": "Upgrade Node.js to 18.19.1, 20.11.1, or 21.6.2+."
    }
]

# ---------------------------------------------------------------------------
# Enhancement #2: Cookie Patterns for Framework & Backend Identification
# ---------------------------------------------------------------------------
COOKIE_FRAMEWORK_PATTERNS = [
    (r"^PHPSESSID$", "PHP"),
    (r"^ASP\.NET_SessionId$", "ASP.NET"),
    (r"^ASPSESSIONID[A-Z]+$", "ASP.NET"),
    (r"^\.AspNetCore\.", "ASP.NET Core"),
    (r"^JSESSIONID$", "Java"),
    (r"^laravel_session$", "Laravel"),
    (r"^laravel_cookie$", "Laravel"),
    (r"^connect\.sid$", "Node.js (Express)"),
    (r"^express:sess", "Express"),
    (r"^django_session$", "Django"),
    (r"^csrftoken$", "Django"),
    (r"^_session_id$", "Ruby on Rails"),
    (r"^_rails_session$", "Ruby on Rails"),
    (r"^ci_session$", "CodeIgniter"),
    (r"^CAKEPHP$", "CakePHP"),
    (r"^craft_session$", "Craft CMS"),
    (r"^whmcs", "WHMCS"),
    (r"^wp_|^wordpress_|^wordpress_logged_in_", "WordPress"),
    (r"^drupal_|^SESS[0-9a-f]{32}$", "Drupal"),
    (r"^joomla_|^[0-9a-f]{32}$", "Joomla"),
    (r"^cf_clearance$|^__cf_bm$|^__cfduid$", "Cloudflare"),
    (r"^AWSALB|^AWSALBCORS$", "AWS ALB"),
    (r"^BIGipServer", "F5 BIG-IP"),
    (r"^X-Mapping-", "HAProxy"),
    (r"^koa:sess", "Koa.js"),
    (r"^beaker\.session\.id$", "Python (Beaker/Flask)"),
    (r"^rack\.session$", "Ruby (Rack)"),
]

def _parse_version(v_str):
    """Parses a version string into a numeric tuple for comparison."""
    if not v_str:
        return ()
    v_clean = re.sub(r'^[vV]', '', str(v_str).strip())
    m = re.match(r'^(\d+(?:\.\d+)*)', v_clean)
    if m:
        return tuple(int(x) for x in m.group(1).split('.'))
    return ()

def _version_matches(v_str, exact=None, min_v=None, max_v=None, max_exclusive=None):
    """Compares version string against constraints."""
    if not v_str:
        return False
    v_clean = re.sub(r'^[vV]', '', str(v_str).strip())
    if exact:
        for ex in exact:
            if v_clean == ex or v_clean.startswith(ex + ".") or v_clean.startswith(ex + "-"):
                return True

    parsed = _parse_version(v_str)
    if not parsed:
        return False

    if min_v:
        min_parsed = _parse_version(min_v)
        length = max(len(parsed), len(min_parsed))
        p1 = parsed + (0,) * (length - len(parsed))
        p2 = min_parsed + (0,) * (length - len(min_parsed))
        if p1 < p2:
            return False

    if max_v:
        max_parsed = _parse_version(max_v)
        length = max(len(parsed), len(max_parsed))
        p1 = parsed + (0,) * (length - len(parsed))
        p2 = max_parsed + (0,) * (length - len(max_parsed))
        if p1 > p2:
            return False

    if max_exclusive:
        max_ex_parsed = _parse_version(max_exclusive)
        length = max(len(parsed), len(max_ex_parsed))
        p1 = parsed + (0,) * (length - len(parsed))
        p2 = max_ex_parsed + (0,) * (length - len(max_ex_parsed))
        if p1 >= p2:
            return False

    return True

def parse_tech_entry(entry):
    """
    Parses a technology string like 'WordPress:7.2', 'nginx/1.24', or 'PHP 8.1'.
    Returns (base_key_lower, display_name, version_str_or_None).
    """
    if not entry or not isinstance(entry, str):
        return None, None, None
    entry = entry.strip()
    if not entry:
        return None, None, None
    
    match = re.match(r"^([^:/\[]+)(?:[:/ ]v?([0-9]+(?:\.[0-9a-zA-Z_-]+)*))?", entry)
    if match:
        name = match.group(1).strip()
        version = match.group(2).strip() if match.group(2) else None
        return name.lower(), name, version
    return entry.lower(), entry, None

def merge_and_deduplicate_tech(*tech_sources):
    """
    Merge technology items from multiple sources (httpx list, whatweb plugins, server banner, cookie hints, db).
    Items can be strings (e.g. 'WordPress:7.2') or tuples (name, version).
    Deduplicates strictly by canonical lowercase base name, keeping the richest version and best casing.
    Excludes non-technology pseudo-plugins.
    """
    tech_map = {}
    for source in tech_sources:
        if not source:
            continue
        for item in source:
            if not item:
                continue
            if isinstance(item, tuple):
                name, version = item
                if not name or not isinstance(name, str):
                    continue
                base_key = name.lower().strip()
                display_name = name.strip()
            elif isinstance(item, str):
                base_key, display_name, version = parse_tech_entry(item)
            else:
                continue
            
            if not base_key or base_key in IGNORE_PLUGINS:
                continue
            
            if base_key not in tech_map:
                tech_map[base_key] = {"display_name": display_name, "version": version}
            else:
                curr = tech_map[base_key]
                # If incoming version is provided, prefer it if we don't have one or if it's more specific
                if version:
                    if not curr.get("version") or len(str(version)) > len(str(curr.get("version", ""))):
                        curr["version"] = version
                # Prefer title/uppercase casing (e.g. Nginx over nginx)
                if not curr["display_name"][0].isupper() and display_name[0].isupper():
                    curr["display_name"] = display_name

    result = []
    for key in sorted(tech_map.keys()):
        d = tech_map[key]
        disp = d["display_name"]
        ver = d.get("version")
        if ver:
            result.append(f"{disp}:{ver}")
        else:
            result.append(disp)
    return result

class TechFingerprinterAgent(BaseAgent):
    def __init__(self):
        super().__init__("tech_fingerprinter", "Technology Fingerprinter", type="script")
        self._nvd_cache = {}

    async def run_httpx(self, url):
        logger.info(f"Running httpx fingerprinting on {url}")
        cmd = [
            "pd-httpx", "-u", url, "-td", "-title", "-server", "-sc", "-json", "-silent"
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=60)
            if stdout:
                return json.loads(stdout)
        except Exception as e:
            logger.error(f"httpx error for {url}: {e}")
        return None

    async def run_whatweb(self, url):
        logger.info(f"Running whatweb fingerprinting on {url}")
        cmd = [
            "whatweb", "--log-json=-", "-q", "-a", "1", url
        ]
        try:
            stdout, stderr = await self.run_command(cmd, timeout=60)
            if stdout:
                data = json.loads(stdout)
                if isinstance(data, list) and len(data) > 0:
                    return data[0]
                elif isinstance(data, dict):
                    return data
        except Exception as e:
            logger.error(f"whatweb error for {url}: {e}")
        return None

    def extract_security_headers(self, raw_headers):
        """Parse raw headers from httpx output to find security headers."""
        headers = {}
        if not raw_headers:
            return headers

        security_list = {
            "Strict-Transport-Security": "hsts",
            "Content-Security-Policy": "csp",
            "X-Frame-Options": "x_frame_options",
            "X-Content-Type-Options": "x_content_type_options",
            "X-XSS-Protection": "x_xss_protection",
            "Referrer-Policy": "referrer_policy"
        }

        normalized_headers = {k.lower(): v for k, v in raw_headers.items()}
        for h_name, key in security_list.items():
            val = normalized_headers.get(h_name.lower())
            if val:
                headers[key] = val
            else:
                headers[key] = None
        return headers

    # ---------------------------------------------------------------------------
    # Enhancement #1: Automated CVE / Known Vulnerability Correlation
    # ---------------------------------------------------------------------------
    async def query_nvd_api(self, tech_name: str, version: str, api_key: str = None) -> list:
        """
        Query NIST National Vulnerability Database (NVD) API 2.0 for live CVE correlation.
        Uses the provided apiKey for relaxed rate limits (50 req/30s).
        """
        if not tech_name or not version:
            return []

        cache_key = f"{tech_name.lower()}:{version}"
        if cache_key in self._nvd_cache:
            return self._nvd_cache[cache_key]

        search_term = f"{tech_name} {version}"
        query_encoded = urllib.parse.quote(search_term)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query_encoded}&resultsPerPage=5"

        cmd = ["curl", "-s", "-m", "15"]
        if api_key:
            cmd.extend(["-H", f"apiKey: {api_key}"])
        cmd.append(url)

        try:
            stdout, stderr = await self.run_command(cmd, timeout=20)
            if not stdout:
                return []
            
            data = json.loads(stdout)
            vulnerabilities = data.get("vulnerabilities", [])
            nvd_results = []

            for item in vulnerabilities:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id")
                if not cve_id:
                    continue

                # Extract description
                desc = ""
                descriptions = cve_obj.get("descriptions", [])
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                if not desc and descriptions:
                    desc = descriptions[0].get("value", "")

                # Extract CVSS & Severity
                cvss_score = 7.5
                severity = "high"
                metrics = cve_obj.get("metrics", {})
                cvss_data = None
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_data = metrics["cvssMetricV31"][0]
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_data = metrics["cvssMetricV30"][0]

                if cvss_data:
                    c_data = cvss_data.get("cvssData", {})
                    cvss_score = c_data.get("baseScore", 7.5)
                    sev = cvss_data.get("baseSeverity") or c_data.get("baseSeverity")
                    if sev:
                        severity = sev.lower()

                short_desc = desc[:250] + "..." if len(desc) > 250 else desc

                nvd_results.append({
                    "tech": tech_name,
                    "version": version,
                    "cve": cve_id,
                    "title": f"{tech_name} {version} Vulnerability ({cve_id})",
                    "severity": severity,
                    "cvss": cvss_score,
                    "cisa_kev": False,
                    "description": short_desc,
                    "remediation": f"Apply security patch or upgrade {tech_name} beyond version {version}.",
                    "source": "NIST NVD API"
                })

            self._nvd_cache[cache_key] = nvd_results
            return nvd_results
        except Exception as e:
            logger.debug(f"NVD API query error for {tech_name} {version}: {e}")
            return []

    async def correlate_vulnerabilities(self, tech_stack: list, nvd_api_key: str = None) -> list:
        """
        Correlates detected technologies and versions against known high-severity
        vulnerabilities, CISA's KEV catalog, and NIST NVD API 2.0 when an API key is configured.
        """
        correlations = []
        if not tech_stack:
            return correlations

        parsed_items = []
        for item in tech_stack:
            base_key, display_name, version = parse_tech_entry(item)
            if base_key:
                parsed_items.append((base_key, display_name, version))

        seen_cves = set()
        for base_key, display_name, version in parsed_items:
            for vuln in _KNOWN_VULNERABILITIES:
                vuln_tech = vuln["tech"].lower()
                cve_id = vuln["cve"]

                # Check technology match
                tech_match = (
                    vuln_tech == base_key or
                    vuln_tech in base_key or
                    base_key in vuln_tech or
                    (vuln_tech == "tomcat" and "tomcat" in base_key) or
                    (vuln_tech == "spring" and "spring" in base_key) or
                    (vuln_tech == "iis" and ("iis" in base_key or "microsoft-iis" in base_key)) or
                    (vuln_tech == "big-ip" and ("big-ip" in base_key or "bigip" in base_key))
                )
                if not tech_match:
                    continue

                # If no version detected, skip version-constrained CVEs
                if not version:
                    continue

                # Evaluate version constraints
                matched = False
                if "custom_matcher" in vuln and callable(vuln["custom_matcher"]):
                    matched = vuln["custom_matcher"](version)
                else:
                    matched = _version_matches(
                        version,
                        exact=vuln.get("exact_versions"),
                        min_v=vuln.get("min_version"),
                        max_v=vuln.get("max_version"),
                        max_exclusive=vuln.get("max_exclusive")
                    )

                if matched:
                    unique_key = f"{cve_id}:{display_name}:{version}"
                    if unique_key not in seen_cves:
                        seen_cves.add(unique_key)
                        correlations.append({
                            "tech": display_name,
                            "version": version,
                            "cve": cve_id,
                            "title": vuln.get("title", f"Vulnerability in {display_name}"),
                            "severity": vuln.get("severity", "high"),
                            "cvss": vuln.get("cvss", 7.5),
                            "cisa_kev": vuln.get("cisa_kev", False),
                            "description": vuln.get("description", ""),
                            "remediation": vuln.get("remediation", ""),
                            "source": "Curated / CISA KEV"
                        })

        # Query NIST NVD API if an API key is available
        if nvd_api_key:
            for base_key, display_name, version in parsed_items:
                if version:
                    try:
                        nvd_vulns = await self.query_nvd_api(display_name, version, api_key=nvd_api_key)
                        for nv in nvd_vulns:
                            cve_id = nv["cve"]
                            unique_key = f"{cve_id}:{display_name}:{version}"
                            if unique_key not in seen_cves:
                                seen_cves.add(unique_key)
                                correlations.append(nv)
                    except Exception as e:
                        logger.debug(f"Live NVD query error for {display_name}:{version}: {e}")

        return correlations

    async def create_vulnerability_alert(self, target: str, vuln: dict, url: str):
        """Create a lead/alert for a detected high/critical known vulnerability."""
        cve_id = vuln.get("cve", "UNKNOWN-CVE")
        tech = vuln.get("tech", "")
        ver = vuln.get("version", "")
        severity = vuln.get("severity", "high")
        cvss = vuln.get("cvss", "N/A")
        kev = vuln.get("cisa_kev", False)
        title_str = vuln.get("title", f"Vulnerability in {tech}")
        desc = vuln.get("description", "")
        remediation = vuln.get("remediation", "")

        alert_title = f"Known Vulnerability: {tech} {ver} ({cve_id})"
        alert_desc = f"[{severity.upper()}] {title_str} (CVSS {cvss}){' [CISA KEV]' if kev else ''}"

        details = (
            f"### Vulnerability Intelligence Report\n\n"
            f"- **Target URL**: {url}\n"
            f"- **Detected Technology**: `{tech}:{ver}`\n"
            f"- **Vulnerability Reference**: `{cve_id}`\n"
            f"- **Severity Rating**: **{severity.upper()}** (CVSS Score: {cvss})\n"
            f"- **CISA Known Exploited Vulnerability (KEV)**: {'YES - Actively Exploited in the Wild' if kev else 'No'}\n\n"
            f"#### Vulnerability Details\n{desc}\n"
        )

        exploitation = (
            f"### Remediation & Verification\n\n"
            f"1. **Remediation**: {remediation}\n"
            f"2. **Patch Priority**: {'URGENT: This vulnerability is in CISA KEV with active exploitation.' if kev else 'High: Apply latest vendor security patches.'}\n"
            f"3. **Version Verification**: Confirm version in administrative dashboard or dependency manifest."
        )

        await self.create_alert(
            title=alert_title,
            description=alert_desc,
            target=target,
            risk_level=severity,
            details=details,
            exploitation_suggestions=exploitation,
            extra_key=f"{cve_id}:{ver}",
            alert_type="known_vulnerability_detected"
        )

    # ---------------------------------------------------------------------------
    # Enhancement #2: Comprehensive Cookie Security & Framework Identification
    # ---------------------------------------------------------------------------
    async def audit_cookies(self, url: str, raw_headers: dict = None, whatweb_plugins: dict = None) -> dict:
        """
        Audits Set-Cookie headers for security flags (HttpOnly, Secure, SameSite)
        and identifies underlying backend frameworks and session architecture.
        """
        raw_cookie_lines = []

        # 1. Check raw_headers if available
        if raw_headers:
            for k, v in raw_headers.items():
                if k.lower() == "set-cookie":
                    if isinstance(v, list):
                        raw_cookie_lines.extend(v)
                    elif isinstance(v, str):
                        raw_cookie_lines.append(v)

        # 2. Check whatweb plugins
        if whatweb_plugins and "Cookies" in whatweb_plugins:
            c_info = whatweb_plugins["Cookies"]
            if isinstance(c_info, dict) and "string" in c_info:
                for c_str in c_info["string"]:
                    if c_str and c_str not in raw_cookie_lines:
                        raw_cookie_lines.append(c_str)

        # 3. Direct probe with curl to capture redirect chain Set-Cookie headers
        try:
            cmd = ["curl", "-sI", "-L", "--max-redirs", "2", "-m", "8", "-k", url]
            stdout, _ = await self.run_command(cmd, timeout=10)
            if stdout:
                for line in stdout.splitlines():
                    if line.lower().startswith("set-cookie:"):
                        raw_cookie_lines.append(line[11:].strip())
        except Exception as e:
            logger.debug(f"Direct curl cookie probe error for {url}: {e}")

        parsed_cookies = []
        framework_hints = set()
        security_issues = []
        insecure_session_cookies = []

        seen_names = set()
        for cookie_str in raw_cookie_lines:
            if not cookie_str or not isinstance(cookie_str, str):
                continue

            parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
            if not parts:
                continue

            name_val = parts[0].split("=", 1)
            c_name = name_val[0].strip()
            c_val = name_val[1].strip() if len(name_val) > 1 else ""

            if not c_name or c_name in seen_names:
                continue
            seen_names.add(c_name)

            # Mask value for security
            masked_val = (c_val[:4] + "..." + c_val[-3:]) if len(c_val) > 8 else "***"

            http_only = False
            secure = False
            same_site = None
            domain = None
            path = None
            expires = None

            for attr in parts[1:]:
                if "=" in attr:
                    k, v = attr.split("=", 1)
                    k_lower = k.strip().lower()
                    v_val = v.strip()
                    if k_lower == "samesite":
                        same_site = v_val
                    elif k_lower == "domain":
                        domain = v_val
                    elif k_lower == "path":
                        path = v_val
                    elif k_lower in ("expires", "max-age"):
                        expires = v_val
                else:
                    k_lower = attr.strip().lower()
                    if k_lower == "httponly":
                        http_only = True
                    elif k_lower == "secure":
                        secure = True

            # Identify framework from cookie name
            matched_framework = None
            for pattern, fw in COOKIE_FRAMEWORK_PATTERNS:
                if re.search(pattern, c_name, re.I):
                    matched_framework = fw
                    framework_hints.add(fw)
                    break

            is_session = bool(
                matched_framework or
                re.search(r'(sess|token|sid|auth|jwt|login|account|member|user|csrf)', c_name, re.I)
            )

            # Flag security issues on session cookies
            cookie_issues = []
            if is_session:
                if not http_only:
                    cookie_issues.append({
                        "type": "missing_httponly",
                        "severity": "high",
                        "issue": f"Session cookie '{c_name}' lacks the HttpOnly attribute. Accessible via document.cookie (XSS credential theft risk).",
                        "recommendation": f"Add '; HttpOnly' to the Set-Cookie header for '{c_name}'."
                    })
                if not secure and url.lower().startswith("https://"):
                    cookie_issues.append({
                        "type": "missing_secure",
                        "severity": "high",
                        "issue": f"Session cookie '{c_name}' lacks the Secure attribute on HTTPS site. May be transmitted over unencrypted HTTP.",
                        "recommendation": f"Add '; Secure' to the Set-Cookie header for '{c_name}'."
                    })
                if same_site is None:
                    cookie_issues.append({
                        "type": "missing_samesite",
                        "severity": "medium",
                        "issue": f"Session cookie '{c_name}' lacks the SameSite attribute, defaulting to Lax or browser fallback (CSRF risk).",
                        "recommendation": f"Configure 'SameSite=Lax' or 'SameSite=Strict' for '{c_name}'."
                    })
                elif same_site.lower() == "none" and not secure:
                    cookie_issues.append({
                        "type": "samesite_none_insecure",
                        "severity": "high",
                        "issue": f"Cookie '{c_name}' has SameSite=None without the Secure attribute (rejected by modern browsers).",
                        "recommendation": f"Enforce 'Secure; SameSite=None' or switch to 'SameSite=Lax'."
                    })

                if cookie_issues:
                    for iss in cookie_issues:
                        security_issues.append({"cookie": c_name, **iss})
                    insecure_session_cookies.append({
                        "cookie": c_name,
                        "issues": cookie_issues,
                        "severity": "high" if any(i["severity"] == "high" for i in cookie_issues) else "medium"
                    })

            parsed_cookies.append({
                "name": c_name,
                "masked_value": masked_val,
                "http_only": http_only,
                "secure": secure,
                "same_site": same_site,
                "domain": domain,
                "path": path,
                "expires": expires,
                "is_session": is_session,
                "identified_framework": matched_framework
            })

        return {
            "cookies": parsed_cookies,
            "cookies_count": len(parsed_cookies),
            "framework_hints": sorted(list(framework_hints)),
            "security_issues": security_issues,
            "insecure_session_cookies": insecure_session_cookies
        }

    async def create_cookie_alert(self, target: str, insecure_cookies: list, url: str):
        """Create a lead/alert for insecure session cookie configurations."""
        if not insecure_cookies:
            return

        cookie_names = [c["cookie"] for c in insecure_cookies]
        severities = [c.get("severity", "medium") for c in insecure_cookies]
        highest_severity = "high" if "high" in severities else "medium"

        alert_title = f"Insecure Session Cookies: {target}"
        alert_desc = f"Identified {len(insecure_cookies)} session cookie(s) missing security flags: {', '.join(cookie_names[:3])}"

        issues_md = []
        for item in insecure_cookies:
            c_name = item["cookie"]
            for iss in item.get("issues", []):
                issues_md.append(f"- **`{c_name}`**: {iss['issue']}\n  - *Fix*: `{iss['recommendation']}`")

        details = (
            f"### Cookie Security Audit for {url}\n\n"
            f"The following session or authentication cookies were transmitted without standard defensive flags:\n\n"
            + "\n".join(issues_md)
        )

        exploitation = (
            f"### Cookie Hardening Guidance\n\n"
            f"1. **HttpOnly**: Ensures tokens cannot be stolen via Client-Side Cross-Site Scripting (XSS).\n"
            f"2. **Secure**: Mandates transmission exclusively over encrypted TLS connections.\n"
            f"3. **SameSite**: Defends against Cross-Site Request Forgery (CSRF). Set `SameSite=Lax` for general sessions or `SameSite=Strict` for sensitive actions."
        )

        await self.create_alert(
            title=alert_title,
            description=alert_desc,
            target=target,
            risk_level=highest_severity,
            details=details,
            exploitation_suggestions=exploitation,
            extra_key="cookie_sec:" + ",".join(sorted(cookie_names)),
            alert_type="insecure_cookie_configuration"
        )

    # ---------------------------------------------------------------------------
    # Enhancement #3: HTTP/2 & HTTP/3 (QUIC) Support Auditing
    # ---------------------------------------------------------------------------
    async def audit_protocol_support(self, url: str, raw_headers: dict = None) -> dict:
        """
        Audits HTTP/2 negotiation, HTTP/1.1 legacy fallback, and HTTP/3 (QUIC)
        advertisement via Alt-Svc headers to uncover edge protocol attack surfaces.
        """
        http2_supported = False
        http1_fallback = False
        http3_advertised = False
        http3_confirmed = False
        alt_svc_header = None
        quic_protocols = []
        quic_ports = []
        negotiated_protocol = "HTTP/1.1"
        notes = []

        # 1. Probe HTTP/2 negotiation
        try:
            cmd = ["curl", "-sI", "-k", "--http2", "-m", "8", url]
            stdout, _ = await self.run_command(cmd, timeout=10)
            if stdout:
                lines = stdout.splitlines()
                first_line = lines[0].strip() if lines else ""
                if first_line.upper().startswith("HTTP/2"):
                    http2_supported = True
                    negotiated_protocol = "HTTP/2"
                elif first_line.upper().startswith("HTTP/3"):
                    http3_confirmed = True
                    negotiated_protocol = "HTTP/3"

                for line in lines:
                    if line.lower().startswith("alt-svc:"):
                        alt_svc_header = line[8:].strip()
        except Exception as e:
            logger.debug(f"HTTP/2 probe error for {url}: {e}")

        # 2. Probe HTTP/1.1 legacy fallback
        try:
            cmd = ["curl", "-sI", "-k", "--http1.1", "-m", "8", url]
            stdout, _ = await self.run_command(cmd, timeout=10)
            if stdout and any(line.upper().startswith("HTTP/1.1") for line in stdout.splitlines()):
                http1_fallback = True
        except Exception as e:
            logger.debug(f"HTTP/1.1 probe error for {url}: {e}")

        # 3. Check Alt-Svc from raw headers if not already found
        if not alt_svc_header and raw_headers:
            for k, v in raw_headers.items():
                if k.lower() == "alt-svc":
                    alt_svc_header = v if isinstance(v, str) else str(v)
                    break

        # 4. Parse Alt-Svc header for HTTP/3 and QUIC tokens
        if alt_svc_header:
            if re.search(r'(h3|quic)', alt_svc_header, re.I):
                http3_advertised = True
                quic_protocols = sorted(list(set(re.findall(r'(h3(?:-\d+)?|quic)', alt_svc_header, re.I))))
                ports = [int(p) for p in re.findall(r':(\d+)', alt_svc_header)]
                quic_ports = sorted(list(set(ports)))

        # 5. Compile supported protocols list & configuration notes
        protocols_supported = []
        if http1_fallback:
            protocols_supported.append("HTTP/1.1")
        if http2_supported:
            protocols_supported.append("HTTP/2")
        if http3_confirmed:
            protocols_supported.append("HTTP/3 (QUIC confirmed)")
        elif http3_advertised:
            protocols_supported.append("HTTP/3 (QUIC advertised)")

        if http2_supported and http1_fallback:
            notes.append("Dual protocol support: HTTP/2 enabled with HTTP/1.1 fallback. Investigate frontend-backend request desynchronization / H2.CL / H2.TE smuggling.")
        elif not http2_supported:
            notes.append("Legacy HTTP/1.1 only: Server does not support modern HTTP/2 multiplexing.")

        if http3_advertised:
            notes.append(f"HTTP/3 (QUIC) advertised via Alt-Svc on port(s) {quic_ports or [443]} (protocols: {', '.join(quic_protocols)}).")

        return {
            "http2_supported": http2_supported,
            "http1_fallback": http1_fallback,
            "http3_advertised": http3_advertised,
            "http3_confirmed": http3_confirmed,
            "alt_svc_header": alt_svc_header,
            "quic_protocols": quic_protocols,
            "quic_ports": quic_ports,
            "negotiated_protocol": negotiated_protocol,
            "protocols_supported": protocols_supported,
            "notes": notes
        }

    async def create_tech_alert(self, root_domain, target, old_tech, new_tech, url):
        """Create a lead/alert for a changed technology stack using the centralized alerting system."""
        added = set(new_tech) - set(old_tech)
        removed = set(old_tech) - set(new_tech)
        
        if not added and not removed:
            return

        title = f"Tech Stack Change: {target}"
        changes = []
        if added:
            changes.append(f"Added: {', '.join(added)}")
        if removed:
            changes.append(f"Removed: {', '.join(removed)}")
        
        description = " | ".join(changes)
        details = f"A change in the technology stack was detected for {url}.\n\nPrevious stack: {', '.join(old_tech) or 'None'}\nNew stack: {', '.join(new_tech) or 'None'}"
        exploitation = f"### Tech Stack Analysis\n\n1. **Review Changes**: Analyze why these technologies were added or removed. New technologies might introduce new attack surfaces.\n2. **Version Check**: Check if the newly added technologies have known vulnerabilities (CVEs).\n3. **Consistency**: Ensure these changes align with known infrastructure updates."

        await self.create_alert(title, description, target, "medium", details, exploitation, alert_type="tech_stack_changes")

    async def create_header_alert(self, target, old_headers, new_headers, url):
        """Create a lead/alert for degraded security headers using the centralized alerting system."""
        regressions = []
        for key, name in [
            ("hsts", "Strict-Transport-Security"),
            ("csp", "Content-Security-Policy"),
            ("x_frame_options", "X-Frame-Options")
        ]:
            if old_headers.get(key) and not new_headers.get(key):
                regressions.append(name)
        
        if not regressions:
            return

        title = f"Security Header Regression: {target}"
        description = f"Removed: {', '.join(regressions)}"
        details = f"One or more security headers were removed from {url}.\n\nRegressions: {', '.join(regressions)}"
        exploitation = f"### Header Analysis\n\n1. **Check Config**: Verify if a recent server configuration change accidentally removed these headers.\n2. **Security Impact**: Removing {regressions} increases susceptibility to attacks like Clickjacking or XSS."

        await self.create_alert(title, description, target, "high", details, exploitation, alert_type="security_header_regressions")

    async def process_tasks(self):
        task = await self.get_next_task("tech_fingerprint")

        if not task:
            return

        target = task["target"]
        root_domain = task["root_domain"]
        protocol = task.get("protocol", "http")
        port = task.get("port", 80)
        
        # Build URL
        if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
            url = f"{protocol}://{target}"
        else:
            url = f"{protocol}://{target}:{port}"

        try:
            httpx_data = await self.run_httpx(url)
            whatweb_data = await self.run_whatweb(url)

            if not httpx_data and not whatweb_data:
                logger.warning(f"No fingerprint data obtained for {url}")
                await self.tasks_col.update_one(
                    {"_id": task["_id"]},
                    {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
                )
                await self.check_completion(root_domain)
                return

            # Extract data from httpx
            httpx_tech = []
            server_banner = None
            security_headers = {}
            title = ""
            status_code = 200
            raw_headers = {}

            if httpx_data:
                httpx_tech = httpx_data.get("tech", [])
                server_banner = httpx_data.get("webserver") or httpx_data.get("server")
                raw_headers = httpx_data.get("headers", {})
                security_headers = self.extract_security_headers(raw_headers)
                title = httpx_data.get("title", "")
                status_code = httpx_data.get("status_code", 200)

            # Extract data from whatweb
            whatweb_tech_tuples = []
            whatweb_plugins_data = {}
            whatweb_status = None

            if whatweb_data:
                whatweb_status = whatweb_data.get("http_status")
                if not status_code and whatweb_status:
                    status_code = whatweb_status
                
                plugins = whatweb_data.get("plugins", {})
                whatweb_plugins_data = plugins

                # Fallback title if missing
                if not title and "Title" in plugins and plugins["Title"].get("string"):
                    title = plugins["Title"]["string"][0]
                
                # Fallback server if missing
                if not server_banner and "HTTPServer" in plugins and plugins["HTTPServer"].get("string"):
                    server_banner = plugins["HTTPServer"]["string"][0]

                for p_name, p_info in plugins.items():
                    if p_name.lower() in IGNORE_PLUGINS:
                        continue
                    ver = None
                    if isinstance(p_info, dict):
                        if p_info.get("version") and len(p_info["version"]) > 0:
                            ver = str(p_info["version"][0])
                        elif p_info.get("string") and len(p_info["string"]) > 0:
                            s_val = str(p_info["string"][0])
                            match = re.search(r"v?([0-9]+(?:\.[0-9a-zA-Z_-]+)+)", s_val)
                            if match:
                                ver = match.group(1)
                    whatweb_tech_tuples.append((p_name, ver))

            # Run cookie security & framework identification audit (Enhancement #2)
            cookie_audit = await self.audit_cookies(url, raw_headers=raw_headers, whatweb_plugins=whatweb_plugins_data)
            cookie_frameworks = cookie_audit.get("framework_hints", [])

            # Run HTTP/2 & HTTP/3 (QUIC) protocol audit (Enhancement #3)
            protocol_support = await self.audit_protocol_support(url, raw_headers=raw_headers)

            # Check for configured NIST NVD API key in settings or environment
            nvd_api_key = None
            try:
                settings_doc = await self.settings_col.find_one({"key": "global_settings"})
                if settings_doc:
                    nvd_api_key = settings_doc.get("api_keys", {}).get("nvd_api_key")
            except Exception as e:
                logger.debug(f"Error reading NVD API key from settings: {e}")
            if not nvd_api_key:
                nvd_api_key = os.environ.get("NVD_API_KEY")

            # Update web_applications in the domains collection
            domain_doc = await self.domains_col.find_one({"domain": root_domain})
            if domain_doc:
                web_apps = domain_doc.get("web_applications", [])
                app_found = False
                for app in web_apps:
                    if app.get("target") == target:
                        old_tech = app.get("tech_stack", [])
                        
                        # Merge and deduplicate across all sources including cookie framework hints
                        tech_stack = merge_and_deduplicate_tech(
                            old_tech,
                            httpx_tech,
                            whatweb_tech_tuples,
                            [server_banner] if server_banner else [],
                            cookie_frameworks
                        )
                        
                        tech_changed = set(old_tech) != set(tech_stack)
                        if tech_changed and old_tech:
                            await self.create_tech_alert(root_domain, target, old_tech, tech_stack, url)
                            # Force a re-run of directory hunt because the web app changed
                            await self.tasks_col.delete_many({
                                "root_domain": root_domain,
                                "target": target,
                                "port": port,
                                "task_type": "directory_hunt"
                            })
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "protocol": protocol,
                                "port": port,
                                "task_type": "directory_hunt",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Forced NEW directory hunt for {target}:{port} due to tech stack change.")
                        
                        # Check for header regressions
                        old_headers = app.get("security_headers", {})
                        if security_headers:
                            await self.create_header_alert(target, old_headers, security_headers, url)
                            app["security_headers"] = security_headers

                        # Correlate vulnerabilities & fire alerts (Enhancement #1)
                        vulns = await self.correlate_vulnerabilities(tech_stack, nvd_api_key=nvd_api_key)
                        for vuln in vulns:
                            if vuln.get("severity") in ("critical", "high"):
                                await self.create_vulnerability_alert(target, vuln, url)

                        # Fire cookie alerts if insecure session cookies exist (Enhancement #2)
                        insecure_cookies = cookie_audit.get("insecure_session_cookies", [])
                        if insecure_cookies:
                            await self.create_cookie_alert(target, insecure_cookies, url)

                        # Update fields
                        app["tech_stack"] = tech_stack
                        if title:
                            app["title"] = title
                        if server_banner:
                            app["server"] = server_banner
                        if status_code:
                            app["status"] = status_code
                        if whatweb_data:
                            app["whatweb"] = {
                                "status": whatweb_status,
                                "plugins": whatweb_plugins_data
                            }
                        app["vulnerabilities"] = vulns
                        app["cookie_audit"] = cookie_audit
                        app["protocol_support"] = protocol_support
                        app_found = True
                        
                        # Queue Dynamic JS Extraction for this target
                        exists_js = await self.tasks_col.find_one({
                            "root_domain": root_domain,
                            "target": target,
                            "task_type": "dynamic_js_extract"
                        })
                        if not exists_js:
                            await self.tasks_col.insert_one({
                                "root_domain": root_domain,
                                "target": target,
                                "url": url,
                                "task_type": "dynamic_js_extract",
                                "status": "pending",
                                "created_at": datetime.datetime.utcnow()
                            })
                            logger.info(f"Queued DYNAMIC JS EXTRACT for {url}")
                        break
                
                if not app_found:
                    tech_stack = merge_and_deduplicate_tech(
                        httpx_tech,
                        whatweb_tech_tuples,
                        [server_banner] if server_banner else [],
                        cookie_frameworks
                    )
                    vulns = await self.correlate_vulnerabilities(tech_stack, nvd_api_key=nvd_api_key)
                    for vuln in vulns:
                        if vuln.get("severity") in ("critical", "high"):
                            await self.create_vulnerability_alert(target, vuln, url)

                    insecure_cookies = cookie_audit.get("insecure_session_cookies", [])
                    if insecure_cookies:
                        await self.create_cookie_alert(target, insecure_cookies, url)

                    new_app = {
                        "target": target,
                        "url": url,
                        "tech_stack": tech_stack,
                        "security_headers": security_headers,
                        "title": title,
                        "status": status_code,
                        "server": server_banner or "",
                        "sensitive_files": [],
                        "vulnerabilities": vulns,
                        "cookie_audit": cookie_audit,
                        "protocol_support": protocol_support
                    }
                    if whatweb_data:
                        new_app["whatweb"] = {
                            "status": whatweb_status,
                            "plugins": whatweb_plugins_data
                        }
                    web_apps.append(new_app)
                    
                    # Queue Dynamic JS Extraction for NEW target
                    exists_js_new = await self.tasks_col.find_one({
                        "root_domain": root_domain,
                        "target": target,
                        "task_type": "dynamic_js_extract"
                    })
                    if not exists_js_new:
                        await self.tasks_col.insert_one({
                            "root_domain": root_domain,
                            "target": target,
                            "url": url,
                            "task_type": "dynamic_js_extract",
                            "status": "pending",
                            "created_at": datetime.datetime.utcnow()
                        })
                        logger.info(f"Queued DYNAMIC JS EXTRACT for NEW app: {url}")
                
                await self.domains_col.update_one(
                    {"domain": root_domain},
                    {"$set": {"web_applications": web_apps}}
                )
                logger.info(f"Updated tech stack for {url}: {tech_stack}")
        
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "completed", "completed_at": datetime.datetime.utcnow()}}
            )
            await self.check_completion(root_domain)

        except Exception as e:
            logger.error(f"Error in tech fingerprint for {target}: {e}")
            await self.tasks_col.update_one(
                {"_id": task["_id"]},
                {"$set": {"status": "failed", "error": str(e)}}
            )

if __name__ == "__main__":
    agent = TechFingerprinterAgent()
    asyncio.run(agent.main_loop())
