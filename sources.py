"""
sources.py - ThreatLens Multi-Source Intelligence Aggregator
Integrates VirusTotal, RDAP/WHOIS, AbuseIPDB, URLScan, Google Safe Browsing,
Shodan, DNS resolution, and SSL/Redirect tracing.
"""

from __future__ import annotations

import base64
import os
import socket
import ssl
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import dns.resolver
import requests

REQUEST_TIMEOUT = 10


def _get_key(name: str) -> Optional[str]:
    val = os.environ.get(name)
    if val:
        return val
    try:
        import streamlit as st
        return st.secrets.get(name)
    except Exception:
        return None


def _success(source: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return {"source": source, "status": "success", "data": data, "error": None}


def _failure(source: str, err: str) -> Dict[str, Any]:
    return {"source": source, "status": "error", "data": {}, "error": err}


def _clean_domain(hostname: str) -> str:
    parts = hostname.strip().lower().split(".")
    if len(parts) > 2 and not parts[-1].isdigit():
        return ".".join(parts[-2:])
    return hostname


# 1. VirusTotal
def get_virustotal(target: str, target_type: str) -> Dict[str, Any]:
    api_key = _get_key("VIRUSTOTAL_API_KEY")
    if not api_key:
        return _failure("VirusTotal", "VirusTotal API key not configured.")

    base_url = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    try:
        if target_type == "IP Address":
            endpoint = f"{base_url}/ip_addresses/{target}"
        elif target_type == "Domain":
            endpoint = f"{base_url}/domains/{_clean_domain(target)}"
        else:
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"{base_url}/urls/{url_id}"

        resp = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return _failure("VirusTotal", "Target has not been scanned yet.")
        if resp.status_code == 401:
            return _failure("VirusTotal", "Invalid API key.")
        if resp.status_code != 200:
            return _failure("VirusTotal", f"HTTP {resp.status_code}")

        attr = resp.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        return _success("VirusTotal", {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attr.get("reputation", 0),
        })
    except Exception as e:
        return _failure("VirusTotal", str(e))


# 2. WHOIS / RDAP
def get_whois(target: str, target_type: str) -> Dict[str, Any]:
    try:
        if target_type == "IP Address":
            from ipwhois import IPWhois
            res = IPWhois(target).lookup_rdap(depth=1)
            net = res.get("network", {})
            return _success("WHOIS/RDAP", {
                "name": net.get("name"),
                "cidr": net.get("cidr"),
                "country": net.get("country"),
                "asn": res.get("asn"),
                "asn_description": res.get("asn_description"),
            })

        domain = _clean_domain(urlparse(target).hostname if target_type == "URL" else target)
        resp = requests.get(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/json"}, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return _failure("WHOIS/RDAP", f"RDAP query returned HTTP {resp.status_code}")

        data = resp.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
        created = events.get("registration")
        expires = events.get("expiration")
        age_days = None

        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(dt.tzinfo) - dt).days
                created = dt.strftime("%Y-%m-%d")
            except Exception:
                pass

        # Parse registrar entity
        registrar = "Unknown"
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for item in vcard:
                    if item[0] == "fn":
                        registrar = item[3]
                        break

        return _success("WHOIS/RDAP", {
            "domain": domain,
            "registrar": registrar,
            "creation_date": created,
            "expiration_date": expires[:10] if expires else None,
            "domain_age_days": age_days,
            "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")],
        })
    except Exception as e:
        return _failure("WHOIS/RDAP", str(e))


# 3. AbuseIPDB
def get_abuseipdb(target: str, target_type: str) -> Dict[str, Any]:
    api_key = _get_key("ABUSEIPDB_API_KEY")
    if not api_key:
        return _failure("AbuseIPDB", "API key not configured.")

    ip = target
    if target_type != "IP Address":
        try:
            host = urlparse(target).hostname if target_type == "URL" else target
            ip = socket.gethostbyname(host)
        except Exception:
            return _failure("AbuseIPDB", "Could not resolve hostname to IP.")

    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "false"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return _failure("AbuseIPDB", f"HTTP {resp.status_code}")

        d = resp.json().get("data", {})
        return _success("AbuseIPDB", {
            "resolved_ip": ip,
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "usage_type": d.get("usageType"),
            "isp": d.get("isp"),
            "country": d.get("countryCode"),
        })
    except Exception as e:
        return _failure("AbuseIPDB", str(e))


# 4. Google Safe Browsing
def get_safebrowsing(target: str, target_type: str) -> Dict[str, Any]:
    api_key = _get_key("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key:
        return _failure("Google Safe Browsing", "API key not configured.")

    check_url = target if target_type == "URL" else f"http://{target}"
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "threatlens", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": check_url}],
        },
    }
    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return _failure("Google Safe Browsing", f"HTTP {resp.status_code}")
        matches = resp.json().get("matches", [])
        return _success("Google Safe Browsing", {
            "is_flagged": len(matches) > 0,
            "threat_types": [m.get("threatType") for m in matches],
        })
    except Exception as e:
        return _failure("Google Safe Browsing", str(e))


# 5. URLScan.io
def get_urlscan(target: str, target_type: str) -> Dict[str, Any]:
    query_target = _clean_domain(urlparse(target).hostname if target_type == "URL" else target)
    try:
        resp = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{query_target}&size=1", timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return _failure("URLScan", f"HTTP {resp.status_code}")

        res = resp.json().get("results", [])
        if not res:
            return _failure("URLScan", "No scan history found.")

        item = res[0]
        page = item.get("page", {})
        return _success("URLScan", {
            "overall_malicious": item.get("verdicts", {}).get("overall", {}).get("malicious", False),
            "score": item.get("verdicts", {}).get("overall", {}).get("score", 0),
            "ip": page.get("ip"),
            "country": page.get("country"),
            "server": page.get("server"),
        })
    except Exception as e:
        return _failure("URLScan", str(e))


# 6. Shodan
def get_shodan(target: str, target_type: str) -> Dict[str, Any]:
    api_key = _get_key("SHODAN_API_KEY")
    if not api_key:
        return _failure("Shodan", "API key not configured.")

    ip = target
    if target_type != "IP Address":
        try:
            host = urlparse(target).hostname if target_type == "URL" else target
            ip = socket.gethostbyname(host)
        except Exception:
            return _failure("Shodan", "Could not resolve hostname to IP.")

    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return _failure("Shodan", "No open port data available for this IP.")
        if resp.status_code != 200:
            return _failure("Shodan", f"HTTP {resp.status_code}")

        d = resp.json()
        return _success("Shodan", {
            "ports": d.get("ports", []),
            "vulnerabilities": list(d.get("vulns", {}).keys()),
            "os": d.get("os"),
            "org": d.get("org"),
        })
    except Exception as e:
        return _failure("Shodan", str(e))


# 7. Deep Analysis: Redirect Tracer, SSL, and DNS
def trace_redirects(url: str) -> Dict[str, Any]:
    chain = []
    try:
        session = requests.Session()
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, headers={"User-Agent": "ThreatLens/1.0"})
        for r in resp.history:
            chain.append({"status_code": r.status_code, "url": r.url})
        chain.append({"status_code": resp.status_code, "url": resp.url})
        return {"success": True, "final_url": resp.url, "redirect_count": len(resp.history), "chain": chain}
    except Exception as e:
        return {"success": False, "error": str(e), "chain": []}


def get_dns_ssl_intel(target: str, target_type: str) -> Dict[str, Any]:
    if target_type == "IP Address":
        return {}
    hostname = urlparse(target).hostname if target_type == "URL" else target
    hostname = hostname or target
    out = {"dns": {}, "ssl": {}}

    for qtype in ["A", "MX", "NS"]:
        try:
            answers = dns.resolver.resolve(hostname, qtype, lifetime=4)
            out["dns"][qtype] = [str(rdata) for rdata in answers][:3]
        except Exception:
            out["dns"][qtype] = []

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                issuer = dict(x[0] for x in cert.get('issuer', []))
                out["ssl"] = {
                    "valid": True,
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "expires": exp_date.strftime("%Y-%m-%d"),
                    "days_left": (exp_date - datetime.utcnow()).days,
                }
    except Exception as e:
        out["ssl"] = {"valid": False, "error": str(e)}

    return out


SOURCES: Dict[str, Callable[[str, str], Dict[str, Any]]] = {
    "VirusTotal": get_virustotal,
    "WHOIS/RDAP": get_whois,
    "AbuseIPDB": get_abuseipdb,
    "Google Safe Browsing": get_safebrowsing,
    "URLScan": get_urlscan,
    "Shodan": get_shodan,
}