"""
checker.py — threat checker for scraper.py outputs

Usage:
  python checker.py scraped_data/<domain>_YYYYmmdd_HHMMSS.json
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

 
# Scoring configuration
 
WEIGHTS = {
    "missing_security_headers": 30.0,  # split across key headers
    "ssl_tls_issues":            20.0,  # cert errors / old TLS / expiring
    "mixed_content":             10.0,  # http resources on https page
    "info_disclosure_headers":    5.0,  # Server / X-Powered-By version leaks
    "forms_issues":              10.0,  # sensitive via GET / http action / empty action
    "inline_scripts_no_csp":      5.0,  # inline <script> without CSP
    "exposed_emails_phones":      5.0,  # presence on page
    "comments_present":           5.0,  # HTML comments
    "risky_external_links":       5.0,  # cleartext external links
    "cms_generator_exposed":      5.0,  # meta name=generator
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy",
]

SENSITIVE_INPUT_HINTS = {"password", "passwd", "pwd", "secret", "token", "email"}


 
# Helpers
 
def pct(x: float) -> float:
    return max(0.0, min(100.0, round(x, 1)))


def is_https_url(url: str) -> bool:
    return isinstance(url, str) and url.lower().startswith("https://")


def is_http_url(url: str) -> bool:
    return isinstance(url, str) and url.lower().startswith("http://")


def contains_version_str(value: str) -> bool:
    if not value:
        return False
    return bool(re.search(r"(?:/|\bversion\b)\s*\d", value, flags=re.IGNORECASE))


def parse_not_after(not_after: str):
    """
    Input example from scraper: 'Nov 10 12:00:00 2026 GMT'
    Returns (days_left, ok_bool)
    """
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days, True
    except Exception:
        return None, False


def load_scrape(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


 
# Buckets
 
def bucket_security_headers(headers: Dict[str, str], url: str) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    per_header = WEIGHTS["missing_security_headers"] / len(SECURITY_HEADERS)
    missing, weak = [], []

    csp = headers.get("Content-Security-Policy", "")
    if "Content-Security-Policy" not in headers:
        missing.append("Content-Security-Policy")
    else:
        if re.search(r"unsafe-inline", csp, flags=re.IGNORECASE):
            weak.append("Content-Security-Policy (allows 'unsafe-inline')")

    if "Strict-Transport-Security" not in headers and is_https_url(url):
        missing.append("Strict-Transport-Security")

    for h in SECURITY_HEADERS:
        if h in ("Content-Security-Policy", "Strict-Transport-Security"):
            continue
        if h not in headers:
            missing.append(h)

    if missing:
        contrib = round(per_header * len(missing), 2)
        findings.append({
            "id": "missing_security_headers",
            "title": "Missing security headers",
            "detail": f"Missing: {', '.join(missing)}",
            "percent": contrib
        })
        total += contrib

    if weak:
        contrib = round(per_header, 2)
        findings.append({
            "id": "weak_csp",
            "title": "Weak Content-Security-Policy",
            "detail": "; ".join(weak),
            "percent": contrib
        })
        total += contrib

    return total, findings


def bucket_ssl(ssl_info: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    w = WEIGHTS["ssl_tls_issues"]
    details, contrib = [], 0.0

    if isinstance(ssl_info, dict) and ssl_info.get("error"):
        details.append(f"SSL error: {ssl_info.get('error')}")
        contrib += w
    else:
        tls_version = (ssl_info or {}).get("version", "")
        if tls_version and not any(x in (tls_version or "").upper() for x in ("TLSV1.2", "TLSV1.3")):
            details.append(f"Old/weak TLS protocol: {tls_version or 'unknown'}")
            contrib += w * 0.5

        not_after = (ssl_info or {}).get("notAfter")
        if not_after:
            days_left, ok = parse_not_after(not_after)
            if ok and days_left is not None:
                if days_left <= 0:
                    details.append("Certificate expired")
                    contrib += w * 0.5
                elif days_left <= 30:
                    details.append(f"Certificate expiring soon ({days_left} days)")
                    contrib += w * 0.3
            else:
                details.append("Could not parse certificate expiry")
                contrib += w * 0.1

    if contrib > 0:
        findings.append({
            "id": "ssl_tls_issues",
            "title": "SSL/TLS issues",
            "detail": "; ".join(details),
            "percent": round(contrib, 2)
        })
        total += contrib

    return total, findings


def bucket_mixed_content(url: str, scripts: List[Any], links: List[Any]) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    w = WEIGHTS["mixed_content"]
    mixed_http = []

    for s in scripts or []:
        if isinstance(s, str) and is_http_url(s):
            mixed_http.append(s)

    for l in links or []:
        href = l.get("url") if isinstance(l, dict) else (l or "")
        if is_http_url(href):
            mixed_http.append(href)

    if is_https_url(url) and mixed_http:
        contrib = min(w, w * (len(mixed_http) / 5.0))
        findings.append({
            "id": "mixed_content",
            "title": "Mixed content detected",
            "detail": f"{len(mixed_http)} HTTP resource(s) referenced on HTTPS page.",
            "percent": round(contrib, 2)
        })
        total += contrib

    return total, findings


def bucket_info_disclosure(headers: Dict[str, str]) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    w = WEIGHTS["info_disclosure_headers"]
    info = []

    server_val = headers.get("Server", "")
    x_powered = headers.get("X-Powered-By", "")

    if contains_version_str(server_val):
        info.append(f"Server leaks version: {server_val}")
    if contains_version_str(x_powered):
        info.append(f"X-Powered-By leaks version: {x_powered}")

    if info:
        findings.append({
            "id": "info_disclosure_headers",
            "title": "Technology/version disclosure",
            "detail": "; ".join(info),
            "percent": round(w, 2)
        })
        total += w

    return total, findings


def bucket_forms(url: str, forms: List[Dict[str, Any]]) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    w = WEIGHTS["forms_issues"]
    issues, risky = set(), 0

    for f in forms or []:
        method = (f.get("method") or "GET").upper()
        action = (f.get("action") or "").strip()
        inputs = f.get("inputs") or []

        has_sensitive = any(
            ((i.get("type") or "").lower() == "password") or
            (i.get("name") or "").lower() in SENSITIVE_INPUT_HINTS
            for i in inputs
        )
        if has_sensitive and method == "GET":
            risky += 1
            issues.add("Sensitive inputs submitted via GET")
        if action == "":
            risky += 1
            issues.add("Form with empty/relative action")
        if is_https_url(url) and action.lower().startswith("http://"):
            risky += 1
            issues.add("HTTPS page posts form to HTTP endpoint")

    if risky:
        contrib = min(w, w * (risky / 2.0))
        findings.append({
            "id": "forms_issues",
            "title": "Potentially unsafe form configuration",
            "detail": "; ".join(sorted(issues)) if issues else "Multiple form issues",
            "percent": round(contrib, 2)
        })
        total += contrib

    return total, findings


def bucket_inline_scripts(headers: Dict[str, str], scripts: List[Any]) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    w = WEIGHTS["inline_scripts_no_csp"]
    inline_count = sum(1 for s in scripts or [] if isinstance(s, dict) and s.get("inline"))
    has_csp = "Content-Security-Policy" in headers

    if inline_count > 0 and not has_csp:
        contrib = min(w, w * (inline_count / 3.0))
        findings.append({
            "id": "inline_scripts_no_csp",
            "title": "Inline scripts without CSP",
            "detail": f"{inline_count} inline <script> block(s) and no CSP header",
            "percent": round(contrib, 2)
        })
        total += contrib

    return total, findings


def bucket_pii(emails: List[str], phones: List[str]) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    w = WEIGHTS["exposed_emails_phones"]
    count = len(set(emails or [])) + len(set(phones or []))
    if count:
        contrib = w * min(1.0, count / 5.0)
        findings.append({
            "id": "exposed_emails_phones",
            "title": "Personally identifiable info exposed",
            "detail": f"{count} email/phone instance(s) visible",
            "percent": round(contrib, 2)
        })
        total += contrib
    return total, findings


def bucket_comments(comments: List[str]) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    w = WEIGHTS["comments_present"]
    n = len(comments or [])
    if n:
        contrib = w * min(1.0, n / 10.0)
        findings.append({
            "id": "comments_present",
            "title": "HTML comments found",
            "detail": f"{n} comment(s) present",
            "percent": round(contrib, 2)
        })
        total += contrib
    return total, findings


def bucket_links(links: List[Dict[str, Any]]) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    w = WEIGHTS["risky_external_links"]
    http_links = [l for l in (links or []) if isinstance(l, dict) and is_http_url(l.get("url") or "")]
    if http_links:
        contrib = min(w, w * (len(http_links) / 10.0))
        findings.append({
            "id": "risky_external_links",
            "title": "Cleartext external links",
            "detail": f"{len(http_links)} external HTTP link(s) found",
            "percent": round(contrib, 2)
        })
        total += contrib
    return total, findings


def bucket_cms(meta_tags: List[Dict[str, Any]]) -> Tuple[float, List[Dict[str, Any]]]:
    findings, total = [], 0.0
    w = WEIGHTS["cms_generator_exposed"]
    generators = [
        m.get("content") for m in (meta_tags or [])
        if (m.get("name") or "").lower() == "generator" and m.get("content")
    ]
    if generators:
        findings.append({
            "id": "cms_generator_exposed",
            "title": "CMS generator meta exposed",
            "detail": ", ".join(generators),
            "percent": round(w, 2)
        })
        total += w
    return total, findings


 
# Evaluate
 
def evaluate(scrape: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
    headers     = {k.strip(): v for k, v in (scrape.get("headers") or {}).items()}
    url         = scrape.get("url") or ""
    forms       = scrape.get("forms") or []
    links       = scrape.get("links") or []
    scripts     = scrape.get("scripts") or []
    meta_tags   = scrape.get("meta_tags") or []
    emails      = scrape.get("emails") or []
    phones      = scrape.get("phone_numbers") or []
    comments    = scrape.get("comments") or []
    ssl_info    = scrape.get("ssl_info") or {}
    status_code = scrape.get("status_code")

    total = 0.0
    findings: List[Dict[str, Any]] = []

    for bucket in (
        lambda: bucket_security_headers(headers, url),
        lambda: bucket_ssl(ssl_info),
        lambda: bucket_mixed_content(url, scripts, links),
        lambda: bucket_info_disclosure(headers),
        lambda: bucket_forms(url, forms),
        lambda: bucket_inline_scripts(headers, scripts),
        lambda: bucket_pii(emails, phones),
        lambda: bucket_comments(comments),
        lambda: bucket_links(links),
        lambda: bucket_cms(meta_tags),
    ):
        contrib, fs = bucket()
        total += contrib
        findings.extend(fs)

    if status_code and status_code != 200:
        findings.append({
            "id": "non_200_status",
            "title": "Non-200 HTTP status observed",
            "detail": f"Status code: {status_code}",
            "percent": 0.0
        })

    return pct(total), findings


 
# CLI
 
def main():
    if len(sys.argv) < 2:
        print("Usage: python checker.py <path_to_scraper_json>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"File not found: {path}")
        sys.exit(1)

    data = load_scrape(path)
    overall, findings = evaluate(data)

    print("=" * 72)
    print(" Website Threat Assessment")
    print("=" * 72)
    print(f"Target URL: {data.get('url')}")
    print(f"Domain    : {data.get('domain')}")
    print(f"Scanned   : {data.get('scan_time')}")
    print("-" * 72)
    print(f"THREAT PERCENTAGE: {overall:.1f}%")
    print("-" * 72)

    scored = [f for f in findings if f["percent"] > 0]
    if scored:
        print("Detected issues (with contribution to threat %):")
        for f in scored:
            print(f" - {f['title']} [+{f['percent']:.1f}%]")
            if f.get("detail"):
                print(f"   • {f['detail']}")
    else:
        print("No material issues detected by current heuristics.")

    notes = [f for f in findings if f["percent"] == 0]
    if notes:
        print("-" * 72)
        print("Notes:")
        for f in notes:
            print(f" - {f['title']}: {f['detail']}")

    # Optional machine-readable summary (easy to pipe to a file)
    summary = {
        "url": data.get("url"),
        "domain": data.get("domain"),
        "scanned_at": data.get("scan_time"),
        "threat_percentage": overall,
        "issues": findings,
    }
    print("-" * 72)
    print("JSON SUMMARY:")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()