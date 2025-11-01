import re
import hashlib
import math
import requests
from bs4 import BeautifulSoup
import tldextract
import chardet

SUSPICIOUS_JS_KEYWORDS = [
    "eval(", "new Function", "fromCharCode", "atob(", "unescape(", "document.cookie", "XMLHttpRequest", "fetch("
]
SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Feature-Policy", "Permissions-Policy"
]

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy

def extract_urls(text: str):
    return re.findall(r"https?://[^\s\"'<>]+", text)

def safe_decode(content: bytes):
    # Try requests apparent encoding, fall back to chardet or utf-8.
    try:
        text = content.decode('utf-8')
    except Exception:
        enc = chardet.detect(content).get('encoding') or 'utf-8'
        try:
            text = content.decode(enc, errors='replace')
        except Exception:
            text = content.decode('utf-8', errors='replace')
    return text

def extract_response_features(url: str, timeout=10):
    r = requests.get(url, timeout=timeout, allow_redirects=True)
    headers = {k: v for k, v in r.headers.items()}
    body = r.content or b""
    text = safe_decode(body)
    soup = BeautifulSoup(text, "html.parser")

    # Basic features
    features = {
        "url": r.url,
        "status_code": r.status_code,
        "content_type": headers.get("Content-Type", "").split(";")[0],
        "content_length": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "entropy": shannon_entropy(body),
        "num_redirects": len(r.history),
        "response_time_ms": int(r.elapsed.total_seconds() * 1000),
    }

    # Security headers presence
    for h in SECURITY_HEADERS:
        features[f"hdr_{h.lower().replace('-', '_')}"] = 1 if h in headers else 0

    # Cookies and cookie flags
    set_cookie = headers.get("Set-Cookie", "")
    features["num_set_cookie"] = set_cookie.count("=") if set_cookie else 0
    features["cookie_has_httponly"] = 1 if "httponly" in set_cookie.lower() else 0
    features["cookie_has_secure"] = 1 if "secure" in set_cookie.lower() else 0

    # Extract script sources and inline script heuristics
    script_tags = soup.find_all("script")
    external_scripts = []
    inline_script_text = []
    for s in script_tags:
        if s.get("src"):
            external_scripts.append(s["src"])
        else:
            inline_script_text.append(s.get_text(" ", strip=True))

    features["num_external_scripts"] = len(external_scripts)
    features["num_inline_scripts"] = len(inline_script_text)
    combined_inline = " ".join(inline_script_text)
    features["inline_js_eval_count"] = sum(combined_inline.count(k) for k in SUSPICIOUS_JS_KEYWORDS)

    # Extract URLs/domains
    all_urls = extract_urls(text)
    features["num_urls_in_body"] = len(all_urls)
    domains = set()
    for u in all_urls + external_scripts:
        ext = tldextract.extract(u)
        domain = ".".join([p for p in (ext.domain, ext.suffix) if p])
        if domain:
            domains.add(domain)
    features["num_unique_domains"] = len(domains)

    # Suspicious keyword counts
    body_lower = text.lower()
    suspicious_keywords = ["ransom", "miner", "wallet", "coinhive", "keylogger", "steal"]
    features["suspicious_keyword_count"] = sum(body_lower.count(k) for k in suspicious_keywords)

    return features

# Example usage:
if __name__ == "__main__":
    example = extract_response_features("https://albany.edu")
    for k, v in example.items():
        print(f"{k}: {v}")