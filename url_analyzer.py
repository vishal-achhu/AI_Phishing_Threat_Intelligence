import ipaddress
from urllib.parse import urlparse, urlunparse

SHORTENERS = {"bit.ly","tinyurl.com","t.co","rb.gy","is.gd","cutt.ly"}

def analyze_url(value):
    raw = value.strip()
    candidate = raw if "://" in raw else "http://" + raw
    parsed = urlparse(candidate)
    findings = []
    score = 0
    host = (parsed.hostname or "").lower()

    def flag(message, weight):
        nonlocal score
        findings.append(message)
        score += weight

    if parsed.scheme != "https":
        flag("URL does not use HTTPS.", 15)
    if not host:
        flag("URL host could not be parsed.", 30)
    if host in SHORTENERS:
        flag("URL uses a known URL-shortening service.", 20)
    try:
        ipaddress.ip_address(host)
        flag("URL uses an IP address instead of a domain.", 25)
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        flag("Host contains an internationalized/punycode label.", 15)
    if "@" in parsed.netloc:
        flag("URL contains user-info syntax that may disguise the destination.", 20)
    if len(raw) > 120:
        flag("URL is unusually long.", 10)
    if parsed.port and parsed.port not in (80, 443):
        flag("URL uses a non-standard web port.", 10)
    if not findings:
        findings.append("No configured URL heuristics were triggered; this does not establish that the URL is safe.")

    score = min(score, 100)
    level = "Critical" if score >= 80 else "High" if score >= 55 else "Medium" if score >= 30 else "Low"
    normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))
    return {"input_url": raw, "normalized_url": normalized, "host": host, "risk_score": score, "risk_level": level, "findings": findings}
