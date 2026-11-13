import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>'\"]+")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|test|io|co|info|biz|dev|app|cloud|site|xyz|online|top|ru|uk|in)\b")
HASH_RE = re.compile(r"(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b")

def extract_iocs(text):
    urls = sorted(set(x.rstrip(".,);]") for x in URL_RE.findall(text or "")))
    domains = set(DOMAIN_RE.findall(text or ""))
    for url in urls:
        try:
            host = urlparse(url).hostname
            if host and not IP_RE.fullmatch(host):
                domains.add(host.lower())
        except Exception:
            pass
    ips = sorted(set(IP_RE.findall(text or "")))
    hashes = sorted(set(HASH_RE.findall(text or "")))
    return {
        "ips": ips,
        "domains": sorted(x.lower() for x in domains),
        "urls": urls,
        "hashes": hashes
    }
