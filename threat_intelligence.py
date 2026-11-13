import os
import json
import urllib.request
import urllib.error

def enrich_ioc(kind, indicator):
    """Offline syntax enrichment by default; optional VirusTotal v3 lookup."""
    result = {"source": "Local validation", "reputation": "Unknown", "details": "No external lookup performed."}
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        result["details"] = "Set VIRUSTOTAL_API_KEY to enable optional VirusTotal lookup."
        return result

    # VirusTotal URL lookup uses URL identifiers; IP/domain use corresponding endpoints.
    if kind == "urls":
        import base64
        identifier = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{identifier}"
    elif kind == "ips":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif kind == "domains":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    else:
        result["details"] = "Hash reputation lookup is not enabled in this demo."
        return result

    request = urllib.request.Request(endpoint, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode())
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        result.update({
            "source": "VirusTotal",
            "reputation": "Malicious" if malicious else "Suspicious" if suspicious else "No detections reported",
            "details": f"Malicious: {malicious}; suspicious: {suspicious}; harmless: {stats.get('harmless',0)}; undetected: {stats.get('undetected',0)}"
        })
    except (urllib.error.URLError, ValueError, TimeoutError, KeyError) as exc:
        result.update({"source": "VirusTotal", "reputation": "Lookup unavailable", "details": str(exc)})
    return result
