import os, json, urllib.request, urllib.error

def local_explanation(result):
    indicators = result.get("indicators", [])
    findings = "\n".join(f"- {x['name']}: {x['detail']}" for x in indicators) or "- No configured indicators triggered."
    return f"""### Analyst assessment
The email received a **{result.get('risk_level')}** heuristic risk rating ({result.get('risk_score')}/100).

### Observed indicators
{findings}

### Extracted IOCs
{json.dumps(result.get('iocs', {}), indent=2)}

### Recommended next steps
1. Validate sender identity using a known-good contact method.
2. Inspect email authentication results and the final destination of links.
3. Enrich extracted indicators using approved threat intelligence sources.
4. Search mail and endpoint telemetry for related activity.
5. Preserve the original email and document the investigation.

**Caution:** This score is a transparent heuristic, not proof of phishing. A clean result does not prove an email is safe.
"""

def explain_phishing(result):
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        return local_explanation(result)
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    prompt = (
        "Assist a phishing analyst. Use only supplied data. Distinguish observed facts from hypotheses. "
        "Do not claim compromise is confirmed. Recommend validation steps and safe response actions.\n\n"
        + json.dumps(result, indent=2)
    )
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role":"system","content":"You are a cautious email security analyst assistant."},
            {"role":"user","content":prompt}
        ],
        "temperature":0.2
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
        return data["choices"][0]["message"]["content"]
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as exc:
        return local_explanation(result) + f"\n\n> Optional AI service unavailable; local explanation used: {exc}"
