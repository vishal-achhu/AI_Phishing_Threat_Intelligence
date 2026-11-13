def build_response_plan(analysis):
    level = analysis.get("risk_level", "Low")
    steps = [
        {"phase":"Validate", "action":"Review sender identity, authentication results, URLs and extracted IOCs. Confirm with the business owner through a trusted channel."},
        {"phase":"Contain", "action":"If confirmed malicious, follow approved mail-gateway procedures to quarantine matching messages and warn affected recipients."},
        {"phase":"Investigate", "action":"Search mail, identity and endpoint telemetry for clicks, credential submissions and related activity."},
        {"phase":"Recover", "action":"If credentials were exposed, follow identity-team procedures for password reset, session revocation and MFA review."},
        {"phase":"Document", "action":"Preserve the original message and record evidence, timeline, scope, decisions and lessons learned."}
    ]
    if level in ("High", "Critical"):
        steps.insert(1, {"phase":"Escalate", "action":"Prioritize analyst review and notify the security lead according to the organization's incident severity policy."})
    return steps

def simulate_block(blocklist, indicator):
    """Append to an in-app demo list only; no network controls are modified."""
    clean = list(blocklist)
    if indicator not in clean:
        clean.append(indicator)
    return clean
