import re
from urllib.parse import urlparse
from ioc_extractor import extract_iocs

URGENT = ["urgent", "immediately", "within 24 hours", "account suspended", "verify now", "final warning", "action required"]
CREDENTIALS = ["password", "login", "sign in", "verify your account", "reset your password", "one-time password", "otp"]
PAYMENT = ["gift card", "wire transfer", "payment overdue", "bank details", "invoice attached"]

def load_demo_emails():
    return [
        {
            "name": "Sample A — Suspicious account verification",
            "subject": "URGENT: Verify your account immediately",
            "sender": "security-alert@example-mail.test",
            "headers": "From: security-alert@example-mail.test\nReply-To: helpdesk@different-domain.test\nAuthentication-Results: spf=fail; dkim=fail",
            "body": "Your account will be suspended within 24 hours. Verify your account and sign in at http://198.51.100.77/secure-login to avoid losing access. Enter your password and OTP.",
        },
        {
            "name": "Sample B — Routine internal notice",
            "subject": "Team meeting agenda for Thursday",
            "sender": "calendar@example.test",
            "headers": "From: calendar@example.test\nAuthentication-Results: spf=pass; dkim=pass",
            "body": "Hello team, the agenda for Thursday's project meeting is attached. Please review the discussion topics before the meeting.",
        },
        {
            "name": "Sample C — Suspicious invoice request",
            "subject": "Payment overdue — invoice attached",
            "sender": "billing@vendor-payment.test",
            "headers": "From: billing@vendor-payment.test\nReply-To: accounts@unrelated-mail.test\nAuthentication-Results: spf=softfail",
            "body": "Action required. Your payment is overdue. Please review the invoice and update bank details at https://secure-update.example.test/billing.",
        }
    ]

def analyze_email(subject, sender, headers, body):
    text = f"{subject}\n{sender}\n{headers}\n{body}"
    lower = text.lower()
    indicators = []

    def add(name, detail, weight):
        indicators.append({"name": name, "detail": detail, "weight": weight})

    if any(word in lower for word in URGENT):
        add("Urgency / pressure language", "Contains language intended to prompt immediate action.", 15)
    if any(word in lower for word in CREDENTIALS):
        add("Credential or authentication request", "Requests account verification, login, password or OTP-related action.", 20)
    if any(word in lower for word in PAYMENT):
        add("Payment / financial request", "Contains payment or banking-related language.", 15)
    if "reply-to:" in headers.lower():
        reply = re.search(r"(?im)^reply-to:\s*(\S+)", headers)
        if reply and sender and reply.group(1).lower() not in sender.lower():
            add("Reply-To mismatch", "Reply-To address differs from the visible sender address.", 20)
    if re.search(r"(?im)^authentication-results:.*(spf=fail|dkim=fail|dmarc=fail)", headers):
        add("Email authentication failure", "Headers report SPF, DKIM or DMARC failure.", 20)
    if re.search(r"(?i)https?://(?:\d{1,3}\.){3}\d{1,3}", body):
        add("URL uses raw IP address", "A link points directly to an IPv4 address rather than a domain.", 20)
    if re.search(r"(?i)https?://(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy)/", body):
        add("URL shortener", "A shortened URL hides the final destination.", 10)
    if sender and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender.strip()):
        add("Unusual sender address format", "Sender address does not match a basic email format.", 10)

    score = min(100, sum(x["weight"] for x in indicators))
    level = "Critical" if score >= 80 else "High" if score >= 55 else "Medium" if score >= 30 else "Low"
    return {
        "subject": subject,
        "sender": sender,
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "iocs": extract_iocs(text),
        "disclaimer": "Heuristic risk score, not a calibrated probability or definitive verdict."
    }
