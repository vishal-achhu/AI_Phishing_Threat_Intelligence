# PhishGuard AI — AI-Powered Phishing Detection & Threat Intelligence

A portfolio project for email security analysis, explainable phishing heuristics, URL inspection, IOC extraction, optional VirusTotal enrichment, optional LLM explanations and a simulated response workflow.

> **Safety and scope:** This is a training/demo application. Use only synthetic or authorized samples. It does not send email, visit submitted URLs, execute attachments or change firewall/DNS/mail controls. External reputation and AI APIs may receive the submitted indicators or analysis content when enabled.

## Features

- Analyze email subject, sender, headers and body.
- Detect configured phishing indicators: urgency language, credential requests, payment requests, Reply-To mismatch, SPF/DKIM/DMARC failure markers, raw-IP links and URL shorteners.
- Calculate a transparent weighted risk score.
- Extract IPs, domains, URLs and MD5/SHA1/SHA256-shaped hashes.
- Inspect URL structure using local heuristics without visiting the URL.
- Optionally enrich IP/domain/URL indicators using VirusTotal v3.
- Generate local analyst explanations without an API key.
- Optionally generate LLM-assisted explanations.
- Create a response plan and simulate an IOC blocklist in the app only.
- Export analysis JSON, IOC CSV and response plan JSON.

## Quick start

Python 3.10+ recommended.

Windows PowerShell:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

The app works without API keys using local analysis and sample emails.

## Optional VirusTotal enrichment

Set `VIRUSTOTAL_API_KEY` in your environment before launching. For example, Windows PowerShell:
```powershell
$env:VIRUSTOTAL_API_KEY="your-key"
streamlit run app.py
```

The app supports VirusTotal v3 lookups for IP addresses, domains and URLs. Hash lookup is not enabled. Respect the provider's terms, quotas and privacy rules. Do not submit private or sensitive indicators without authorization.

## Optional AI explanations

Set:
```powershell
$env:OPENAI_API_KEY="your-key"
$env:OPENAI_MODEL="gpt-4.1-mini"
streamlit run app.py
```

Without the key, a deterministic local analyst playbook is used. Never commit API keys to source control.

## How risk scoring works

The scoring system adds configurable weights for detected indicators and caps the result at 100:
- Urgency / pressure language: 15
- Credential/authentication request: 20
- Payment/financial request: 15
- Reply-To mismatch: 20
- Authentication failure marker: 20
- Raw IP URL: 20
- URL shortener: 10
- Unusual sender syntax: 10

Risk bands: Low (0–29), Medium (30–54), High (55–79), Critical (80–100). These are illustrative thresholds, not a calibrated probability of phishing. Tune them against a labeled dataset before making performance claims.

## Project structure

```text
AI-Phishing-Threat-Intelligence/
├── app.py
├── email_analyzer.py
├── url_analyzer.py
├── ioc_extractor.py
├── threat_intelligence.py
├── response_engine.py
├── ai_copilot.py
├── sample_emails/
├── tests/
├── reports/
├── screenshots/
├── requirements.txt
└── README.md
```

## Testing

```bash
python -m unittest discover -s tests -v
```

## Resume description

**AI-Powered Phishing Detection & Threat Intelligence Platform**  
Developed a Python-based email security application to identify phishing indicators, inspect suspicious URLs and extract indicators of compromise. Implemented explainable risk scoring, optional VirusTotal reputation enrichment, AI-assisted analyst explanations and simulated threat-response workflows.

Only claim API integration as completed after testing it with an authorized API key. Clearly describe the blocklist as simulated.

