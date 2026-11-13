import json
import pandas as pd
import streamlit as st

from email_analyzer import analyze_email, load_demo_emails
from url_analyzer import analyze_url
from ioc_extractor import extract_iocs
from threat_intelligence import enrich_ioc
from response_engine import build_response_plan, simulate_block
from ai_copilot import explain_phishing

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp {background:radial-gradient(circle at 15% 0%,#182b43 0,#0b1220 45%,#080d17 100%);color:#e7eef8}
[data-testid="stSidebar"]{background:#0b1524;border-right:1px solid #20344d}
[data-testid="stMetric"]{background:#111f31;border:1px solid #243a55;padding:14px;border-radius:12px}
div.stButton>button{background:#176b87;color:white;border:0;border-radius:8px}
.small-muted{color:#91a6bd;font-size:.88rem}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PhishGuard AI — Phishing & Threat Intelligence")
st.caption("Email analysis • URL inspection • IOC extraction • Threat intelligence • Simulated response")
st.warning("Training/demo application. Use synthetic or authorized samples only. Reputation lookups may send submitted indicators to third-party services. Blocking is simulated and does not change firewall or endpoint controls.", icon="⚠️")

with st.sidebar:
    st.header("Analysis workspace")
    demo = load_demo_emails()
    selected_demo = st.selectbox("Load a sample email", ["Choose a sample"] + [x["name"] for x in demo])
    st.markdown("---")
    st.caption("Optional VirusTotal enrichment")
    st.caption("Set VIRUSTOTAL_API_KEY as an environment variable. The app remains usable without it.")
    st.markdown("---")
    st.caption("No email is sent. All analysis is local unless you explicitly use an external reputation API or optional AI provider.")

tab_email, tab_url, tab_ioc, tab_response, tab_about = st.tabs(
    ["✉ Email Analyzer", "◎ URL Inspector", "⌕ IOC Intelligence", "⚑ Response Center", "▤ Methodology"]
)

if "analysis" not in st.session_state:
    st.session_state.analysis = None

with tab_email:
    st.subheader("Phishing email analysis")
    sample_map = {x["name"]: x for x in demo}
    default_subject = ""
    default_sender = ""
    default_body = ""
    default_headers = ""
    if selected_demo != "Choose a sample":
        selected = sample_map[selected_demo]
        default_subject, default_sender = selected["subject"], selected["sender"]
        default_body, default_headers = selected["body"], selected["headers"]
    with st.form("email_form"):
        subject = st.text_input("Subject", value=default_subject)
        sender = st.text_input("Sender address", value=default_sender)
        headers = st.text_area("Email headers (optional)", value=default_headers, height=110)
        body = st.text_area("Email body", value=default_body, height=220)
        submitted = st.form_submit_button("Analyze email", type="primary")
    if submitted:
        result = analyze_email(subject, sender, headers, body)
        st.session_state.analysis = result
    result = st.session_state.analysis
    if result:
        c1,c2,c3 = st.columns(3)
        c1.metric("Risk score", f"{result['risk_score']}/100")
        c2.metric("Risk level", result["risk_level"])
        c3.metric("Indicators", len(result["indicators"]))
        st.progress(result["risk_score"]/100)
        st.markdown("#### Findings")
        if result["indicators"]:
            for item in result["indicators"]:
                st.write(f"• **{item['name']}** — {item['detail']} (+{item['weight']})")
        else:
            st.success("No configured phishing indicators were detected. This does not prove the email is safe.")
        st.markdown("#### Extracted indicators")
        st.json(result["iocs"])
        if st.button("Generate analyst explanation"):
            st.markdown(explain_phishing(result))
        st.download_button("Download email analysis JSON", json.dumps(result, indent=2).encode(), "phishing_analysis.json", "application/json")

with tab_url:
    st.subheader("URL inspection")
    url = st.text_input("Enter URL to inspect", placeholder="https://example.test/login")
    if st.button("Inspect URL", type="primary") and url.strip():
        url_result = analyze_url(url.strip())
        c1,c2 = st.columns(2)
        c1.metric("URL risk score", f"{url_result['risk_score']}/100")
        c2.metric("Risk level", url_result["risk_level"])
        st.write("**Normalized URL:**", url_result["normalized_url"])
        for finding in url_result["findings"]:
            st.write(f"• {finding}")
        st.caption("This is heuristic inspection, not a browser sandbox or definitive reputation verdict.")

with tab_ioc:
    st.subheader("Indicator of Compromise extraction & enrichment")
    text_input = st.text_area("Paste authorized email text, headers or security notes", height=180, placeholder="Paste content for IP, domain, URL and hash extraction...")
    if st.button("Extract and enrich IOCs"):
        iocs = extract_iocs(text_input)
        rows = []
        for kind, values in iocs.items():
            for value in values:
                rows.append({"type": kind, "indicator": value, **enrich_ioc(kind, value)})
        st.session_state.ioc_rows = rows
    rows = st.session_state.get("ioc_rows", [])
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        st.download_button("Download IOC results CSV", pd.DataFrame(rows).to_csv(index=False).encode(), "ioc_results.csv", "text/csv")
    else:
        st.info("Extracted indicators will appear here. External reputation checks require an optional API key.")

with tab_response:
    st.subheader("Response center — safe simulation")
    active = st.session_state.analysis
    if active:
        plan = build_response_plan(active)
        st.markdown("#### Recommended analyst actions")
        for step in plan:
            st.write(f"**{step['phase']}** — {step['action']}")
        st.markdown("#### Simulated IOC blocklist")
        candidates = active["iocs"].get("domains", []) + active["iocs"].get("urls", [])
        if candidates:
            choice = st.selectbox("Select an indicator to simulate blocking", candidates)
            if st.button("Add to simulated blocklist"):
                st.session_state.blocklist = simulate_block(st.session_state.get("blocklist", []), choice)
                st.success(f"{choice} added to the local simulated blocklist.")
        else:
            st.info("No URL/domain indicator available from the current email.")
        st.write("**Simulated blocklist:**", st.session_state.get("blocklist", []))
        st.download_button("Download response plan", json.dumps({"actions":plan,"simulated_blocklist":st.session_state.get("blocklist",[])}, indent=2).encode(), "response_plan.json", "application/json")
    else:
        st.info("Analyze an email first to generate a response plan.")

with tab_about:
    st.subheader("Detection methodology & limitations")
    st.markdown("""
    **Local heuristics:** sender/header inconsistencies, urgency language, credential requests, suspicious link patterns, URL shorteners, raw IP URLs, punycode markers and risky URL structures.

    **Risk score:** a transparent weighted sum capped at 100. It is a prioritization aid, not a calibrated probability of phishing.

    **IOC enrichment:** local syntax/type validation is available offline. Optional VirusTotal lookups require `VIRUSTOTAL_API_KEY` and may disclose the submitted indicator to VirusTotal.

    **AI explanation:** works with a local deterministic analyst explanation by default. Optional LLM assistance requires `OPENAI_API_KEY`; only the selected analysis result is sent to the configured API.

    **Response:** blocklist functionality is simulated only. No firewall, DNS, mail gateway or endpoint configuration is changed.
    """)

st.markdown("---")
st.caption("PhishGuard AI Portfolio Project • Heuristic detections are explainable and require analyst validation.")
