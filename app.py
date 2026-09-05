"""
app.py - ThreatLens Deterministic Cybersecurity Engine
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st
from sources import SOURCES, get_dns_ssl_intel, trace_redirects

APP_TITLE = "THREATLENS"
APP_TAGLINE = "Know before you connect."

# Active Gemini models in cascade order
GEMINI_MODELS = [
    "gemini-3.0-flash",
    "gemini-2.5-pro",
    "gemini-3.5-flash",
    "gemini-3.6-flash",
    "gemini-3.7-flash",
]


def _get_key(name: str) -> Optional[str]:
    val = os.environ.get(name)
    if val:
        return val
    try:
        return st.secrets.get(name)
    except Exception:
        return None


def calculate_risk(results: Dict[str, Any], url_trace: Optional[Dict[str, Any]]) -> Tuple[int, str, List[str]]:
    score = 0
    signals: List[str] = []

    # 1. VirusTotal
    vt = results.get("VirusTotal", {}).get("data", {})
    vt_mal = vt.get("malicious", 0)
    if vt_mal >= 3:
        score += 65
        signals.append(f"VirusTotal detected {vt_mal} distinct security engines flagging this target.")
    elif vt_mal > 0:
        score += 35
        signals.append(f"VirusTotal detected {vt_mal} suspicious engine indicator.")

    # 2. Google Safe Browsing
    gsb = results.get("Google Safe Browsing", {}).get("data", {})
    if gsb.get("is_flagged"):
        score += 70
        signals.append(f"Google Safe Browsing match: {', '.join(gsb.get('threat_types', []))}.")

    # 3. AbuseIPDB
    abuse = results.get("AbuseIPDB", {}).get("data", {})
    conf = abuse.get("abuse_confidence_score", 0)
    if conf > 40:
        score += min(50, int(conf * 0.6))
        signals.append(f"AbuseIPDB host confidence score reached {conf}%.")

    # 4. WHOIS / Age
    whois = results.get("WHOIS/RDAP", {}).get("data", {})
    age = whois.get("domain_age_days")
    if age is not None:
        if age < 14:
            score += 30
            signals.append(f"Domain is newly provisioned ({age} days old).")
        elif age < 60:
            score += 15
            signals.append(f"Domain registration is relatively recent ({age} days old).")

    # 5. URL Redirects
    if url_trace and url_trace.get("redirect_count", 0) > 2:
        score += 15
        signals.append(f"Target chained across {url_trace['redirect_count']} HTTP redirection hops.")

    # 6. URLScan
    urlscan = results.get("URLScan", {}).get("data", {})
    if urlscan.get("overall_malicious"):
        score += 40
        signals.append("URLScan engine reported overall malicious telemetry.")

    score = min(100, max(0, score))
    active_sources = [r for r in results.values() if r.get("status") == "success"]

    if len(active_sources) == 0:
        verdict = "UNKNOWN"
    elif score >= 60:
        verdict = "MALICIOUS"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return score, verdict, signals


def explain_with_gemini(target: str, verdict: str, score: int, signals: List[str], level: str) -> Dict[str, Any]:
    api_key = _get_key("GEMINI_API_KEY")
    if not api_key:
        return {
            "summary": f"Target calculated as {verdict} with a deterministic risk score of {score}/100.",
            "technical_breakdown": "Deterministic evaluation executed without external AI processing.",
            "findings": signals or ["No active malicious signatures detected across queried feeds."],
            "recommendation": "Standard network safeguards apply.",
        }

    prompts = {
        "Beginner": (
            "Explain in clear, practical terms with relatable real-world analogies. "
            "Avoid acronyms and technical jargon. Focus on safety and simple precautions."
        ),
        "Intermediate": (
            "Provide a solid technical summary. Analyze detection counts, reputation scores, "
            "domain registration signals, and network indicators cleanly."
        ),
        "Expert": (
            "Deliver an in-depth InfoSec threat analysis. Evaluate telemetry vectors, false-positive considerations, "
            "infrastructure trust attributes, and mitigation controls."
        ),
    }

    prompt = f"""You are a principal cybersecurity intelligence analyst generating an assessment for ThreatLens.
The risk score and verdict have ALREADY been deterministically calculated. You MUST strictly adopt this verdict.

Target Asset: {target}
Calculated Verdict: {verdict}
Risk Score: {score}/100 (Higher means more dangerous, 0 means completely clean)
Observed Signals: {json.dumps(signals)}
Knowledge Profile: {level} ({prompts.get(level, prompts['Intermediate'])})

Generate a detailed, substantive assessment. Return ONLY a valid JSON object matching this schema:
{{
  "summary": "Thorough overview (3-4 sentences) breaking down why this asset was designated as {verdict} at the {level} tier.",
  "technical_breakdown": "Detailed paragraph dissecting infrastructure signals, registration age, redirect behavior, and vendor reputations.",
  "findings": [
    "Detailed finding 1 with context",
    "Detailed finding 2 with context",
    "Detailed finding 3 with context",
    "Detailed finding 4 with context"
  ],
  "recommendation": "Precise, multi-step actionable security guidance tailored to this evaluation."
}}"""

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
    except ImportError:
        return {
            "summary": f"Target evaluated as {verdict} ({score}/100).",
            "technical_breakdown": "Deterministic evaluation completed.",
            "findings": signals or ["Clean reputation indicators recorded."],
            "recommendation": "Follow standard precautions.",
        }

    for model_name in GEMINI_MODELS:
        try:
            model = genai.GenerativeModel(model_name)
            resp = model.generate_content(prompt)
            text = re.sub(r"^```(json)?", "", resp.text.strip(), flags=re.IGNORECASE).strip()
            text = re.sub(r"```$", "", text).strip()
            return json.loads(text)
        except Exception as exc:
            err_msg = str(exc).lower()
            if "429" in err_msg or "quota" in err_msg:
                time.sleep(1.5)
                continue
            if "404" in err_msg or "not found" in err_msg:
                continue
            continue

    return {
        "summary": f"Asset evaluated as {verdict} with a score of {score}/100 based on active deterministic security telemetry.",
        "technical_breakdown": "Automated security rule checks completed successfully across available telemetry providers.",
        "findings": signals or ["Telemetry indicates acceptable reputation markers with no critical anomalies detected."],
        "recommendation": "Follow standard security policies when interacting with this domain or IP.",
    }


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")

    st.markdown(
        """
        <style>
            .stApp { background-color: #0b0f19; color: #e2e8f0; }
            
            /* High-contrast styling for top-right 3 dots */
            #MainMenu button, header button, [data-testid="baseButton-header"] {
                color: #0f172a !important;
                background-color: #cbd5e1 !important;
                border-radius: 6px !important;
                padding: 4px !important;
            }
            #MainMenu svg, header svg {
                fill: #0f172a !important;
                stroke: #0f172a !important;
            }
            
            /* Field label headers: bold and high-contrast */
            label p, .stSelectbox label p, .stTextInput label p {
                color: #f8fafc !important;
                font-weight: 700 !important;
                font-size: 0.95rem !important;
                letter-spacing: 0.25px !important;
            }
            
            .metric-card { background: #151d30; border-radius: 10px; padding: 1.25rem; border: 1px solid #222f4c; }
            
            /* ThreatLens custom footer */
            .threatlens-footer {
                margin-top: 4.5rem;
                padding-top: 1.5rem;
                border-top: 1px solid #1e293b;
                text-align: center;
                color: #64748b;
                font-size: 0.85rem;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.title("🛡️ THREATLENS")
    st.caption(f"_{APP_TAGLINE}_")

    col1, col2, col3 = st.columns([2, 5, 2])
    with col1:
        target_type = st.selectbox("Target Type", ["URL", "Domain", "IP Address"])
    with col2:
        raw_target = st.text_input("Target String", placeholder="https://example.com, example.com, 1.1.1.1")
    with col3:
        level = st.selectbox("Knowledge Level", ["Beginner", "Intermediate", "Expert"])

    if st.button("🔍 Run Analysis", type="primary", use_container_width=True):
        if not raw_target.strip():
            st.error("Please enter a valid target to analyze.")
            return

        with st.status("Gathering Multi-Source Intelligence...", expanded=True) as status:
            results = {}
            for name, fn in SOURCES.items():
                results[name] = fn(raw_target, target_type)

            redirects = trace_redirects(raw_target) if target_type == "URL" else None
            dns_ssl = get_dns_ssl_intel(raw_target, target_type)
            score, verdict, signals = calculate_risk(results, redirects)
            explanation = explain_with_gemini(raw_target, verdict, score, signals, level)
            status.update(label="Analysis Completed", state="complete", expanded=False)

        st.session_state["analysis_cache"] = {
            "target": raw_target,
            "target_type": target_type,
            "results": results,
            "redirects": redirects,
            "dns_ssl": dns_ssl,
            "score": score,
            "verdict": verdict,
            "signals": signals,
            "explanation": explanation,
            "level": level,
        }

    data = st.session_state.get("analysis_cache")
    if not data:
        st.markdown(
            """
            <div class="threatlens-footer">
                <strong>ThreatLens</strong> — Intelligence & Verification Platform<br>
                <span>Automated threat telemetry and deterministic risk scoring.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # Dynamic explanation update if level changes without modifying scoring
    if data["level"] != level:
        data["explanation"] = explain_with_gemini(data["target"], data["verdict"], data["score"], data["signals"], level)
        data["level"] = level

    st.divider()

    # Output banner: Verdict, Safety rating, Risk score (without "Synthesized by")
    v_colors = {"SAFE": "#10B981", "SUSPICIOUS": "#F59E0B", "MALICIOUS": "#EF4444", "UNKNOWN": "#6B7280"}
    v_color = v_colors.get(data["verdict"], "#6B7280")
    safety_percentage = max(0, 100 - data["score"])

    st.markdown(
        f"""
        <div style="background-color: {v_color}18; border-left: 6px solid {v_color}; padding: 1.25rem; border-radius: 8px; margin-bottom: 1.5rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap: 10px;">
                <div>
                    <h2 style="margin:0; color:{v_color}; font-weight:800; display:inline-block;">{data['verdict']}</h2>
                    <span style="background-color:{v_color}33; color:{v_color}; font-weight:700; padding:3px 10px; border-radius:12px; margin-left:12px; font-size:0.95rem;">
                        Safety Rating: {safety_percentage}%
                    </span>
                </div>
                <h3 style="margin:0; color:#cbd5e1; font-weight:600;">Risk Score: {data['score']}/100</h3>
            </div>
            <p style="margin-top:0.6rem; margin-bottom:0; color:#94a3b8;">
                Target: <code>{data['target']}</code>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Detailed AI Intelligence Section
    st.subheader(f"AI Security Insight ({data['level']})")
    st.markdown(f"**Executive Overview**\n\n{data['explanation'].get('summary', '')}")
    
    if data["explanation"].get("technical_breakdown"):
        st.markdown(f"**Detailed Vector Assessment**\n\n{data['explanation'].get('technical_breakdown')}")

    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown("**Key Finding Signals**")
        findings = data["explanation"].get("findings", [])
        for f in findings:
            st.markdown(f"- {f}")
    with c2:
        st.markdown("**Actionable Guidance**")
        st.info(data["explanation"].get("recommendation", ""))

    # URL Redirection Chain
    if data.get("redirects") and data["redirects"].get("success"):
        st.subheader("URL Redirection Path")
        chain = data["redirects"].get("chain", [])
        cols = st.columns(len(chain))
        for idx, step in enumerate(chain):
            with cols[idx]:
                st.markdown(f"**Step {idx + 1}** (`HTTP {step['status_code']}`)")
                st.caption(f"`{step['url']}`")

    # Domain, DNS & SSL Details
    whois_data = data["results"].get("WHOIS/RDAP", {}).get("data", {})
    dns_ssl = data.get("dns_ssl", {})

    st.subheader("Domain & Infrastructure Intelligence")
    d1, d2, d3 = st.columns(3)
    with d1:
        st.markdown("**Domain Registration**")
        if whois_data:
            st.write(f"**Registrar:** {whois_data.get('registrar', 'Unknown')}")
            st.write(f"**Created:** {whois_data.get('creation_date', 'Unknown')}")
            st.write(f"**Expires:** {whois_data.get('expiration_date', 'Unknown')}")
            age = whois_data.get('domain_age_days')
            st.write(f"**Domain Age:** {f'{age} days' if age is not None else 'Unknown'}")
        else:
            st.write("No registration data available.")

    with d2:
        st.markdown("**DNS Configuration**")
        dns_records = dns_ssl.get("dns", {})
        for record_type in ["A", "MX", "NS"]:
            vals = dns_records.get(record_type, [])
            st.write(f"**{record_type}:** {', '.join(vals) if vals else 'None'}")

    with d3:
        st.markdown("**SSL Certificate Status**")
        ssl_data = dns_ssl.get("ssl", {})
        if ssl_data.get("valid"):
            st.success(f"Valid Certificate\n\nIssuer: {ssl_data.get('issuer')}\n\nExpires: {ssl_data.get('expires')} ({ssl_data.get('days_left')} days left)")
        else:
            st.warning(f"SSL Status: {ssl_data.get('error', 'No SSL details available')}")

    # Security Intelligence Feeds
    st.subheader("Security Intelligence Feeds")
    source_cols = st.columns(3)
    idx = 0
    for s_name, s_res in data["results"].items():
        with source_cols[idx % 3]:
            badge = "✓ Available" if s_res.get("status") == "success" else "✕ Unavailable"
            with st.expander(f"{s_name} ({badge})"):
                if s_res.get("status") == "success":
                    st.json(s_res.get("data", {}))
                else:
                    st.caption(s_res.get("error", "Source query failed"))
        idx += 1

    # ThreatLens branding footer
    st.markdown(
        """
        <div class="threatlens-footer">
            <strong>ThreatLens</strong> — Deterministic Cyber Defense & Intelligence Platform<br>
            <span>Telemetry analyzed via multi-vector reputation engines.</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()