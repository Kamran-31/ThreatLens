# 🛡️ ThreatLens — Cyber Defense & Intelligence Platform

> **Know before you connect.**  
> A deterministic threat intelligence platform that aggregates multi-source reputation telemetry and delivers AI-synthesized risk analysis.

---

## ⚡ Features
- **Multi-Vector Telemetry**: Ingests signals from VirusTotal, Google Safe Browsing, AbuseIPDB, URLScan, WHOIS/RDAP, and DNS/SSL inspection.
- **Deterministic Risk Scoring**: 0–100 point algorithmic engine that calculates immutable verdicts (`SAFE`, `SUSPICIOUS`, `MALICIOUS`) independent of missing keys.
- **Knowledge-Adaptive AI Analysis**: Multi-model Gemini cascade offering level-tailored technical breakdowns (`Beginner`, `Intermediate`, `Expert`).
- **HTTP Redirect Tracer**: Maps multi-hop URL redirection chains to detect cloaking and obfuscated destinations.
- **Secure Secret Architecture**: Zero hardcoded keys, safe template defaults, and full integration with Streamlit Cloud Secrets.

---

## 🚀 Setup & Local Execution

1. **Clone the repository:**
   git clone [https://github.com/](https://github.com/)<YOUR-USERNAME>/<YOUR-REPO-NAME>.git
   cd <YOUR-REPO-NAME>

2. **Install Dependencies:**
    pip install -r requirements.txt

3. **Configure API:**
   cp .streamlit/secrets.toml.example .streamlit/secrets.toml

4. **Launch:**
    streamlit run app.py
