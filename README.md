🛡️ SOC AI Assistant

⚠️ Security Notice (Read First)

Do not use any API keys committed in this repository.
They are demo-only and may be rate-limited, revoked, or unsafe to rely on.
Generate your own keys from the official providers and place them in your local .env.
Instructions are below in “Generate Your Own API Keys”.








An AI-powered Security Operations Center (SOC) Assistant that automates log preprocessing, threat intelligence enrichment, risk scoring, LLM-driven analysis, and report generation — helping SOC teams reduce alert fatigue and prioritize incidents faster.

✨ Features

🔍 Preprocessing: Normalize raw logs (JSON, TXT, PCAP summaries) for consistent downstream analysis.

🤖 LLM Analysis: Summaries, detections, and remediation suggestions via backend/llm_engine.py.

🌐 Threat Intel Enrichment: AbuseIPDB, VirusTotal, and NVD lookups via backend/threat_intel.py.

⚖️ Risk Scoring: Prioritize incidents using backend/risk_scorer.py.

📑 Report Generation: Structured incident reports using backend/report_generator.py.

✅ Whitelisting: Suppress benign entities via backend/whitelist.yaml.

🖥 Simple UI: Streamlit app in frontend/app.py for uploads, analysis, and report downloads.

🗂 Project Structure
soc-ai-assistant/
├─ backend/
│  ├─ llm_engine.py
│  ├─ preprocessor.py
│  ├─ threat_intel.py
│  ├─ risk_scorer.py
│  ├─ report_generator.py
│  ├─ whitelist.py
│  ├─ whitelist.yaml
│  └─ example_inputs/
├─ frontend/
│  └─ app.py
├─ inputs/                # Sample logs for demo
├─ requirements.txt
├─ README.md
└─ .env                   # Your local secrets (DO NOT COMMIT)

⚙️ Installation

Clone

git clone https://github.com/ojas1216/soc-ai-assistant.git
cd soc-ai-assistant


Create a virtual environment (recommended)

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate


Install dependencies

pip install -r requirements.txt


Create a .env file (see next section for keys)

LLM_MODEL=mistral
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VT_API_KEY=your_virustotal_api_key_here
NVD_API_KEY=your_nvd_api_key_here

🔑 Generate Your Own API Keys (Required)
1) AbuseIPDB

Site: https://www.abuseipdb.com/

Steps: Sign up → Account Settings → API Key → copy it into ABUSEIPDB_API_KEY.

2) VirusTotal

Site: https://www.virustotal.com/gui/join-us

Steps: Create account → User Profile → API Key → copy into VT_API_KEY.

3) NVD (National Vulnerability Database)

Site: https://nvd.nist.gov/developers/request-an-api-key

Steps: Request key → check email → copy into NVD_API_KEY.

💡 Tip: Never commit your personal keys. Keep .env local and listed in .gitignore.

▶️ Run the App
streamlit run frontend/app.py


Workflow:

Open the local URL shown by Streamlit.

Upload a sample log from inputs/ (e.g., high_risk.json).

Review LLM analysis, threat intel enrichment, and risk score.

Generate/download the incident report.

🧪 Quick CLI Tests (optional)

Test LLM backend

python backend/test_llm.py


Try example inputs
Use files in backend/example_inputs/ and inputs/ within the Streamlit UI.

🔒 Security & Best Practices

Do not commit .env or any keys to Git.

Add to .gitignore:

.env
__pycache__/
*.pyc
.venv/


If you accidentally committed secrets:

Rotate the keys in the provider dashboards.

Remove from tracking: git rm --cached .env && git commit -m "Remove .env" && git push.

(Advanced) Rewrite history with git filter-repo and force-push.

🧭 Roadmap

SIEM integrations (ELK, Splunk, QRadar)

Real-time streaming / ingestion

Richer visualizations & timelines

Pluggable LLMs and offline modes

🤝 Contributing

Fork the repo

Create a feature branch: git checkout -b feat/awesome-thing

Commit your changes: git commit -m "Add awesome thing"

Push and open a PR

📜 License

This project is licensed under the MIT License.

🙌 Acknowledgements

Streamlit

AbuseIPDB, VirusTotal, NVD

The broader cybersecurity & AI communities

📣 Disclaimer

This project is for educational and research purposes. Use responsibly and in accordance with all applicable laws and the terms of service of third-party APIs.

## 📜 License

This project is licensed under the **Creative Commons Attribution-NoDerivatives 4.0 International License (CC BY-ND 4.0)**.  
You may use and share this project as-is, but you may not modify or redistribute it.  

Full license text: [LICENSE](./LICENSE)
