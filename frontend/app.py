import streamlit as st
import os
import sys
import time
from pathlib import Path

# 🛠️ Fix backend import path
sys.path.append(str(Path(__file__).resolve().parent.parent))

# 🧠 Backend imports
from backend.llm_engine import query_llm, generate_remediation_steps
from backend.threat_intel import enrich_with_threat_intel, extract_iocs
from backend.risk_scorer import calculate_risk_score
from backend.whitelist import update_whitelist  # ✅ NEW

# ⚙️ Streamlit Settings
st.set_page_config(page_title="SOC AI Assistant", layout="wide")
st.title("🛡️ SOC AI Assistant")
st.markdown("Upload security logs to get instant AI-powered threat insights and remediation steps.")

# 🎯 Model Selector
model_choice = st.sidebar.selectbox("🔍 Choose LLM Model", ["mistral", "llama2", "llama3"])

# ✅ Optional: Enable/disable auto-whitelist
auto_whitelist = st.sidebar.checkbox("✅ Auto-whitelist safe files", value=True)



# 📁 Upload Section
uploaded_file = st.file_uploader("📁 Upload a log file (.json or .txt)", type=["json", "txt"])


if uploaded_file:
    file_content = uploaded_file.read().decode("utf-8", errors="ignore")

    # 👁️ Preview Logs
    st.subheader("📄 Log Preview:")
    st.code(file_content[:3000], language="json" if uploaded_file.name.endswith("json") else "text")

    # 🧠 Trigger LLM Analysis
    if st.button("🧠 Analyze with LLM"):
        with st.spinner("Analyzing with local LLM... please wait"):
            try:
                prompt = f"""You are a senior security analyst. Analyze the following log entries to detect:

1. Known threats (based on CVEs, malware hashes, suspicious IPs)
2. Unknown or zero-day threats (based on unusual patterns or behavior)
3. Anomalous activity that might indicate lateral movement, data exfiltration, privilege escalation, or unauthorized access.

For each finding, provide:
- Description of the behavior
- Reason it's suspicious or malicious
- Whether it's known or possibly a zero-day


---
{file_content}
---"""

                response = query_llm(prompt, model=model_choice)
            except Exception as e:
                st.error(f"❌ LLM processing failed: {e}")
                st.stop()

        st.success("✅ LLM Analysis Complete")

        # 🌸 Display Summary
        st.subheader("🌸 Threat Summary:")
        st.markdown(response or "No threats detected.")

        # 🔍 Threat Intel Enrichment
        st.subheader("📦 Threat Intelligence Enrichment:")
        try:
            intel_progress = st.progress(0, text="Extracting IOCs and starting enrichment...")

            def update_progress(done, total):
                percent = done / total if total else 1
                intel_progress.progress(percent, text=f"Enriching IOCs: {done}/{total} complete")

            intel = enrich_with_threat_intel(file_content, progress_callback=update_progress)
            intel_progress.progress(1.0, text="✅ Threat enrichment complete")
            time.sleep(0.3)
            intel_progress.empty()

            if intel:
                st.code("\n".join(intel))
            else:
                st.info("No enrichable IPs, hashes, or CVEs found.")

            # ✅ Auto-whitelist if all IOCs skipped or safe
            all_safe = all(
                "Skipped" in line or "0 malicious" in line or "No enrichable" in line
                for line in intel
            )

            if auto_whitelist and all_safe and ("no threats" in response.lower() or "no suspicious" in response.lower()):
                iocs = extract_iocs(file_content)
                if update_whitelist(iocs):
                    st.success("✅ File is clean. IOCs auto-added to whitelist.")
                else:
                    st.info("File is clean but contains no new IOCs to whitelist.")
            elif auto_whitelist and not all_safe:
                st.warning("⚠️ Auto-whitelist skipped due to possibly suspicious IOCs.")
        except Exception as e:
            intel = []
            intel_progress.empty()
            st.warning(f"Threat intel enrichment failed: {e}")

        # 🛠️ Remediation Suggestions
        st.subheader("🧯 Recommended Remediation Steps:")
        try:
            threat_summary = response[:1500]
            progress_remed = st.progress(0, text="Generating remediation steps...")

            time.sleep(0.5)
            progress_remed.progress(0.3, text="Analyzing threat context...")
            time.sleep(0.5)

            remediation = generate_remediation_steps(threat_summary, model=model_choice)
            progress_remed.progress(1.0, text="✅ Remediation ready")
            time.sleep(0.2)
            progress_remed.empty()

            if remediation:
                st.markdown(remediation)
            else:
                st.warning("No remediation suggestions returned.")
        except Exception as e:
            progress_remed.empty()
            st.error(f"Error during remediation generation: {e}")

        # 🚨 Risk Score & MITRE ATT&CK Mapping
        st.subheader("🚨 Risk Score & MITRE ATT&CK Mapping:")
        try:
            score, mitre_hits = calculate_risk_score(file_content, intel)
            st.markdown(f"**Risk Score:** {score} / 10")
            if mitre_hits:
                for tid, desc in mitre_hits:
                    st.markdown(f"- `{tid}` : {desc}")
            else:
                st.info("No MITRE techniques detected.")
        except Exception as e:
            st.error(f"Error during risk scoring or MITRE mapping: {e}")

# 👣 Footer
st.markdown("---")
st.markdown("Made with ❤️ for SOC Teams | Runs locally using Ollama + Streamlit")
