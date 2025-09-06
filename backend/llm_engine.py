import subprocess
import os
from dotenv import load_dotenv

load_dotenv()

def query_llm(prompt: str, model: str = None) -> str:
    model = model or os.getenv("LLM_MODEL", "mistral")
    try:
        result = subprocess.run(
            ["ollama", "run", model],
            input=prompt.encode(),
            capture_output=True,
            check=True
        )
        return result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        return f"❌ Error querying model: {e.stderr.decode().strip()}"

def generate_remediation_steps(observed_threat: str, model: str = None) -> str:
    prompt = f"""
You are a senior SOC analyst.

Based on the following threat summary:
---
{observed_threat}
---

Provide **step-by-step technical remediation measures** using bullet points. Be concise, realistic, and specific to SOC workflows.

Your output must include:
- Containment & isolation (firewall rules, host isolation, port blocking)
- Threat neutralization (kill processes, delete malware, reset credentials)
- Investigation (logs to inspect, persistence mechanisms to check)
- Recovery & patching steps
- Optional: CLI commands if useful (iptable, netsh, taskkill, etc.)

Output format:
- Bullet points only
- No introduction or summary
- No generic advice
"""
    return query_llm(prompt, model)
