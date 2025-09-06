import re

# 🔐 Sample MITRE technique mapping
MITRE_MAPPING = {
    "powershell": ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "cmd.exe": ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
    "base64": ("T1027", "Obfuscated Files or Information"),
    "wget": ("T1105", "Ingress Tool Transfer"),
    "curl": ("T1105", "Ingress Tool Transfer"),
    "certutil": ("T1105", "Ingress Tool Transfer"),
    "suspicious_ip": ("T1071", "Application Layer Protocol")
}

def calculate_risk_score(text, threat_iocs=None):
    risk = 0
    mitre_ids = set()

    # Check for behavior-based patterns
    for keyword, (tid, description) in MITRE_MAPPING.items():
        if keyword.lower() in text.lower():
            risk += 2
            mitre_ids.add((tid, description))

    # Check for known malicious indicators
    if threat_iocs:
        for result in threat_iocs:
            if "malicious" in result.lower() or "abuse score" in result.lower():
                risk += 3
                mitre_ids.add(MITRE_MAPPING.get("suspicious_ip"))

    # Cap risk score to 10
    risk = min(risk, 10)

    return risk, list(mitre_ids)
