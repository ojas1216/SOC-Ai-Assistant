import requests
import os
import re
from dotenv import load_dotenv

from backend.whitelist import load_whitelist  # ✅ Import whitelist functions

load_dotenv()

# 🔐 API keys
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")

# 🧪 IOC extractors
def extract_iocs(text):
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return {
        "ips": list(set(ips)),
        "hashes": list(set(hashes)),
        "cves": list(set(cves))
    }

# 🌍 AbuseIPDB enrichment
def check_abuseipdb(ip, whitelist):
    private_prefixes = ("10.", "127.", "192.168", "172.16.")
    if ip.startswith(private_prefixes) or ip in whitelist["ips"]:
        return f"IP {ip}: Skipped (private or whitelisted)"

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        res = requests.get(url, headers=headers, params=params, timeout=8)
        if res.status_code == 200:
            data = res.json()["data"]
            return f"IP {ip}: {data['abuseConfidenceScore']}% abuse score, {data['countryCode']}, {data.get('domain', 'N/A')}"
        else:
            return f"IP {ip}: API Error {res.status_code}"
    except Exception as e:
        return f"IP {ip}: Error - {e}"

# 🔍 VirusTotal hash enrichment
def check_virustotal_hash(h, whitelist):
    if h in whitelist["hashes"]:
        return f"Hash {h}: Skipped (whitelisted)"

    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            stats = res.json()["data"]["attributes"]["last_analysis_stats"]
            return f"Hash {h}: {stats['malicious']} malicious / {sum(stats.values())} total detections"
        else:
            return f"Hash {h}: API Error {res.status_code}"
    except Exception as e:
        return f"Hash {h}: Error - {e}"

# 🛡️ NVD CVE enrichment
def check_nvd_cve(cve_id, whitelist):
    if cve_id.upper() in whitelist["cves"]:
        return f"{cve_id} | Skipped (whitelisted)"

    url = "https://services.nvd.nist.gov/rest/json/cve/2.0"
    headers = {"apiKey": NVD_API_KEY}
    params = {"cveId": cve_id}

    try:
        res = requests.get(url, headers=headers, params=params, timeout=10)
        res.raise_for_status()
        data = res.json()
        vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
        desc = vuln.get("descriptions", [{}])[0].get("value", "No description.")
        score = vuln.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
        return f"{cve_id} | CVSS: {score} | {desc}"
    except Exception as e:
        return f"{cve_id} | NVD lookup error: {e}"

# 🔬 Main enrichment wrapper
def enrich_with_threat_intel(log_text, progress_callback=None):
    whitelist = load_whitelist()  # ✅ Dynamically load
    iocs = extract_iocs(log_text)
    results = []
    total = len(iocs["ips"]) + len(iocs["hashes"]) + len(iocs["cves"])
    done = 0

    for ip in iocs["ips"]:
        results.append(check_abuseipdb(ip, whitelist))
        done += 1
        if progress_callback:
            progress_callback(done, total)

    for h in iocs["hashes"]:
        results.append(check_virustotal_hash(h, whitelist))
        done += 1
        if progress_callback:
            progress_callback(done, total)

    for cve in iocs["cves"]:
        results.append(check_nvd_cve(cve.upper(), whitelist))
        done += 1
        if progress_callback:
            progress_callback(done, total)

    return results
