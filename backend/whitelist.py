import os
import yaml
from datetime import datetime

WHITELIST_PATH = os.path.join(os.path.dirname(__file__), "whitelist.yaml")
WHITELIST_LOG_PATH = os.path.join(os.path.dirname(__file__), "whitelist_log.txt")

def load_whitelist():
    """Load the current whitelist.yaml, return a safe default if not found or keys are missing."""
    default_keys = {"ips": [], "hashes": [], "cves": [], "domains": []}
    if os.path.exists(WHITELIST_PATH):
        with open(WHITELIST_PATH, "r") as f:
            data = yaml.safe_load(f) or {}
            # Ensure all keys exist
            for key in default_keys:
                if key not in data:
                    data[key] = []
            return data
    return default_keys

def save_whitelist(data):
    """Save the updated whitelist to disk."""
    with open(WHITELIST_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False)

def log_added_iocs(iocs):
    """Optional: Log each whitelist addition for auditing."""
    with open(WHITELIST_LOG_PATH, "a") as f:
        f.write(f"\n[+] Whitelist updated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        for key, values in iocs.items():
            if values:
                f.write(f"{key}: {values}\n")

def update_whitelist(iocs: dict) -> bool:
    """
    Adds new, non-duplicate IOCs to whitelist.yaml.
    Returns True if new IOCs were added.
    """
    whitelist = load_whitelist()
    updated = False
    added = {"ips": [], "hashes": [], "cves": [], "domains": []}

    for key in whitelist:
        for item in iocs.get(key, []):
            if item not in whitelist[key]:
                whitelist[key].append(item)
                added[key].append(item)
                updated = True

    if updated:
        save_whitelist(whitelist)
        log_added_iocs(added)

    return updated
