import os
from Evtx.Evtx import Evtx
from pathlib import Path

def extract_evtx_logs(folder_path, output_file="extracted_logs.txt"):
    log_entries = []
    log_files = list(Path(folder_path).glob("*.evtx"))

    print(f"Found {len(log_files)} EVTX files to scan...\n")

    for evtx_file in log_files:
        print(f"Processing: {evtx_file.name}")
        try:
            with Evtx(str(evtx_file)) as log:
                for record in log.records():
                    entry = record.xml()
                    log_entries.append(entry)
        except Exception as e:
            print(f"Error reading {evtx_file.name}: {e}")

    # Save all entries to a single output file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n\n".join(log_entries))

    print(f"\n✅ Extracted {len(log_entries)} entries to {output_file}")
    return output_file
