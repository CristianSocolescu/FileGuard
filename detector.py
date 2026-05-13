import os
import hashlib
import json
from datetime import datetime
import yara

from scanner import identify_file
from database import save_scan_result
from virustotal_check import check_hash_virustotal


def load_yara_rules():
    # Target folders based on high-fidelity Yara-Rules repository categories
    target_folders = ['malware', 'maldocs', 'webshells', 'cve_rules']
    repo_path = './yara_rules_repo'
    
    valid_filepaths = {}

    # Iterate through selected directories and validate each rule file
    for folder in target_folders:
        folder_path = os.path.join(repo_path, folder)
        
        if not os.path.exists(folder_path):
            continue

        for filename in os.listdir(folder_path):
            if filename.endswith('.yar') or filename.endswith('.yara'):
                file_path = os.path.join(folder_path, filename)
                
                try:
                    yara.compile(filepath=file_path)
                    valid_filepaths[filename] = file_path
                except yara.Error:
                    pass
    if valid_filepaths:
        try:
            return yara.compile(filepaths=valid_filepaths)
        except Exception:
            return None
    return None


yara_engine = load_yara_rules()

WAZUH_LOG_FILE = "/var/log/file-scanner/alerts.json"


def write_wazuh_event(filename, filepath, actual_type, file_extension,
                      is_suspicious, file_hash, vt_found,
                      vt_malicious, vt_suspicious, vt_error, yara_match="none"):
    event = {
        "source": "file_type_scanner",
        "scan_type": "file_scan",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "filename": filename,
        "filepath": filepath,
        "detected_type": actual_type,
        "extension": file_extension,
        "sha256": file_hash,
        # added str()
        "is_suspicious": str(is_suspicious).lower(), 
        "vt_found": str(vt_found).lower(),
        "vt_malicious": str(vt_malicious),
        "vt_suspicious": str(vt_suspicious),
        "vt_error": str(vt_error) if vt_error else "null",
        "yara_match": str(yara_match)
    }

    with open(WAZUH_LOG_FILE, "a") as log_file:
        log_file.write(json.dumps(event) + "\n")


def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()

    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


def analyze_directory(directory_path):
    report = []

    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)

        if os.path.isdir(file_path):
            continue

        actual_type = identify_file(file_path)
        file_extension = os.path.splitext(filename)[1].lower()
        is_suspicious = False

        if actual_type.lower() == "exe" and file_extension != ".exe":
            is_suspicious = True

        if filename.count(".") > 1:
            is_suspicious = True

        if actual_type == "UNKNOWN":
            is_suspicious = True

        file_hash = get_file_hash(file_path)

        vt_result = check_hash_virustotal(file_hash)
        vt_found = vt_result.get("found", False)
        vt_malicious = vt_result.get("malicious", 0)
        vt_suspicious = vt_result.get("suspicious", 0)
        vt_error = vt_result.get("error")

        if vt_malicious > 0 or vt_suspicious > 0:
            is_suspicious = True


        yara_match_name = "none"    
        if yara_engine:
            # Perform static analysis using the compiled YARA engine
            matches = yara_engine.match(file_path)
            
            if matches:
                # Extract the name of the first triggered rule
                yara_match_name = matches[0].rule
                # Flag the file as suspicious for further processing
                is_suspicious = True

            save_scan_result(
                filename,
                actual_type,
                is_suspicious,
                vt_found,
                vt_malicious,
                vt_suspicious,
                vt_error
            )

            write_wazuh_event(
                filename,
                file_path,
                actual_type,
                file_extension,
                is_suspicious,
                file_hash,
                vt_found,
                vt_malicious,
                vt_suspicious,
                vt_error,
                yara_match=yara_match_name
            )

            report.append({
                "filename": filename,
                "detected_type": actual_type,
                "suspicious": is_suspicious,
            })

    return report