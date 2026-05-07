import os
from scanner import identify_file
from database import save_scan_result
import hashlib
from virustotal_check import check_hash_virustotal

def get_file_hash(filepath):
    sha256_hash=hashlib.sha256()
    with open(filepath, "rb") as f:
    #read 4kb blocks from a file and stop when it gets an empty bit
        for byte_block in iter(lambda:f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def analyze_directory(directory_path):
    report=[]

    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)

        #if the item found is a sub-directory and not a file skip
        if os.path.isdir(file_path):
            continue

        #calls previously defined function to see what is the actualy format of a fyle ex pdf/exe/docx
        actual_type = identify_file(file_path)
        #cut the name of the file at the last dot. virus.pdf.exe will return .exe
        file_extension = os.path.splitext(filename)[1].lower()
        is_suspicious = False
        
        if actual_type.lower() == "exe" and file_extension!=".exe":
            is_suspicious = True

        if filename.count('.')>1:
            is_suspicious = True 

        if actual_type == "UNKNOWN":
            is_suspicious = True
        
        #get the hash of the current file
        file_hash=get_file_hash(file_path)

        vt_result = check_hash_virustotal(file_hash)
        vt_found = vt_result.get("found", False)
        vt_malicious = vt_result.get("malicious", 0)
        vt_suspicious = vt_result.get("suspicious",0)
        vt_error = vt_result.get("error")
        if vt_malicious>0 or vt_suspicious>0:
            is_suspicious=True

        save_scan_result(filename, actual_type, is_suspicious, vt_found, vt_malicious, vt_suspicious, vt_error)

        report.append({
            "filename": filename,
            "detected_type": actual_type,
            "suspicious": is_suspicious,
        })
    
    return report
