import os
from dotenv import load_dotenv
import requests

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

def check_hash_virustotal(file_hash):
    if not VT_API_KEY:
        return {
            "found": False,
            "error": "Missing VT_API_KEY environment variable"
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "error": None
            }

        if response.status_code != 200:
            return {
                "found": False,
                "error": f"VirusTotal API error: {response.status_code}"
            }

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "error": None
        }

    except requests.RequestException as e:
        return {
            "found": False,
            "error": str(e)
        }