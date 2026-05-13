# FileGuard: Security Scanner & SIEM Integrator

FileGuard is a Python-based file security scanner that detects suspicious files by comparing file extensions with actual file signatures (Magic Numbers). The project logs scan results in a local SQLite database, provides a simple Flask dashboard for reviewing detected files, and natively integrates with **Wazuh SIEM** for real-time threat alerting.

## Project Purpose

Attackers frequently disguise executable or malicious files by assigning them misleading names or extensions (e.g., a file that appears to be a `.pdf` but is actually a `.exe`). 

This project demonstrates essential defensive security concepts, including:
- File inspection and signature validation.
- Suspicious file detection and alerting.
- Local logging and dashboard-based alert review.
- Threat intelligence enrichment using the VirusTotal API.
- Static Malware Analysis using YARA rules.
- **SIEM Integration:** Forwarding real-time JSON events to a security monitoring platform.

## Key Features & Roadmap

| Feature | Status | Description |
|---|:---:|---|
| **Magic Number Detection** | ✅ | Detects true file types ignoring spoofed extensions. |
| **VirusTotal Hash Lookup** | ✅ | Checks file SHA-256 hashes against VT databases. |
| **SQLite Logging** | ✅ | Maintains a persistent local record of all scans. |
| **Flask Dashboard** | ✅ | Simple UI to review historical scan data. |
| **Wazuh SIEM Integration** | ✅ | Generates JSONL logs and custom alerting rules. |
| **YARA Scanning** | ✅ | Pattern matching for malware detection using community rules. |
| String & API Heuristics | ❌ | Planned: Deep analysis of file contents. |
| PE Header Analysis | ❌ | Planned: Extracting metadata from executables. |

## Technologies Used
- **Python 3** (Core logic, Hash calculation, File reading)
- **Flask** (Web Dashboard)
- **SQLite** (Local Database)
- **Wazuh SIEM** (Real-time Alerting Engine)
- **VirusTotal API** (Threat Intelligence)
- **YARA** (Static Malware Analysis Engine)

---

## Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/FileGuard.git](https://github.com/yourusername/FileGuard.git)
   cd FileGuard
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Download YARA Rules:**
   To enable the static malware analysis engine, clone the official community YARA rules directly into the project root:
   ```bash
   git clone [https://github.com/Yara-Rules/rules.git](https://github.com/Yara-Rules/rules.git) yara_rules_repo
   ```

4. **Configure Environment Variables:**
   Create a `.env` file in the root directory and add your VirusTotal API key:
   ```env
   VT_API_KEY=your_virustotal_api_key_here
   ```

5. **Run the Application:**
   ```bash
   python3 app.py
   ```
   *Access the dashboard at `http://127.0.0.1:5000/` to trigger the directory scan.*

---

## Adversary Emulation & Testing

To safely test the YARA detection engine and the Wazuh integration without using real malware (Live Malware), this project includes an Adversary Emulation script.

Run the following command to generate a harmless executable containing Advanced Persistent Threat (APT) string signatures (specifically, the Codoso PlugX trojan):

```bash
python3 scripts/generate_mock_malware.py
```

This script will create a `fake_plugx.exe` file inside the `to_scan` directory. When FileGuard scans this directory, YARA will correctly identify the malicious signatures and immediately trigger a **Level 12 Critical Alert** in the Wazuh dashboard, proving the detection pipeline is fully operational.

---

## Wazuh SIEM Integration Guide

FileGuard is designed to work seamlessly with Wazuh. It outputs perfectly formatted JSON Lines (JSONL) that Wazuh decoders can instantly parse.

### 1. Configure Localfile Collection
Add the following block to your Wazuh Manager/Agent `ossec.conf` to monitor the FileGuard log output:

```xml
<localfile>
  <location>/var/log/file-scanner/alerts.json</location>
  <log_format>json</log_format>
</localfile>
```

### 2. Add Custom Detection Rules
To trigger alerts on the Wazuh Dashboard, add these custom rules to your `/var/ossec/etc/rules/local_rules.xml` file:

<details>
<summary><strong>Click to view XML Rules</strong></summary>

```xml
<group name="file_scanner,">
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">file_type_scanner</field>
    <description>FileGuard: Custom file scanner event received</description>
  </rule>

  <rule id="100101" level="8">
    <if_sid>100100</if_sid>
    <field name="is_suspicious">true</field>
    <description>FileGuard: Suspicious file detected (Extension Mismatch): $(filename)</description>
  </rule>

  <rule id="100102" level="12">
    <if_sid>100100</if_sid>
    <field name="vt_malicious" negate="yes">^0$</field>
    <description>FileGuard: VirusTotal detected malicious file hash: $(filename)</description>
  </rule>

  <rule id="100103" level="12">
    <if_sid>100100</if_sid>
    <field name="yara_match" negate="yes">^none$</field>
    <description>FileGuard: YARA rule matched! Signature: $(yara_match) in file: $(filename)</description>
  </rule>
</group>
```
</details>

*Note: Ensure the target log directory (`/var/log/file-scanner/`) has the correct permissions (`755`) so the `wazuh` user can read the generated `alerts.json` file.*

---

## Credits & Acknowledgements
* **YARA Rules**: The static malware analysis engine utilizes the excellent community-driven [Yara-Rules repository](https://github.com/Yara-Rules/rules). We use their `malware`, `maldocs`, `webshells`, and `cve_rules` datasets to ensure high-fidelity threat detection.