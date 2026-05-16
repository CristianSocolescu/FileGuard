# FileGuard: Security Scanner & Distributed SIEM Integrator

FileGuard is a Python-based file security scanner that detects suspicious files by comparing file extensions with actual file signatures (Magic Numbers). The project logs scan results locally, provides a simple Flask dashboard for reviewing detected files, and natively integrates with a **Docker-hosted Wazuh SIEM** for real-time, cross-network threat alerting.

## Project Purpose

Attackers frequently disguise executable or malicious files by assigning them misleading names or extensions (e.g., a file that appears to be a `.pdf` but is actually a `.exe`). 

This project demonstrates essential defensive security concepts, including:
- File inspection and signature validation.
- Suspicious file detection and alerting.
- Threat intelligence enrichment using the VirusTotal API.
- Static Malware Analysis using YARA rules.
- Distributed SIEM Architecture: Running the SIEM Manager in a Docker container and streaming real-time JSON events over the network via UDP sockets, allowing the scanner and the monitoring platform to exist on separate machines.

## Key Features & Roadmap

| Feature | Status | Description |
|---|:---:|---|
| **Magic Number Detection** | ✅ | Detects true file types ignoring spoofed extensions. |
| **VirusTotal Hash Lookup** | ✅ | Checks file SHA-256 hashes against VT databases. |
| **Wazuh SIEM in Docker** | ✅ | Centralized logging and alerting environment using Docker Compose. |
| **Network Log Streaming** | ✅ | Forwards alerts to the remote SIEM via UDP Network Sockets. |
| **YARA Scanning** | ✅ | Pattern matching for malware detection using community rules. |
| String & API Heuristics | ❌ | Planned: Deep analysis of file contents & Network IOC extraction. |
| PE Header Analysis | ❌ | Planned: Extracting metadata from executables. |

## Technologies Used
- **Python 3** 
- **Docker & Docker Compose** (SIEM Manager Hosting)
- **Wazuh SIEM** 
- **VirusTotal API** 
- **YARA** (Static Malware Analysis Engine)
- **Flask & SQLite** (Local Dashboard & DB)

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
   Create a `.env` file in the root directory. Add your VirusTotal API key and configure the target IP of your Docker-hosted Wazuh server:
   ```env
   VT_API_KEY=your_virustotal_api_key_here
   WAZUH_SERVER_IP=192.168.x.x  # The IP of the machine running Wazuh via Docker
   WAZUH_PORT=514               # UDP Port for network logging
   ```

5. **Run the Application:**
   ```bash
   python3 app.py
   ```

---

## Adversary Emulation & Testing

To safely test the YARA detection engine and the network integration without using real malware, this project includes an Adversary Emulation script.

Run the following command to generate a harmless executable containing Advanced Persistent Threat (APT) string signatures (specifically, the Codoso PlugX trojan):

```bash
python3 scripts/generate_mock_malware.py
```

When FileGuard scans the `to_scan` directory, YARA will identify the signatures and instantly stream a **Level 12 Critical Alert** over the network to the Wazuh dashboard, proving the UDP pipeline and detection engine are fully operational.

---

## Distributed Wazuh SIEM Integration Guide

FileGuard is designed as a distributed agent. It utilizes Python `socket` libraries to stream JSON files over the network into a Wazuh Manager hosted in Docker.

### 1. Docker Compose Configuration (Manager Side)
Ensure your Wazuh Manager is running via Docker and has the syslog UDP port exposed. In your `docker-compose.yml`, verify the ports section includes:
```yaml
ports:
  - "514:514/udp"
```

### 2. Add Custom Detection Rules
To trigger alerts on the Wazuh Dashboard, add these custom rules to your Wazuh Manager's `local_rules.xml` file (`/var/ossec/etc/rules/local_rules.xml`):

<details>
<summary><strong>Click to view XML Rules</strong></summary>

```xml
<group name="file_scanner,">
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">file_type_scanner</field>
    <description>FileGuard: Custom file scanner event received from $(hostname)</description>
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

*Note: Ensure your host machine's firewall (e.g., Windows Defender Firewall) allows inbound UDP traffic on port 514 from the IP address of the machine running the FileGuard scanner.*

---

## Credits & Acknowledgements
* **YARA Rules**: The static malware analysis engine utilizes the community-driven [Yara-Rules repository](https://github.com/Yara-Rules/rules). We use their `malware`, `maldocs`, `webshells`, and `cve_rules` datasets to ensure threat detection.