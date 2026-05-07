# FileGuard

FileGuard is a Python-based file security scanner that detects suspicious files by comparing file extensions with actual file signatures.  
The project also logs scan results in a local SQLite database and provides a small Flask dashboard for reviewing detected files.

## Features

- Detects file types using magic numbers
- Identifies suspicious files with misleading extensions
- Logs scan results in a SQLite database
- Provides a simple Flask web dashboard
- Supports optional VirusTotal hash checks
- Uses environment variables to protect API keys

## Project Purpose

Attackers sometimes disguise executable or suspicious files by giving them misleading names or extensions, for example a file that appears to be a PDF but is actually an executable.

This project demonstrates basic defensive security concepts such as:

- file inspection
- file type validation
- suspicious file detection
- local logging
- dashboard-based alert review
- basic threat intelligence enrichment using VirusTotal

## Technologies Used

- Python
- Flask
- SQLite
- Requests
- python-dotenv
- VirusTotal API


## Features

| Feature | Status |
|---|---|
| Magic number detection | ✅ |
| VirusTotal hash lookup | ✅ |
| SQLite logging | ✅ |
| Flask dashboard | ✅ |
| YARA scanning | ❌ |
| String & API heuristics | ❌ |
| PE header analysis | ❌ |
| Entropy analysis | ❌ |