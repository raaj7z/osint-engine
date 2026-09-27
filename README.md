# OSINT Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003B57.svg)](https://www.sqlite.org/)
[![Shodan](https://img.shields.io/badge/Provider-Shodan-red.svg)](https://www.shodan.io/)
[![VirusTotal](https://img.shields.io/badge/Provider-VirusTotal-blue.svg)](https://www.virustotal.com/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)]()

> Multi-Provider Open Source Intelligence (OSINT) Aggregation Engine & Threat Monitoring Framework.

---

## 📋 Table of Contents
- [Overview](#overview)
- [Architecture & Modular Design](#architecture--modular-design)
- [Repository Structure](#repository-structure)
- [Supported Providers & Scanners](#supported-providers--scanners)
- [Environment Requirements](#environment-requirements)
- [Installation & Configuration](#installation--configuration)
- [Usage & Execution](#usage--execution)
  - [Command Line Execution](#command-line-execution)
  - [Python Module Integration](#python-module-integration)
- [Watchlist & Continuous Monitoring](#watchlist--continuous-monitoring)
- [OPSEC Risk Scoring](#opsec-risk-scoring)

---

## 🔍 Overview

**OSINT Engine** is a threat intelligence framework that aggregates open-source data across multiple external providers (Shodan, VirusTotal, Censys, AbuseIPDB, Urlscan) and specialized local scanners (IP, Domain/DNS, Crypto Wallet, PGP Key, Email, Username, Dark Web). It correlates technical indicators, computes OPSEC risk scores, manages persistent target watchlists, and generates threat reports.

---

## 🏗️ Architecture & Modular Design

```
                       +-----------------------------+
                       |      CLI / Application      |
                       |       (src/main.py)         |
                       +--------------+--------------+
                                      |
                                      v
                       +-----------------------------+
                       |     OSINT Engine Orchestration |
                       |       (src/engine.py)       |
                       +--------------+--------------+
                                      |
       +------------------------------+------------------------------+
       |                              |                              |
       v                              v                              v
+--------------+               +--------------+               +--------------+
| Providers    |               | Scanners     |               | Watchlist    |
| (src/        |               | (src/        |               | Store        |
|  providers/) |               |  scanners/)  |               | (src/track-  |
| - Shodan     |               | - IP / DNS   |               |  ing/)       |
| - VirusTotal |               | - Crypto     |               | - Scheduler  |
| - Censys     |               | - PGP / Email|               | - Alerts     |
| - AbuseIPDB  |               | - Username   |               +--------------+
| - Urlscan    |               +--------------+                      |
+--------------+                      |                              |
       |                              v                              v
       +----------------------> +--------------+ <--------------------+
                                | OPSEC Scorer |
                                | & Exporter   |
                                | (src/        |
                                |  reports/)   |
                                +--------------+
```

---

## 📁 Repository Structure

```
osint-engine/
├── config/
│   └── providers.yaml         # Provider API endpoints and timeout settings
├── src/
│   ├── main.py                # Main CLI entry point
│   ├── engine.py              # OSINT Engine orchestrator class
│   ├── input.py               # Target input validator & normalizer
│   ├── models.py              # Data models for findings, indicators, and reports
│   ├── normalizer.py          # Data normalization utilities
│   ├── ai_cleaner.py          # AI-assisted threat data filter
│   ├── database.py            # SQLite local database manager
│   ├── providers/             # External Threat Intel API Adapters
│   │   ├── base.py            # Base provider abstract class
│   │   ├── shodan.py          # Shodan Host & Search API client
│   │   ├── virustotal.py      # VirusTotal Domain/IP/URL API client
│   │   ├── censys.py          # Censys Search API client
│   │   ├── abuseipdb.py       # AbuseIPDB IP Check API client
│   │   └── urlscan.py         # Urlscan.io Submission & Result API client
│   ├── scanners/              # Specialized Technical Indicator Scanners
│   │   ├── base.py            # Base scanner abstract class
│   │   ├── ip.py              # IP lookup and open port scanner
│   │   ├── dns.py             # DNS record and WHOIS scanner
│   │   ├── crypto.py          # Bitcoin & Ethereum address validator
│   │   ├── pgp.py             # PGP Public Key server lookup
│   │   ├── email.py           # Email MX record and breach scanner
│   │   ├── username.py        # Handle / Username footprint checker
│   │   ├── darkweb.py         # Dark web mention scanner
│   │   └── url.py             # Web page header and metadata scanner
│   ├── tracking/              # Persistent Watchlist & Alert System
│   │   ├── watchlist.py       # WatchlistStore database implementation
│   │   ├── alert_manager.py   # Alert notification manager
│   │   ├── change_detector.py # Indicator diff and change tracking
│   │   └── scheduler.py       # Periodic target scan scheduler
│   └── reports/               # Scoring & Report Exporters
│       ├── opsec_scorer.py    # OPSEC exposure risk scoring algorithm
│       └── report_generator.py# Report builder (JSON, CSV, Markdown)
├── .env.example               # Example environment variable file
├── requirements.txt           # Python dependencies
└── README.md                  # Project documentation
```

---

## 🛠️ Supported Providers & Scanners

### External Providers

- **Shodan**: Host port scanning, banner matching, SSL certificate fingerprints.
- **VirusTotal**: Domain registration dates, IP resolutions, threat reputation scores.
- **Censys**: Certificate Transparency logs and host service scans.
- **AbuseIPDB**: IP abuse confidence scores and reporter counts.
- **Urlscan.io**: Web page screenshot previews and DOM link analysis.

### Technical Scanners

- **IP & DNS**: Reverse DNS, WHOIS registration, open ports, IP geolocation.
- **Crypto Wallet**: BTC/ETH wallet validation and transaction footprinting.
- **PGP Keys**: Key ID extraction, fingerprint verification, UID email matching.
- **Username / Handle**: Cross-platform pseudonymous handle presence.

---

## 🔧 Environment Requirements

- **Python**: Python 3.10+
- **API Keys** (Optional for full provider features): Shodan, VirusTotal, Censys.

---

## 🚀 Installation & Configuration

1. **Clone Repository**:
   ```bash
   git clone https://github.com/raaj7z/osint-engine.git
   cd osint-engine
   ```

2. **Set up Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API Keys**:
   Copy `.env.example` to `.env` and fill in your keys:
   ```bash
   cp .env.example .env
   ```
   ```ini
   SHODAN_API_KEY=your_shodan_key_here
   VIRUSTOTAL_API_KEY=your_virustotal_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_key_here
   ```

---

## 💻 Usage & Execution

### Command Line Execution

```bash
# Scan a domain target
python -m src.main --target aether-sec.com --type domain

# Scan an IP address target
python -m src.main --target 192.0.2.45 --type ip

# Scan a crypto wallet target
python -m src.main --target 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --type crypto
```

### Python Module Integration

```python
from src.engine import OSINTEngine

engine = OSINTEngine()
results = engine.scan_target(target="aether-sec.com", target_type="domain")
print("OPSEC Exposure Score:", results.opsec_score)
print("Findings Count:", len(results.findings))
```

---

## 📊 Watchlist & Continuous Monitoring

The `WatchlistStore` manages recurring scans for target actors:

```python
from src.tracking.watchlist import WatchlistStore

store = WatchlistStore()
watch_id = store.add(
    actor_id="ACT-VIPER-001",
    handle="DarkViper_2024",
    interval_minutes=360,
    notes="Monitored threat actor handle"
)
print("Created Watchlist Entry:", watch_id)
```

---

## 📜 License

Proprietary — Threat Intelligence & OSINT Aggregation Module.
