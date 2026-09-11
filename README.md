# OSINT Engine 

Modular, evidence-first OSINT engine for lawful/public or explicitly authorized security research. It accepts crawler findings or manual identifiers, normalizes them, runs relevant scanners/providers, deduplicates findings, preserves provenance, generates JSON reports, and provides a foundation for watchlists and future Phase 3 correlation.

## Flow
```text
Crawler / Manual Lead -> Input -> Normalize -> Relevant scanners/providers
-> Evidence + provenance -> Deduplicate -> Report -> Tracking -> Phase 3
```

Supported identifiers: username, email, URL, domain, DNS/IP, PGP, cryptocurrency wallet.

Provider credentials are optional. No authentication bypass, private-group access, rate-limit evasion, destructive actions, or marketplace transactions are implemented.

## Quick start
```bash
pip install -r requirements.txt
cp .env.example .env
python -m src.engine --username example_handle --domain example.com
pytest
```
