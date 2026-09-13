"""Report generation for the OSINT engine.

Produces JSON, CSV, and HTML reports from an investigation result, plus
two specialized report types for the web platform integration with the
onion-site crawler: a network-focused report (infrastructure/domains/
IPs/Tor links) and a threat-actor-focused report (identity/platforms/
financial exposure + OPSEC score). These map directly to the two
report types the crawler pipeline is expected to hand off to
investigators (network report, threat actor report).
"""

import csv
import json
import os
from datetime import datetime, timezone

from ..models import Finding, InvestigationResult
from .opsec_scorer import OPSECScorer

NETWORK_TYPES = {"ip", "domain", "dns", "infrastructure", "url"}
ACTOR_TYPES = {"username", "email", "pgp", "crypto", "forum_profile"}


class ReportGenerator:
    """Generates JSON, CSV, and HTML reports (general, network, and threat-actor focused)."""

    def __init__(self, db=None, scorer: OPSECScorer | None = None):
        """Set up the report generator, creating the reports/ directory if needed."""
        self.db = db
        self.scorer = scorer or OPSECScorer()
        os.makedirs("reports", exist_ok=True)

    def generate_all(self, result: InvestigationResult, actor_handle: str) -> dict:
        """Generate every report format/type and return a dict of output paths."""
        return {
            "json": self.to_json(result, actor_handle),
            "csv": self.to_csv(result, actor_handle),
            "html": self.to_html(result, actor_handle),
            "network_report": self.to_network_report(result, actor_handle),
            "threat_actor_report": self.to_threat_actor_report(result, actor_handle),
        }

    def _group_findings(self, findings: list[Finding]) -> dict:
        """Group findings by their finding_type."""
        grouped: dict[str, list[Finding]] = {}
        for f in findings:
            grouped.setdefault(f.finding_type, []).append(f)
        return grouped

    def _compute_stats(self, findings: list[Finding]) -> dict:
        """Compute summary statistics across a finding set."""
        platforms = {
            f.metadata.get("platform", f.source)
            for f in findings
            if f.finding_type in ("username", "forum_profile")
        }
        wallets = [f for f in findings if f.finding_type == "crypto"]
        breaches = [f for f in findings if "breach" in f.source.lower()]
        high_confidence = [f for f in findings if f.confidence > 0.7]

        return {
            "total_findings": len(findings),
            "unique_platforms": len(platforms),
            "wallets_found": len(wallets),
            "breaches_found": len(breaches),
            "high_confidence_count": len(high_confidence),
        }

    def to_json(self, result: InvestigationResult, actor_handle: str) -> str:
        """Write a full JSON report (metadata, grouped findings, OPSEC score, stats)."""
        filename = f"reports/{actor_handle}_{result.investigation_id}.json"
        grouped = self._group_findings(result.findings)
        opsec = self.scorer.score(result.findings)
        stats = self._compute_stats(result.findings)

        payload = {
            "investigation_id": result.investigation_id,
            "actor_id": result.actor_id,
            "actor_handle": actor_handle,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "errors": result.errors,
            "findings_by_type": {
                k: [json.loads(f.model_dump_json()) for f in v] for k, v in grouped.items()
            },
            "opsec_score": opsec,
            "stats": stats,
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
        except Exception:
            pass

        return filename

    def to_csv(self, result: InvestigationResult, actor_handle: str) -> str:
        """Write a flat CSV report of all findings."""
        filename = f"reports/{actor_handle}_{result.investigation_id}.csv"
        columns = [
            "finding_type", "value", "source", "source_url",
            "confidence", "platform", "collected_at",
        ]

        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=columns)
                writer.writeheader()
                for finding in result.findings:
                    writer.writerow(
                        {
                            "finding_type": finding.finding_type,
                            "value": finding.value,
                            "source": finding.source,
                            "source_url": finding.source_url,
                            "confidence": finding.confidence,
                            "platform": finding.metadata.get("platform", ""),
                            "collected_at": finding.collected_at.isoformat(),
                        }
                    )
        except Exception:
            pass

        return filename

    def to_html(self, result: InvestigationResult, actor_handle: str) -> str:
        """Write a dark-themed HTML report covering the full investigation."""
        filename = f"reports/{actor_handle}_{result.investigation_id}.html"
        opsec = self.scorer.score(result.findings)
        stats = self._compute_stats(result.findings)
        grouped = self._group_findings(result.findings)

        html = self._render_html(
            title=f"OSINT Report — {actor_handle}",
            investigation_id=result.investigation_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            opsec=opsec,
            stats=stats,
            grouped=grouped,
        )

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html)
        except Exception:
            pass

        return filename

    def to_network_report(self, result: InvestigationResult, actor_handle: str) -> str:
        """Write a network-infrastructure-focused report (IPs, domains, DNS, servers, Tor links).

        Populated from crawler + IP/URL/darkweb scanner findings. Intended
        for the web platform's "network report" view.
        """
        filename = f"reports/{actor_handle}_{result.investigation_id}_network.json"
        network_findings = [f for f in result.findings if f.finding_type in NETWORK_TYPES]
        grouped = self._group_findings(network_findings)

        payload = {
            "investigation_id": result.investigation_id,
            "actor_handle": actor_handle,
            "report_type": "network",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings_by_type": {
                k: [json.loads(f.model_dump_json()) for f in v] for k, v in grouped.items()
            },
            "tor_exit_nodes": [
                f.value for f in network_findings if f.metadata.get("is_tor_exit")
            ],
            "infrastructure_summary": {
                "total_ips": len([f for f in network_findings if f.finding_type == "ip"]),
                "total_domains": len([f for f in network_findings if f.finding_type == "domain"]),
                "total_onion_links": len(
                    [f for f in network_findings if ".onion" in f.value]
                ),
            },
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
        except Exception:
            pass

        return filename

    def to_threat_actor_report(self, result: InvestigationResult, actor_handle: str) -> str:
        """Write a threat-actor-identity-focused report (usernames, emails, PGP, wallets, OPSEC score).

        Intended for the web platform's "threat actor report" view.
        """
        filename = f"reports/{actor_handle}_{result.investigation_id}_actor.json"
        actor_findings = [f for f in result.findings if f.finding_type in ACTOR_TYPES]
        grouped = self._group_findings(actor_findings)
        opsec = self.scorer.score(result.findings)

        payload = {
            "investigation_id": result.investigation_id,
            "actor_handle": actor_handle,
            "report_type": "threat_actor",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings_by_type": {
                k: [json.loads(f.model_dump_json()) for f in v] for k, v in grouped.items()
            },
            "opsec_score": opsec,
            "identity_summary": {
                "platforms": sorted(
                    {
                        f.metadata.get("platform", f.source)
                        for f in actor_findings
                        if f.finding_type in ("username", "forum_profile")
                    }
                ),
                "wallets": [f.value for f in actor_findings if f.finding_type == "crypto"],
                "emails": [f.value for f in actor_findings if f.finding_type == "email"],
            },
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
        except Exception:
            pass

        return filename

    def _render_html(self, title, investigation_id, timestamp, opsec, stats, grouped) -> str:
        """Render the dark-themed HTML report body."""
        risk_colors = {
            "CRITICAL": "#ff4d4d",
            "HIGH": "#ff9f43",
            "MEDIUM": "#f5d76e",
            "LOW": "#4caf50",
        }
        risk_color = risk_colors.get(opsec["risk_level"], "#e0e0e0")

        rows = ""
        for finding_type, findings in grouped.items():
            rows += f"<h3>{finding_type}</h3><table><tr><th>Value</th><th>Source</th><th>Confidence</th></tr>"
            for f in findings:
                rows += (
                    f"<tr><td>{f.value}</td><td>{f.source}</td>"
                    f"<td>{f.confidence:.2f}</td></tr>"
                )
            rows += "</table>"

        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ background:#0d0d0d; color:#e0e0e0; font-family: monospace; padding: 24px; }}
h1, h2, h3 {{ color:#f0f0f0; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
th, td {{ border: 1px solid #333; padding: 6px 10px; text-align: left; }}
.score-card {{ border: 2px solid {risk_color}; padding: 16px; border-radius: 8px; display:inline-block; margin-bottom: 20px; }}
.stats-grid {{ display: flex; gap: 16px; margin-bottom: 20px; }}
.stat-box {{ border: 1px solid #333; padding: 12px 20px; border-radius: 6px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p>Investigation ID: {investigation_id} | Generated: {timestamp}</p>

<div class="score-card">
  <h2 style="color:{risk_color}">OPSEC Score: {opsec['total_score']:.1f}/100 ({opsec['risk_level']})</h2>
  <p>{opsec['summary']}</p>
</div>

<div class="stats-grid">
  <div class="stat-box">Total Findings<br><strong>{stats['total_findings']}</strong></div>
  <div class="stat-box">Unique Platforms<br><strong>{stats['unique_platforms']}</strong></div>
  <div class="stat-box">Wallets Found<br><strong>{stats['wallets_found']}</strong></div>
  <div class="stat-box">Breaches Found<br><strong>{stats['breaches_found']}</strong></div>
</div>

<h2>Findings</h2>
{rows}

</body>
</html>"""
