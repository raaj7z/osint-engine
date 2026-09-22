from __future__ import annotations

import csv
import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import Finding, InvestigationResult
from .opsec_scorer import OPSECScorer


NETWORK_TYPES = {
    "ip",
    "domain",
    "dns",
    "infrastructure",
    "url",
}

ACTOR_TYPES = {
    "username",
    "email",
    "pgp",
    "crypto",
    "forum_profile",
}


class ReportGenerator:
    def __init__(
        self,
        db=None,
        scorer: OPSECScorer | None = None,
        report_dir: str | None = None,
    ):
        self.db = db
        self.scorer = scorer or OPSECScorer()
        self.report_dir = Path(
            report_dir or "reports"
        )
        self.report_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    def generate_all(
        self,
        result: InvestigationResult,
        actor_handle: str,
    ) -> dict[str, str]:
        return {
            "json": self.to_json(
                result,
                actor_handle,
            ),
            "csv": self.to_csv(
                result,
                actor_handle,
            ),
            "html": self.to_html(
                result,
                actor_handle,
            ),
            "network_report": self.to_network_report(
                result,
                actor_handle,
            ),
            "threat_actor_report": self.to_threat_actor_report(
                result,
                actor_handle,
            ),
            "raw_report": self.to_raw_report(
                result,
                actor_handle,
            ),
        }

    def _safe_name(
        self,
        value: str,
    ) -> str:
        cleaned = "".join(
            character
            if character.isalnum() or character in "._-"
            else "_"
            for character in str(value)
        )

        return cleaned[:120] or "investigation"

    def _timestamp(self) -> str:
        return datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%d_%H%M%S_%f"
        )

    def _filename(
        self,
        actor_handle: str,
        investigation_id: str,
        suffix: str,
        extension: str,
    ) -> str:
        actor = self._safe_name(
            actor_handle
        )

        investigation = self._safe_name(
            investigation_id
        )

        timestamp = self._timestamp()

        return str(
            self.report_dir
            / (
                f"{actor}_"
                f"{investigation}_"
                f"{suffix}_"
                f"{timestamp}."
                f"{extension}"
            )
        )

    def _group_findings(
        self,
        findings: list[Finding],
    ) -> dict[str, list[Finding]]:
        grouped: dict[
            str,
            list[Finding],
        ] = {}

        for finding in findings:
            grouped.setdefault(
                str(finding.finding_type),
                [],
            ).append(finding)

        return grouped

    def _finding_dict(
        self,
        finding: Finding,
    ) -> dict[str, Any]:
        if hasattr(
            finding,
            "model_dump",
        ):
            return finding.model_dump(
                mode="json"
            )

        if hasattr(
            finding,
            "dict",
        ):
            return finding.dict()

        return {
            "finding_type": finding.finding_type,
            "value": finding.value,
            "source": finding.source,
            "source_url": finding.source_url,
            "confidence": finding.confidence,
            "metadata": finding.metadata,
        }

    def _compute_stats(
        self,
        findings: list[Finding],
    ) -> dict[str, Any]:
        platforms = {
            f.metadata.get(
                "platform",
                f.source,
            )
            for f in findings
            if f.finding_type
            in {
                "username",
                "forum_profile",
            }
        }

        wallets = [
            f
            for f in findings
            if f.finding_type == "crypto"
        ]

        breaches = [
            f
            for f in findings
            if "breach"
            in str(
                f.source
            ).lower()
        ]

        high_confidence = [
            f
            for f in findings
            if f.confidence >= 0.80
        ]

        sources = {
            str(f.source)
            for f in findings
            if f.source
        }

        return {
            "total_findings": len(
                findings
            ),
            "unique_platforms": len(
                platforms
            ),
            "wallets_found": len(
                wallets
            ),
            "breaches_found": len(
                breaches
            ),
            "high_confidence_count": len(
                high_confidence
            ),
            "unique_sources": len(
                sources
            ),
        }

    def _base_payload(
        self,
        result: InvestigationResult,
        actor_handle: str,
    ) -> dict[str, Any]:
        findings = list(
            result.findings
        )

        grouped = self._group_findings(
            findings
        )

        return {
            "investigation_id": result.investigation_id,
            "actor_id": result.actor_id,
            "session_id": getattr(
                result,
                "session_id",
                None,
            ),
            "run_id": getattr(
                result,
                "run_id",
                None,
            ),
            "actor_handle": actor_handle,
            "started_at": (
                result.started_at.isoformat()
                if result.started_at
                else None
            ),
            "completed_at": (
                result.completed_at.isoformat()
                if result.completed_at
                else None
            ),
            "status": getattr(
                result,
                "status",
                "COMPLETED",
            ),
            "errors": list(
                result.errors or []
            ),
            "stats": self._compute_stats(
                findings
            ),
            "findings_by_type": {
                key: [
                    self._finding_dict(
                        finding
                    )
                    for finding in values
                ]
                for key, values
                in grouped.items()
            },
        }

    def _write_json(
        self,
        filename: str,
        payload: dict[str, Any],
    ) -> str:
        with open(
            filename,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                payload,
                file,
                indent=2,
                ensure_ascii=False,
                default=str,
            )

        return filename

    def _register_report(
        self,
        result: InvestigationResult,
        filename: str,
        report_type: str,
        report_format: str,
    ) -> None:
        if self.db is None:
            return

        add_report = getattr(
            self.db,
            "add_report",
            None,
        )

        if not callable(add_report):
            return

        try:
            size = os.path.getsize(
                filename
            )

            add_report(
                investigation_id=result.investigation_id,
                report_type=report_type,
                format=report_format,
                file_name=Path(
                    filename
                ).name,
                file_path=filename,
                file_size=size,
                mime_type={
                    "json": "application/json",
                    "csv": "text/csv",
                    "html": "text/html",
                }.get(
                    report_format,
                    "application/octet-stream",
                ),
                status="COMPLETED",
                run_id=getattr(
                    result,
                    "run_id",
                    None,
                ),
                module_id="osint-engine",
            )
        except TypeError:
            try:
                add_report(
                    investigation_id=result.investigation_id,
                    report_type=report_type,
                    format=report_format,
                    file_name=Path(
                        filename
                    ).name,
                    file_path=filename,
                    file_size=size,
                    mime_type="application/json",
                    status="COMPLETED",
                )
            except Exception:
                pass
        except Exception:
            pass

    def to_json(
        self,
        result: InvestigationResult,
        actor_handle: str,
    ) -> str:
        filename = self._filename(
            actor_handle,
            result.investigation_id,
            "osint",
            "json",
        )

        payload = self._base_payload(
            result,
            actor_handle,
        )

        payload["report_type"] = "osint"
        payload["generated_at"] = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )
        payload["opsec_score"] = (
            self.scorer.score(
                result.findings
            )
        )

        filename = self._write_json(
            filename,
            payload,
        )

        self._register_report(
            result,
            filename,
            "OSINT Report",
            "json",
        )

        return filename

    def to_raw_report(
        self,
        result: InvestigationResult,
        actor_handle: str,
    ) -> str:
        filename = self._filename(
            actor_handle,
            result.investigation_id,
            "raw",
            "json",
        )

        payload = {
            "report_type": "raw",
            "generated_at": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),
            "result": self._finding_result_payload(
                result
            ),
            "execution_log": getattr(
                result,
                "execution_log",
                [],
            ),
            "component_registry": getattr(
                result,
                "component_registry",
                {},
            ),
            "metadata": getattr(
                result,
                "metadata",
                {},
            ),
        }

        filename = self._write_json(
            filename,
            payload,
        )

        self._register_report(
            result,
            filename,
            "Raw Report",
            "json",
        )

        return filename

    def _finding_result_payload(
        self,
        result: InvestigationResult,
    ) -> dict[str, Any]:
        payload = {
            "investigation_id": result.investigation_id,
            "actor_id": result.actor_id,
            "session_id": getattr(
                result,
                "session_id",
                None,
            ),
            "run_id": getattr(
                result,
                "run_id",
                None,
            ),
            "started_at": (
                result.started_at.isoformat()
                if result.started_at
                else None
            ),
            "completed_at": (
                result.completed_at.isoformat()
                if result.completed_at
                else None
            ),
            "errors": result.errors,
            "findings": [
                self._finding_dict(
                    finding
                )
                for finding in result.findings
            ],
        }

        return payload

    def to_csv(
        self,
        result: InvestigationResult,
        actor_handle: str,
    ) -> str:
        filename = self._filename(
            actor_handle,
            result.investigation_id,
            "osint",
            "csv",
        )

        columns = [
            "finding_type",
            "value",
            "source",
            "source_url",
            "confidence",
            "platform",
            "collected_at",
            "first_seen",
            "last_seen",
            "actor_id",
            "run_id",
        ]

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=columns,
            )

            writer.writeheader()

            for finding in result.findings:
                writer.writerow(
                    {
                        "finding_type": finding.finding_type,
                        "value": finding.value,
                        "source": finding.source,
                        "source_url": finding.source_url,
                        "confidence": finding.confidence,
                        "platform": finding.metadata.get(
                            "platform",
                            "",
                        ),
                        "collected_at": (
                            finding.collected_at.isoformat()
                            if finding.collected_at
                            else ""
                        ),
                        "first_seen": (
                            finding.first_seen.isoformat()
                            if finding.first_seen
                            else ""
                        ),
                        "last_seen": (
                            finding.last_seen.isoformat()
                            if finding.last_seen
                            else ""
                        ),
                        "actor_id": finding.actor_id,
                        "run_id": finding.run_id,
                    }
                )

        self._register_report(
            result,
            filename,
            "OSINT Report",
            "csv",
        )

        return filename

    def to_html(
        self,
        result: InvestigationResult,
        actor_handle: str,
    ) -> str:
        filename = self._filename(
            actor_handle,
            result.investigation_id,
            "osint",
            "html",
        )

        opsec = self.scorer.score(
            result.findings
        )

        stats = self._compute_stats(
            result.findings
        )

        grouped = self._group_findings(
            result.findings
        )

        title = html.escape(
            f"OSINT Report — {actor_handle}"
        )

        rows = ""

        for finding_type, findings in grouped.items():
            rows += (
                f"<h3>{html.escape(str(finding_type))}</h3>"
                "<table>"
                "<tr>"
                "<th>Value</th>"
                "<th>Source</th>"
                "<th>Confidence</th>"
                "</tr>"
            )

            for finding in findings:
                rows += (
                    "<tr>"
                    f"<td>{html.escape(str(finding.value))}</td>"
                    f"<td>{html.escape(str(finding.source))}</td>"
                    f"<td>{finding.confidence:.2f}</td>"
                    "</tr>"
                )

            rows += "</table>"

        risk_level = html.escape(
            str(
                opsec.get(
                    "risk_level",
                    "UNKNOWN",
                )
            )
        )

        score = opsec.get(
            "total_score",
            0,
        )

        summary = html.escape(
            str(
                opsec.get(
                    "summary",
                    "",
                )
            )
        )

        report_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{
    background:#0d0d0d;
    color:#e0e0e0;
    font-family:monospace;
    padding:24px;
}}
h1,h2,h3 {{
    color:#f0f0f0;
}}
table {{
    border-collapse:collapse;
    width:100%;
    margin-bottom:20px;
}}
th,td {{
    border:1px solid #333;
    padding:7px 10px;
    text-align:left;
}}
.score-card {{
    border:1px solid #8b1e2d;
    padding:16px;
    border-radius:6px;
    margin-bottom:20px;
}}
.stats-grid {{
    display:flex;
    flex-wrap:wrap;
    gap:12px;
    margin-bottom:20px;
}}
.stat-box {{
    border:1px solid #333;
    padding:12px 18px;
    border-radius:5px;
}}
</style>
</head>
<body>

<h1>{title}</h1>

<p>
Investigation ID:
<strong>{html.escape(result.investigation_id)}</strong>
</p>

<p>
Run ID:
<strong>{html.escape(str(getattr(result, "run_id", "") or ""))}</strong>
</p>

<div class="score-card">
<h2>
OPSEC Score:
{score:.1f}/100
({risk_level})
</h2>
<p>{summary}</p>
</div>

<div class="stats-grid">

<div class="stat-box">
Total Findings<br>
<strong>{stats["total_findings"]}</strong>
</div>

<div class="stat-box">
Unique Platforms<br>
<strong>{stats["unique_platforms"]}</strong>
</div>

<div class="stat-box">
Wallets Found<br>
<strong>{stats["wallets_found"]}</strong>
</div>

<div class="stat-box">
Breaches Found<br>
<strong>{stats["breaches_found"]}</strong>
</div>

<div class="stat-box">
High Confidence<br>
<strong>{stats["high_confidence_count"]}</strong>
</div>

<div class="stat-box">
Sources<br>
<strong>{stats["unique_sources"]}</strong>
</div>

</div>

<h2>Findings</h2>

{rows}

</body>
</html>"""

        with open(
            filename,
            "w",
            encoding="utf-8",
        ) as file:
            file.write(
                report_html
            )

        self._register_report(
            result,
            filename,
            "OSINT Report",
            "html",
        )

        return filename

    def to_network_report(
        self,
        result: InvestigationResult,
        actor_handle: str,
    ) -> str:
        filename = self._filename(
            actor_handle,
            result.investigation_id,
            "network",
            "json",
        )

        network_findings = [
            finding
            for finding in result.findings
            if finding.finding_type
            in NETWORK_TYPES
        ]

        grouped = self._group_findings(
            network_findings
        )

        payload = {
            "investigation_id": result.investigation_id,
            "actor_id": result.actor_id,
            "run_id": getattr(
                result,
                "run_id",
                None,
            ),
            "actor_handle": actor_handle,
            "report_type": "network",
            "generated_at": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),
            "findings_by_type": {
                key: [
                    self._finding_dict(
                        finding
                    )
                    for finding in values
                ]
                for key, values
                in grouped.items()
            },
            "tor_exit_nodes": [
                finding.value
                for finding in network_findings
                if finding.metadata.get(
                    "is_tor_exit"
                )
            ],
            "infrastructure_summary": {
                "total_ips": len(
                    [
                        finding
                        for finding in network_findings
                        if finding.finding_type == "ip"
                    ]
                ),
                "total_domains": len(
                    [
                        finding
                        for finding in network_findings
                        if finding.finding_type == "domain"
                    ]
                ),
                "total_onion_links": len(
                    [
                        finding
                        for finding in network_findings
                        if ".onion"
                        in finding.value.lower()
                    ]
                ),
            },
        }

        filename = self._write_json(
            filename,
            payload,
        )

        self._register_report(
            result,
            filename,
            "Network Report",
            "json",
        )

        return filename

    def to_threat_actor_report(
        self,
        result: InvestigationResult,
        actor_handle: str,
    ) -> str:
        filename = self._filename(
            actor_handle,
            result.investigation_id,
            "actor",
            "json",
        )

        actor_findings = [
            finding
            for finding in result.findings
            if finding.finding_type
            in ACTOR_TYPES
        ]

        grouped = self._group_findings(
            actor_findings
        )

        opsec = self.scorer.score(
            result.findings
        )

        payload = {
            "investigation_id": result.investigation_id,
            "actor_id": result.actor_id,
            "run_id": getattr(
                result,
                "run_id",
                None,
            ),
            "actor_handle": actor_handle,
            "report_type": "threat_actor",
            "generated_at": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),
            "findings_by_type": {
                key: [
                    self._finding_dict(
                        finding
                    )
                    for finding in values
                ]
                for key, values
                in grouped.items()
            },
            "opsec_score": opsec,
            "identity_summary": {
                "platforms": sorted(
                    {
                        finding.metadata.get(
                            "platform",
                            finding.source,
                        )
                        for finding
                        in actor_findings
                        if finding.finding_type
                        in {
                            "username",
                            "forum_profile",
                        }
                    }
                ),
                "wallets": [
                    finding.value
                    for finding
                    in actor_findings
                    if finding.finding_type == "crypto"
                ],
                "emails": [
                    finding.value
                    for finding
                    in actor_findings
                    if finding.finding_type == "email"
                ],
                "pgp_keys": [
                    finding.value
                    for finding
                    in actor_findings
                    if finding.finding_type == "pgp"
                ],
            },
        }

        filename = self._write_json(
            filename,
            payload,
        )

        self._register_report(
            result,
            filename,
            "Threat Actor Report",
            "json",
        )

        return filename
