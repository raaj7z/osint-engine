from __future__ import annotations

import os
import socket
import time

import requests

from ..models import Finding, Identifier
from .base import Scanner


class IpScanner(Scanner):
    name = "ip"
    supported_types = {"ip"}

    def scan(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
        run_id: str | None = None,
    ) -> list[Finding]:
        ip = identifier.value.strip()

        if not ip:
            return []

        findings: list[Finding] = []

        techniques = (
            self._reverse_dns,
            self._ipapi,
            self._abuseipdb,
            self._tor_exit_check,
        )

        for technique in techniques:
            try:
                findings.extend(
                    technique(
                        ip,
                        investigation_id,
                        actor_id,
                        run_id,
                    )
                )
            except Exception:
                continue

        return findings

    def _reverse_dns(
        self,
        ip: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
        except Exception:
            return []

        if not hostname:
            return []

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="domain",
                value=hostname,
                source="reverse_dns",
                confidence=0.85,
                metadata={
                    "ip": ip,
                },
            )
        ]

    def _ipapi(
        self,
        ip: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=10,
            )
            time.sleep(1.5)
        except Exception:
            return []

        try:
            data = response.json()
        except Exception:
            return []

        if data.get("status") != "success":
            return []

        metadata = {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
        }

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="ip",
                value=ip,
                source="ip-api",
                confidence=0.80,
                metadata=metadata,
            )
        ]

    def _abuseipdb(
        self,
        ip: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        api_key = os.getenv("ABUSEIPDB_API_KEY")

        if not api_key:
            return []

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": True,
                },
                timeout=10,
            )
            response.raise_for_status()
            data = response.json().get(
                "data",
                {},
            )
        except Exception:
            return []

        abuse_score = (
            data.get(
                "abuseConfidenceScore",
                0,
            )
            or 0
        )

        confidence = min(
            max(
                abuse_score / 100,
                0.0,
            ),
            1.0,
        )

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="ip",
                value=ip,
                source="abuseipdb",
                confidence=confidence,
                metadata={
                    "abuseConfidenceScore": abuse_score,
                    "totalReports": data.get(
                        "totalReports"
                    ),
                    "lastReportedAt": data.get(
                        "lastReportedAt"
                    ),
                },
            )
        ]

    def _tor_exit_check(
        self,
        ip: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        try:
            response = requests.get(
                "https://check.torproject.org/exit-addresses",
                timeout=10,
            )
            response.raise_for_status()
        except Exception:
            return []

        if ip not in response.text:
            return []

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="infrastructure",
                value=ip,
                source="tor_exit_list",
                confidence=0.95,
                metadata={
                    "is_tor_exit": True,
                },
            )
        ]
