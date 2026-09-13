"""AbuseIPDB provider for the OSINT engine.

Retrieves abuse confidence scores and individual abuse reports for IP
addresses.
"""

import os

import requests

from ..models import Identifier, Finding
from .base import Provider

CATEGORY_MAP = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}


class AbuseIPDBProvider(Provider):
    """Provider that enriches IPs with AbuseIPDB abuse scores and reports."""

    name = "abuseipdb"
    supported_types = {"ip"}

    def query(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
    ) -> list[Finding]:
        """Fetch both the abuse score summary and recent individual reports for an IP."""
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return []

        findings: list[Finding] = []
        try:
            findings.extend(self._check_ip(identifier.value, investigation_id, actor_id))
        except Exception:
            pass
        try:
            findings.extend(self._get_reports(identifier.value, investigation_id, actor_id))
        except Exception:
            pass
        return findings

    def _check_ip(self, ip: str, iid: str, aid: str | None) -> list[Finding]:
        """Fetch the aggregate abuse confidence score and metadata for an IP."""
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except Exception:
            return []

        score = data.get("abuseConfidenceScore", 0) or 0

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="ip",
            value=ip,
            source="abuseipdb",
            confidence=min(max(score / 100, 0.0), 1.0),
            metadata={
                "abuseConfidenceScore": score,
                "totalReports": data.get("totalReports"),
                "lastReportedAt": data.get("lastReportedAt"),
                "usageType": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "countryCode": data.get("countryCode"),
                "isPublic": data.get("isPublic"),
                "isTor": data.get("isTor"),
                "high_abuse": score > 50,
            },
        )
        return [finding]

    def _get_reports(self, ip: str, iid: str, aid: str | None) -> list[Finding]:
        """Fetch recent individual abuse reports for an IP as evidence findings."""
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 30, "page": 1, "perPage": 5}

        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/reports",
                headers=headers,
                params=params,
                timeout=10,
            )
            resp.raise_for_status()
            results = resp.json().get("data", {}).get("results", [])
        except Exception:
            return []

        findings: list[Finding] = []
        for report in results:
            categories = report.get("categories", [])
            category_names = [CATEGORY_MAP.get(c, f"Category {c}") for c in categories]

            findings.append(
                Finding(
                    investigation_id=iid,
                    actor_id=aid,
                    finding_type="evidence",
                    value=ip,
                    source="abuseipdb_reports",
                    confidence=0.6,
                    metadata={
                        "reportedAt": report.get("reportedAt"),
                        "comment": report.get("comment"),
                        "categories": categories,
                        "category_names": category_names,
                    },
                )
            )

        return findings
