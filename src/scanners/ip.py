"""IP address scanner for the OSINT engine.

Performs reverse DNS lookup, free geolocation via ip-api.com, abuse
scoring via AbuseIPDB, and Tor exit node detection.
"""

import os
import socket
import time

import requests

from ..models import Identifier, Finding
from .base import Scanner


class IpScanner(Scanner):
    """Scanner that fingerprints an IP address across multiple free/paid sources."""

    name = "ip"
    supported_types = {"ip"}

    def scan(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
    ) -> list[Finding]:
        """Run all IP intelligence techniques and return the combined findings list."""
        ip = identifier.value
        findings: list[Finding] = []

        techniques = (
            self._reverse_dns,
            self._ipapi,
            self._abuseipdb,
            self._tor_exit_check,
        )

        for technique in techniques:
            try:
                findings.extend(technique(ip, investigation_id, actor_id))
            except Exception:
                continue

        return findings

    def _reverse_dns(self, ip: str, iid: str, aid: str | None) -> list[Finding]:
        """Resolve the IP's PTR record to a hostname, if one exists."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
        except Exception:
            return []

        if not hostname:
            return []

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="domain",
            value=hostname,
            source="reverse_dns",
            confidence=0.85,
            metadata={"ip": ip},
        )
        return [finding]

    def _ipapi(self, ip: str, iid: str, aid: str | None) -> list[Finding]:
        """Fetch free geolocation/ISP data for the IP from ip-api.com.

        Respects ip-api.com's free-tier rate limit (45 req/min) by
        pausing briefly after each call.
        """
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            time.sleep(1.5)
        except Exception:
            return []

        try:
            data = resp.json()
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

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="ip",
            value=ip,
            source="ip-api",
            confidence=0.80,
            metadata=metadata,
        )
        return [finding]

    def _abuseipdb(self, ip: str, iid: str, aid: str | None) -> list[Finding]:
        """Check the IP's abuse confidence score via AbuseIPDB. Returns [] if no API key is set."""
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return []

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

        abuse_score = data.get("abuseConfidenceScore", 0) or 0

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="ip",
            value=ip,
            source="abuseipdb",
            confidence=min(max(abuse_score / 100, 0.0), 1.0),
            metadata={
                "abuseConfidenceScore": abuse_score,
                "totalReports": data.get("totalReports"),
                "lastReportedAt": data.get("lastReportedAt"),
            },
        )
        return [finding]

    def _tor_exit_check(self, ip: str, iid: str, aid: str | None) -> list[Finding]:
        """Check whether the IP appears in the public Tor exit node list.

        This is a critical signal for dark web investigations: traffic
        originating from a Tor exit node cannot be tied to a single
        real-world user by IP alone.
        """
        try:
            resp = requests.get(
                "https://check.torproject.org/exit-addresses", timeout=10
            )
            resp.raise_for_status()
            text = resp.text
        except Exception:
            return []

        if ip not in text:
            return []

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="infrastructure",
            value=ip,
            source="tor_exit_list",
            confidence=0.95,
            metadata={"is_tor_exit": True},
        )
        return [finding]
