"""Censys provider for the OSINT engine.

Uses the Censys Search v2 API to fingerprint hosts: open services,
software, and certificates. Requires both CENSYS_API_ID and
CENSYS_API_SECRET (Censys uses HTTP basic auth with these as
id/secret).
"""

import os

import requests

from ..models import Identifier, Finding
from .base import Provider


class CensysProvider(Provider):
    """Provider that enriches IPs and domains with Censys host/certificate data."""

    name = "censys"
    supported_types = {"ip", "domain"}
    BASE_URL = "https://search.censys.io/api/v2"

    def query(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
    ) -> list[Finding]:
        """Route the identifier to the correct Censys lookup based on its type."""
        api_id = os.getenv("CENSYS_API_ID")
        api_secret = os.getenv("CENSYS_API_SECRET")
        if not api_id or not api_secret:
            return []

        try:
            if identifier.type == "ip":
                return self._lookup_host(identifier.value, investigation_id, actor_id)
            if identifier.type == "domain":
                return self._search_domain(identifier.value, investigation_id, actor_id)
        except Exception:
            return []

        return []

    def _auth(self) -> tuple[str, str]:
        """Build the HTTP basic auth tuple for Censys requests."""
        return (os.getenv("CENSYS_API_ID", ""), os.getenv("CENSYS_API_SECRET", ""))

    def _lookup_host(self, ip: str, iid: str, aid: str | None) -> list[Finding]:
        """Fetch Censys host data (open services, software, location) for an IP."""
        try:
            resp = requests.get(
                f"{self.BASE_URL}/hosts/{ip}",
                auth=self._auth(),
                timeout=15,
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
        except Exception:
            return []

        services = result.get("services", [])
        service_summaries = [
            f"{s.get('port')}/{s.get('transport_protocol', 'TCP')}: {s.get('service_name', '')}"
            for s in services
        ]

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="infrastructure",
            value=ip,
            source="censys",
            confidence=0.85,
            metadata={
                "services": service_summaries,
                "location": result.get("location"),
                "autonomous_system": result.get("autonomous_system"),
                "last_updated": result.get("last_updated_at"),
            },
        )
        return [finding]

    def _search_domain(self, domain: str, iid: str, aid: str | None) -> list[Finding]:
        """Search Censys for hosts associated with a domain via certificate SAN names."""
        try:
            resp = requests.post(
                f"{self.BASE_URL}/hosts/search",
                auth=self._auth(),
                json={"q": f"services.tls.certificates.leaf_data.names: {domain}"},
                timeout=15,
            )
            resp.raise_for_status()
            hits = resp.json().get("result", {}).get("hits", [])
        except Exception:
            return []

        findings: list[Finding] = []
        for hit in hits:
            ip = hit.get("ip")
            if not ip:
                continue
            findings.append(
                Finding(
                    investigation_id=iid,
                    actor_id=aid,
                    finding_type="ip",
                    value=ip,
                    source="censys",
                    confidence=0.75,
                    metadata={
                        "location": hit.get("location"),
                        "autonomous_system": hit.get("autonomous_system"),
                    },
                )
            )

        return findings
