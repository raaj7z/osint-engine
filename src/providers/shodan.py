"""Shodan provider for the OSINT engine.

Uses the official shodan SDK to fingerprint infrastructure exposed to
the internet: open ports, running services, hostnames, and known
vulnerabilities.
"""

import os

from ..models import Identifier, Finding
from .base import Provider

try:
    import shodan
except ImportError:  # pragma: no cover - optional dependency
    shodan = None


class ShodanProvider(Provider):
    """Provider that enriches IPs and domains with Shodan infrastructure data."""

    name = "shodan"
    supported_types = {"ip", "domain"}

    def query(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
    ) -> list[Finding]:
        """Route the identifier to the correct Shodan lookup based on its type."""
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key or shodan is None:
            return []

        try:
            if identifier.type == "ip":
                return self._lookup_ip(identifier.value, investigation_id, actor_id)
            if identifier.type == "domain":
                return self._search_domain(identifier.value, investigation_id, actor_id)
        except Exception:
            return []

        return []

    def _lookup_ip(self, ip: str, iid: str, aid: str | None) -> list[Finding]:
        """Fetch full Shodan host data for an IP and emit an overview + per-port findings."""
        api_key = os.getenv("SHODAN_API_KEY")

        try:
            api = shodan.Shodan(api_key)
            host = api.host(ip)
        except Exception:
            return []

        ports = host.get("ports", [])
        services = [
            f"{item.get('port')}/{item.get('transport', 'tcp')}: {item.get('product', '')}".strip()
            for item in host.get("data", [])
        ]
        vulns = list(host.get("vulns", []))

        overview = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="infrastructure",
            value=ip,
            source="shodan",
            confidence=0.90,
            metadata={
                "ports": ports,
                "services": services,
                "hostnames": host.get("hostnames", []),
                "os": host.get("os"),
                "vulns": vulns,
                "org": host.get("org"),
                "isp": host.get("isp"),
                "country": host.get("country_name"),
                "last_update": host.get("last_update"),
            },
        )

        findings = [overview]

        for item in host.get("data", []):
            port = item.get("port")
            if port is None:
                continue
            findings.append(
                Finding(
                    investigation_id=iid,
                    actor_id=aid,
                    finding_type="infrastructure",
                    value=f"{ip}:{port}",
                    source="shodan",
                    confidence=0.90,
                    metadata={
                        "port": port,
                        "transport": item.get("transport"),
                        "product": item.get("product"),
                        "version": item.get("version"),
                        "banner": item.get("data"),
                    },
                )
            )

        return findings

    def _search_domain(self, domain: str, iid: str, aid: str | None) -> list[Finding]:
        """Search Shodan for hosts matching the given hostname and return their IPs."""
        api_key = os.getenv("SHODAN_API_KEY")

        try:
            api = shodan.Shodan(api_key)
            results = api.search(f"hostname:{domain}")
        except Exception:
            return []

        findings: list[Finding] = []
        for match in results.get("matches", []):
            ip = match.get("ip_str")
            if not ip:
                continue
            findings.append(
                Finding(
                    investigation_id=iid,
                    actor_id=aid,
                    finding_type="ip",
                    value=ip,
                    source="shodan",
                    confidence=0.80,
                    metadata={
                        "hostnames": match.get("hostnames", []),
                        "org": match.get("org"),
                        "port": match.get("port"),
                    },
                )
            )

        return findings
