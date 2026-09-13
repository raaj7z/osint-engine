"""VirusTotal provider for the OSINT engine.

Queries the VirusTotal v3 API for domain, IP, and URL reputation data.
"""

import base64
import os
import time

import requests

from ..models import Identifier, Finding
from .base import Provider


class VirusTotalProvider(Provider):
    """Provider that enriches domains, IPs, and URLs with VirusTotal reputation data."""

    name = "virustotal"
    supported_types = {"domain", "url", "ip"}
    BASE_URL = "https://www.virustotal.com/api/v3"

    def query(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
    ) -> list[Finding]:
        """Route the identifier to the correct VirusTotal lookup based on its type."""
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return []

        try:
            if identifier.type == "domain":
                return self._check_domain(identifier.value, investigation_id, actor_id)
            if identifier.type == "ip":
                return self._check_ip(identifier.value, investigation_id, actor_id)
            if identifier.type == "url":
                return self._check_url(identifier.value, investigation_id, actor_id)
        except Exception:
            return []

        return []

    def _headers(self) -> dict:
        """Build the auth header for VirusTotal requests."""
        return {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY", "")}

    def _confidence_from_malicious(self, malicious: int) -> float:
        """Map a malicious-vote count to a confidence score."""
        if malicious == 0:
            return 0.1
        if malicious <= 3:
            return 0.6
        return 0.9

    def _check_domain(self, domain: str, iid: str, aid: str | None) -> list[Finding]:
        """Look up a domain's VirusTotal reputation and analysis stats."""
        try:
            resp = requests.get(
                f"{self.BASE_URL}/domains/{domain}",
                headers=self._headers(),
                timeout=15,
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
        except Exception:
            return []
        finally:
            # Free-tier VirusTotal allows 4 requests/minute.
            time.sleep(15)

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) or 0

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="domain",
            value=domain,
            source="virustotal",
            confidence=self._confidence_from_malicious(malicious),
            metadata={
                "last_analysis_stats": stats,
                "reputation": attrs.get("reputation"),
                "categories": attrs.get("categories"),
                "registrar": attrs.get("registrar"),
            },
        )
        return [finding]

    def _check_ip(self, ip: str, iid: str, aid: str | None) -> list[Finding]:
        """Look up an IP's VirusTotal reputation and analysis stats."""
        try:
            resp = requests.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=self._headers(),
                timeout=15,
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
        except Exception:
            return []
        finally:
            time.sleep(15)

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) or 0

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="ip",
            value=ip,
            source="virustotal",
            confidence=self._confidence_from_malicious(malicious),
            metadata={
                "last_analysis_stats": stats,
                "reputation": attrs.get("reputation"),
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
            },
        )
        return [finding]

    def _check_url(self, url: str, iid: str, aid: str | None) -> list[Finding]:
        """Look up a URL's VirusTotal reputation using its base64 URL-safe identifier."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        try:
            resp = requests.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers=self._headers(),
                timeout=15,
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
        except Exception:
            return []
        finally:
            time.sleep(15)

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) or 0

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="url",
            value=url,
            source="virustotal",
            confidence=self._confidence_from_malicious(malicious),
            metadata={
                "last_analysis_stats": stats,
                "reputation": attrs.get("reputation"),
                "categories": attrs.get("categories"),
            },
        )
        return [finding]
