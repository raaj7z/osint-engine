"""urlscan.io provider for the OSINT engine.

Searches urlscan.io's historical scan index for existing scans of a
domain or URL, complementing the on-demand submission already done in
src/scanners/url.py (which triggers a fresh scan).
"""

import os

import requests

from ..models import Identifier, Finding
from .base import Provider


class UrlscanProvider(Provider):
    """Provider that searches urlscan.io's public index for prior scans of a domain/URL."""

    name = "urlscan"
    supported_types = {"domain", "url"}

    def query(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
    ) -> list[Finding]:
        """Search urlscan.io's historical index for scans matching the identifier."""
        api_key = os.getenv("URLSCAN_API_KEY")
        if not api_key:
            return []

        query_field = "domain" if identifier.type == "domain" else "page.url"
        headers = {"API-Key": api_key}
        params = {"q": f"{query_field}:{identifier.value}", "size": 5}

        try:
            resp = requests.get(
                "https://urlscan.io/api/v1/search/",
                headers=headers,
                params=params,
                timeout=15,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except Exception:
            return []

        findings: list[Finding] = []
        for item in results:
            task = item.get("task", {}) or {}
            page = item.get("page", {}) or {}

            findings.append(
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    finding_type="url",
                    value=page.get("url", identifier.value),
                    source="urlscan_search",
                    source_url=task.get("reportURL"),
                    confidence=0.70,
                    metadata={
                        "screenshot_url": item.get("screenshot"),
                        "ip": page.get("ip"),
                        "country": page.get("country"),
                        "server": page.get("server"),
                        "scanned_at": task.get("time"),
                    },
                )
            )

        return findings
