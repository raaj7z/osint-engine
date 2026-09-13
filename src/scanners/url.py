"""URL scanner for the OSINT engine.

Performs infrastructure fingerprinting (HEAD request headers), redirect
chain tracing, urlscan.io submission, and security header analysis for
URL-type identifiers.
"""

import os
import time

import requests

from ..models import Identifier, Finding
from .base import Scanner


class URLScanner(Scanner):
    """Scanner that inspects URLs for infrastructure leaks and OPSEC risk."""

    name = "url"
    supported_types = {"url"}

    def scan(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
    ) -> list[Finding]:
        """Run all URL analysis techniques for this identifier and return combined findings.

        Each sub-technique is isolated in its own try/except so a single
        failure (network error, missing API key, bad response) never
        crashes the overall scan.
        """
        url = identifier.value
        findings: list[Finding] = []

        techniques = (
            self._head_request,
            self._check_redirects,
            self._urlscan_submit,
            self._check_security_headers,
        )

        for technique in techniques:
            try:
                findings.extend(technique(url, investigation_id, actor_id))
            except Exception:
                continue

        return findings

    def _head_request(
        self, url: str, iid: str, aid: str | None
    ) -> list[Finding]:
        """Send a HEAD request and record server fingerprint headers as an infrastructure finding."""
        try:
            resp = requests.head(url, timeout=10, allow_redirects=True)
        except Exception:
            return []

        headers = dict(resp.headers)
        metadata = {
            "status_code": resp.status_code,
            "server": headers.get("Server"),
            "x_powered_by": headers.get("X-Powered-By"),
            "content_type": headers.get("Content-Type"),
            "headers": headers,
        }

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="infrastructure",
            value=url,
            source="url_scanner_head",
            source_url=url,
            confidence=0.75,
            metadata=metadata,
        )
        return [finding]

    def _check_redirects(
        self, url: str, iid: str, aid: str | None
    ) -> list[Finding]:
        """Follow the URL's redirect chain and flag it if the final destination differs from the input."""
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
        except Exception:
            return []

        redirect_chain = [r.url for r in resp.history]
        final_url = resp.url

        if final_url == url and not redirect_chain:
            return []

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="url",
            value=final_url,
            source="url_scanner_redirects",
            source_url=url,
            confidence=0.80,
            metadata={
                "redirect_chain": redirect_chain,
                "final_url": final_url,
            },
        )
        return [finding]

    def _urlscan_submit(
        self, url: str, iid: str, aid: str | None
    ) -> list[Finding]:
        """Submit the URL to urlscan.io and return screenshot/DOM/verdict metadata.

        Returns [] silently if URLSCAN_API_KEY is unset or any request fails.
        """
        api_key = os.getenv("URLSCAN_API_KEY")
        if not api_key:
            return []

        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        payload = {"url": url, "visibility": "private"}

        try:
            submit_resp = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers=headers,
                json=payload,
                timeout=15,
            )
            submit_resp.raise_for_status()
            submit_data = submit_resp.json()
        except Exception:
            return []

        result_api = submit_data.get("api")
        if not result_api:
            return []

        # urlscan.io needs time to render and scan the page before results are ready.
        time.sleep(10)

        try:
            result_resp = requests.get(result_api, timeout=15)
            result_resp.raise_for_status()
            result_data = result_resp.json()
        except Exception:
            return []

        task = result_data.get("task", {})
        page = result_data.get("page", {})
        verdicts = result_data.get("verdicts", {})

        metadata = {
            "screenshot_url": task.get("screenshotURL"),
            "dom_url": task.get("domURL") or result_data.get("dom"),
            "verdict": verdicts.get("overall", {}),
            "report_url": task.get("reportURL"),
            "page": page,
        }

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="url",
            value=url,
            source="urlscan",
            source_url=task.get("reportURL"),
            confidence=0.85,
            metadata=metadata,
        )
        return [finding]

    def _check_security_headers(
        self, url: str, iid: str, aid: str | None
    ) -> list[Finding]:
        """Check for missing standard security headers and assign an OPSEC risk level."""
        required_headers = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
        ]

        try:
            resp = requests.get(url, timeout=10)
        except Exception:
            return []

        present = {h.lower() for h in resp.headers.keys()}
        missing = [h for h in required_headers if h.lower() not in present]

        if len(missing) >= 3:
            risk = "HIGH"
        elif len(missing) >= 1:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        finding = Finding(
            investigation_id=iid,
            actor_id=aid,
            finding_type="infrastructure",
            value=url,
            source="url_scanner_security_headers",
            source_url=url,
            confidence=0.70,
            metadata={
                "missing_headers": missing,
                "opsec_risk": risk,
            },
        )
        return [finding]
