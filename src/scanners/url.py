from __future__ import annotations

import os
import time

import requests

from ..models import Finding, Identifier
from .base import Scanner


class URLScanner(Scanner):
    name = "url"
    supported_types = {"url"}

    def scan(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
        run_id: str | None = None,
    ) -> list[Finding]:
        url = identifier.value.strip()

        if not url:
            return []

        findings: list[Finding] = []

        techniques = (
            self._head_request,
            self._check_redirects,
            self._urlscan_submit,
            self._check_security_headers,
        )

        for technique in techniques:
            try:
                findings.extend(
                    technique(
                        url,
                        investigation_id,
                        actor_id,
                        run_id,
                    )
                )
            except Exception:
                continue

        return findings

    def _head_request(
        self,
        url: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        try:
            response = requests.head(
                url,
                timeout=10,
                allow_redirects=True,
            )
        except Exception:
            return []

        headers = dict(response.headers)

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="infrastructure",
                value=url,
                source="url_scanner_head",
                source_url=url,
                confidence=0.75,
                metadata={
                    "status_code": response.status_code,
                    "server": headers.get("Server"),
                    "x_powered_by": headers.get(
                        "X-Powered-By"
                    ),
                    "content_type": headers.get(
                        "Content-Type"
                    ),
                    "headers": headers,
                },
            )
        ]

    def _check_redirects(
        self,
        url: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
            )
        except Exception:
            return []

        redirect_chain = [
            item.url
            for item in response.history
        ]

        final_url = response.url

        if (
            final_url == url
            and not redirect_chain
        ):
            return []

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
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
        ]

    def _urlscan_submit(
        self,
        url: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        api_key = os.getenv(
            "URLSCAN_API_KEY"
        )

        if not api_key:
            return []

        try:
            submit_response = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers={
                    "API-Key": api_key,
                    "Content-Type": "application/json",
                },
                json={
                    "url": url,
                    "visibility": "private",
                },
                timeout=15,
            )

            submit_response.raise_for_status()
            submit_data = submit_response.json()
        except Exception:
            return []

        result_api = submit_data.get("api")

        if not result_api:
            return []

        time.sleep(10)

        try:
            result_response = requests.get(
                result_api,
                timeout=15,
            )
            result_response.raise_for_status()
            result_data = result_response.json()
        except Exception:
            return []

        task = result_data.get(
            "task",
            {},
        )
        page = result_data.get(
            "page",
            {},
        )
        verdicts = result_data.get(
            "verdicts",
            {},
        )

        metadata = {
            "screenshot_url": task.get(
                "screenshotURL"
            ),
            "dom_url": (
                task.get("domURL")
                or result_data.get("dom")
            ),
            "verdict": verdicts.get(
                "overall",
                {},
            ),
            "report_url": task.get(
                "reportURL"
            ),
            "page": page,
        }

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="url",
                value=url,
                source="urlscan",
                source_url=task.get(
                    "reportURL"
                ),
                confidence=0.85,
                metadata=metadata,
            )
        ]

    def _check_security_headers(
        self,
        url: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        required_headers = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
        ]

        try:
            response = requests.get(
                url,
                timeout=10,
            )
        except Exception:
            return []

        present = {
            header.lower()
            for header in response.headers.keys()
        }

        missing = [
            header
            for header in required_headers
            if header.lower() not in present
        ]

        if len(missing) >= 3:
            risk = "HIGH"
        elif missing:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="infrastructure",
                value=url,
                source=(
                    "url_scanner_security_headers"
                ),
                source_url=url,
                confidence=0.70,
                metadata={
                    "missing_headers": missing,
                    "opsec_risk": risk,
                },
            )
        ]
