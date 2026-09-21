from __future__ import annotations

import os
import subprocess

import requests

from .base import Scanner
from ..models import Evidence, Finding


class EmailScanner(Scanner):
    name = "email"
    supported_types = {"email"}

    def scan(
        self,
        identifier,
        investigation_id,
        actor_id=None,
        run_id=None,
    ):
        email = identifier.value.strip()

        if not email:
            return []

        results = []

        results.extend(
            self._holehe(
                email,
                investigation_id,
                actor_id,
                run_id,
            )
        )

        results.extend(
            self._xposedornot(
                email,
                investigation_id,
                actor_id,
                run_id,
            )
        )

        results.extend(
            self._hunter(
                email,
                investigation_id,
                actor_id,
                run_id,
            )
        )

        return self._deduplicate(results)

    def _holehe(
        self,
        email,
        investigation_id,
        actor_id,
        run_id,
    ):
        try:
            process = subprocess.run(
                [
                    "holehe",
                    email,
                    "--only-used",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return []
        except subprocess.TimeoutExpired:
            return []
        except Exception:
            return []

        results = []

        for line in process.stdout.splitlines():
            if "[+]" not in line:
                continue

            platform = (
                line
                .split("[+]", 1)[-1]
                .strip()
            )

            if not platform:
                continue

            results.append(
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type="email",
                    value=email,
                    source="holehe",
                    confidence=0.80,
                    evidence=[
                        Evidence(
                            source="holehe",
                            title=(
                                f"Email registered on "
                                f"{platform}"
                            ),
                            excerpt=line.strip(),
                        )
                    ],
                    metadata={
                        "platform": platform,
                        "type": "account_found",
                    },
                )
            )

        return results

    def _xposedornot(
        self,
        email,
        investigation_id,
        actor_id,
        run_id,
    ):
        try:
            response = requests.get(
                (
                    "https://api.xposedornot.com/"
                    "v1/breach-analytics"
                ),
                params={
                    "email": email,
                },
                timeout=10,
            )

            if response.status_code != 200:
                return []

            payload = response.json()

            breaches = (
                payload
                .get("breaches", {})
                .get("breaches_details", [])
            )

        except Exception:
            return []

        results = []

        if not isinstance(breaches, list):
            return results

        for breach in breaches:
            if not isinstance(breach, dict):
                continue

            breach_name = breach.get(
                "breach",
                "",
            )

            results.append(
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type="email",
                    value=email,
                    source="xposedornot",
                    source_url=(
                        "https://xposedornot.com"
                    ),
                    confidence=0.95,
                    evidence=[
                        Evidence(
                            source="xposedornot",
                            source_url=(
                                "https://xposedornot.com"
                            ),
                            title=(
                                f"Breach: {breach_name}"
                            ),
                            excerpt=(
                                f"Date: "
                                f"{breach.get('xposed_date', '')} | "
                                f"Data: "
                                f"{breach.get('xposed_data', '')}"
                            ),
                            metadata=breach,
                        )
                    ],
                    metadata={
                        "breach_name": breach_name,
                        "breach_date": breach.get(
                            "xposed_date",
                            "",
                        ),
                        "data_classes": breach.get(
                            "xposed_data",
                            "",
                        ),
                        "records": breach.get(
                            "xposed_records",
                            "",
                        ),
                    },
                )
            )

        return results

    def _hunter(
        self,
        email,
        investigation_id,
        actor_id,
        run_id,
    ):
        api_key = os.getenv(
            "HUNTER_API_KEY",
            "",
        )

        if not api_key:
            return []

        try:
            response = requests.get(
                "https://api.hunter.io/v2/email-verifier",
                params={
                    "email": email,
                    "api_key": api_key,
                },
                timeout=10,
            )

            if response.status_code != 200:
                return []

            data = (
                response
                .json()
                .get("data", {})
            )

        except Exception:
            return []

        result = data.get(
            "result",
            "",
        )

        score = data.get(
            "score",
            0,
        )

        confidence = (
            0.85
            if result == "deliverable"
            else 0.40
        )

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="email",
                value=email,
                source="hunter.io",
                source_url=(
                    "https://hunter.io"
                ),
                confidence=confidence,
                evidence=[
                    Evidence(
                        source="hunter.io",
                        source_url=(
                            "https://hunter.io"
                        ),
                        title=(
                            f"Email verification: "
                            f"{result or 'unknown'}"
                        ),
                        excerpt=(
                            f"Result: {result} | "
                            f"Score: {score}"
                        ),
                    )
                ],
                metadata={
                    "status": result,
                    "score": score,
                    "disposable": data.get(
                        "disposable",
                        False,
                    ),
                    "webmail": data.get(
                        "webmail",
                        False,
                    ),
                },
            )
        ]

    @staticmethod
    def _deduplicate(
        findings,
    ):
        seen = set()
        result = []

        for finding in findings:
            key = (
                finding.source,
                finding.value,
                finding.source_url,
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(finding)

        return result
