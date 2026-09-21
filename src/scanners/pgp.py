from __future__ import annotations

import re

import requests

from .base import Scanner
from ..models import Evidence, Finding


class PGPScanner(Scanner):
    name = "pgp"
    supported_types = {"pgp"}

    def scan(
        self,
        identifier,
        investigation_id,
        actor_id=None,
        run_id=None,
    ):
        fingerprint = (
            identifier.value
            .strip()
            .upper()
            .replace(" ", "")
        )

        if not fingerprint:
            return []

        results = []

        results.extend(
            self._lookup_openpgp(
                fingerprint,
                investigation_id,
                actor_id,
                run_id,
            )
        )

        results.extend(
            self._lookup_mit(
                fingerprint,
                investigation_id,
                actor_id,
                run_id,
            )
        )

        return self._deduplicate(results)

    def _lookup_openpgp(
        self,
        fingerprint,
        investigation_id,
        actor_id,
        run_id,
    ):
        url = (
            "https://keys.openpgp.org/"
            "vks/v1/by-fingerprint/"
            f"{fingerprint}"
        )

        try:
            response = requests.get(
                url,
                timeout=10,
            )
        except Exception:
            return []

        if response.status_code != 200:
            return []

        key_data = response.text

        emails = re.findall(
            r"<([^>]+@[^>]+)>",
            key_data,
        )

        uids = re.findall(
            r"uid\s+(.+)",
            key_data,
        )

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="pgp",
                value=fingerprint,
                source="keys.openpgp.org",
                source_url=url,
                confidence=0.95,
                evidence=[
                    Evidence(
                        source="keys.openpgp.org",
                        source_url=url,
                        title=(
                            "PGP key found: "
                            f"{fingerprint[:16]}..."
                        ),
                        excerpt=(
                            f"UIDs: {uids[:2]} | "
                            f"Emails: {emails[:2]}"
                        ),
                    )
                ],
                metadata={
                    "fingerprint": fingerprint,
                    "emails_in_key": emails[:5],
                    "uids": uids[:5],
                    "key_data": key_data[:500],
                },
            )
        ]

    def _lookup_mit(
        self,
        fingerprint,
        investigation_id,
        actor_id,
        run_id,
    ):
        lookup_url = (
            "https://pgp.mit.edu/pks/"
            "lookup?op=get&search=0x"
            f"{fingerprint}"
        )

        source_url = (
            "https://pgp.mit.edu/pks/"
            "lookup?op=vindex&search=0x"
            f"{fingerprint}"
        )

        try:
            response = requests.get(
                lookup_url,
                timeout=10,
            )
        except Exception:
            return []

        if (
            response.status_code != 200
            or "BEGIN PGP" not in response.text
        ):
            return []

        emails = re.findall(
            r"<([^>]+@[^>]+)>",
            response.text,
        )

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="pgp",
                value=fingerprint,
                source="pgp.mit.edu",
                source_url=source_url,
                confidence=0.90,
                evidence=[
                    Evidence(
                        source="pgp.mit.edu",
                        source_url=source_url,
                        title=(
                            "PGP key found: "
                            f"{fingerprint[:16]}..."
                        ),
                        excerpt=(
                            f"Emails: {emails[:5]}"
                        ),
                    )
                ],
                metadata={
                    "fingerprint": fingerprint,
                    "emails_in_key": emails[:5],
                },
            )
        ]

    @staticmethod
    def _deduplicate(findings):
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
