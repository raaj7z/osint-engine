"""
Username scanner using locally installed OSINT tools.

The scanner only records publicly returned profile URLs.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from typing import Any

from .base import Scanner
from ..models import Evidence, Finding


class UsernameScanner(Scanner):
    name = "username"
    supported_types = {"username"}

    def scan(self, identifier, investigation_id, actor_id):
        username = identifier.value.strip().lstrip("@")

        if not username:
            return []

        results = []
        errors = []

        found, error = self._sherlock(
            username,
            investigation_id,
            actor_id,
        )
        results.extend(found)

        if error:
            errors.append(error)

        found, error = self._maigret(
            username,
            investigation_id,
            actor_id,
        )
        results.extend(found)

        if error:
            errors.append(error)

        found, error = self._blackbird(
            username,
            investigation_id,
            actor_id,
        )
        results.extend(found)

        if error:
            errors.append(error)

        # Do not silently hide scanner failures.
        for error in errors:
            print(f"[ERROR] username scanner: {error}")

        return self._deduplicate(results)

    @staticmethod
    def _make_finding(
        investigation_id,
        actor_id,
        username,
        source,
        url,
        confidence,
        platform,
    ):
        return Finding(
            investigation_id=investigation_id,
            actor_id=actor_id,
            finding_type="username",
            value=username,
            source=source,
            source_url=url,
            confidence=confidence,
            evidence=[
                Evidence(
                    source=source,
                    source_url=url,
                    title=(
                        f"{source}: {platform}"
                        if platform
                        else f"{source} username match"
                    ),
                )
            ],
            metadata={
                "platform": platform,
                "username": username,
            },
        )

    # ---------------------------------------------------------
    # SHERLOCK
    # ---------------------------------------------------------

    def _sherlock(self, username, investigation_id, actor_id):
        """
        Run Sherlock and extract profile URLs from its output.
        """

        results = []

        try:
            process = subprocess.run(
                [
                    "sherlock",
                    username,
                    "--print-found",
                    "--timeout",
                    "10",
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )

        except FileNotFoundError:
            return [], "Sherlock executable not found in PATH"

        except subprocess.TimeoutExpired:
            return [], "Sherlock timed out"

        except Exception as exc:
            return [], f"Sherlock failed: {exc}"

        stdout = process.stdout or ""
        stderr = process.stderr or ""

        combined_output = stdout + "\n" + stderr

        # Sherlock normally returns 0 when successful and may return
        # non-zero for some execution conditions.
        if process.returncode not in (0, 1):
            return [], (
                f"Sherlock exited with code "
                f"{process.returncode}: "
                f"{self._short(combined_output)}"
            )

        for raw_line in combined_output.splitlines():

            line = raw_line.strip()

            if "[+]" not in line:
                continue

            # Extract any URL from the result line.
            urls = re.findall(
                r"https?://[^\s\]\[<>\"']+",
                line,
            )

            if not urls:
                continue

            url = urls[-1].rstrip(".,)")

            if not self._looks_like_profile_url(
                url,
                username,
            ):
                continue

            platform = self._platform_from_url(url)

            results.append(
                self._make_finding(
                    investigation_id,
                    actor_id,
                    username,
                    "sherlock",
                    url,
                    0.75,
                    platform,
                )
            )

        return results, None

    # ---------------------------------------------------------
    # MAIGRET
    # ---------------------------------------------------------

    def _maigret(self, username, investigation_id, actor_id):
        """
        Run Maigret and parse its JSON output.
        """

        results = []

        fd, temp_path = tempfile.mkstemp(
            prefix="maigret_",
            suffix=".json",
        )

        os.close(fd)

        try:
            process = subprocess.run(
                [
                    "maigret",
                    username,
                    "--json",
                    temp_path,
                    "--timeout",
                    "10",
                    "--no-progressbar",
                ],
                capture_output=True,
                text=True,
                timeout=240,
            )

        except FileNotFoundError:
            return [], "Maigret executable not found in PATH"

        except subprocess.TimeoutExpired:
            return [], "Maigret timed out"

        except Exception as exc:
            return [], f"Maigret failed: {exc}"

        try:

            if (
                not os.path.exists(temp_path)
                or os.path.getsize(temp_path) == 0
            ):
                detail = self._short(
                    process.stderr
                    or process.stdout
                    or ""
                )

                if detail:
                    return [], (
                        "Maigret produced no JSON output: "
                        + detail
                    )

                return [], "Maigret produced no JSON output"

            with open(
                temp_path,
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

            if not isinstance(data, dict):
                return [], (
                    "Maigret JSON has an unexpected "
                    "top-level format"
                )

            # Support both:
            #
            # {
            #     "sites": {...}
            # }
            #
            # and:
            #
            # {
            #     "Twitter": {...},
            #     "GitHub": {...}
            # }

            if isinstance(
                data.get("sites"),
                dict,
            ):
                sites = data["sites"]
            else:
                sites = data

            for site, info in sites.items():

                if not isinstance(info, dict):
                    continue

                status = info.get("status", {})

                if isinstance(status, dict):
                    status_value = status.get(
                        "status"
                    )
                else:
                    status_value = status

                status_text = str(
                    status_value or ""
                ).lower()

                url = str(
                    info.get("url_user")
                    or info.get("url")
                    or ""
                ).strip()

                if not url:
                    continue

                claimed = status_text in {
                    "claimed",
                    "found",
                    "true",
                    "200",
                    "available",
                }

                if not claimed:
                    if not info.get("claimed", False):
                        continue

                results.append(
                    self._make_finding(
                        investigation_id,
                        actor_id,
                        username,
                        "maigret",
                        url,
                        0.80,
                        str(site),
                    )
                )

            if process.returncode not in (0, 1):
                if not results:
                    detail = self._short(
                        process.stderr
                        or process.stdout
                        or ""
                    )

                    return [], (
                        f"Maigret exited with code "
                        f"{process.returncode}"
                        + (
                            f": {detail}"
                            if detail
                            else ""
                        )
                    )

            return results, None

        except json.JSONDecodeError as exc:
            return [], (
                f"Maigret returned invalid JSON: {exc}"
            )

        except Exception as exc:
            return [], (
                f"Maigret result parsing failed: {exc}"
            )

        finally:
            try:
                os.remove(temp_path)
            except OSError:
                pass

    # ---------------------------------------------------------
    # BLACKBIRD
    # ---------------------------------------------------------

    def _blackbird(self, username, investigation_id, actor_id):
        """
        Query Blackbird's public endpoint when available.
        """

        results = []

        try:
            import requests

            response = requests.get(
                f"https://blackbird-osint.com/api/user/{username}",
                timeout=15,
                headers={
                    "User-Agent": (
                        "SIH26151-OSINT-Engine/1.0"
                    )
                },
            )

            if response.status_code != 200:
                return [], (
                    "Blackbird returned HTTP "
                    f"{response.status_code}"
                )

            payload = response.json()

            if not isinstance(payload, dict):
                return [], (
                    "Blackbird returned an unexpected "
                    "response format"
                )

            items = payload.get(
                "results",
                [],
            )

            if not isinstance(items, list):
                return [], (
                    "Blackbird results field has an "
                    "unexpected format"
                )

            for item in items:

                if not isinstance(item, dict):
                    continue

                if not item.get("found"):
                    continue

                url = str(
                    item.get("url")
                    or ""
                ).strip()

                if not url:
                    continue

                results.append(
                    self._make_finding(
                        investigation_id,
                        actor_id,
                        username,
                        "blackbird",
                        url,
                        0.70,
                        str(
                            item.get("site")
                            or ""
                        ),
                    )
                )

            return results, None

        except Exception as exc:
            return [], (
                f"Blackbird request failed: {exc}"
            )

    # ---------------------------------------------------------
    # HELPERS
    # ---------------------------------------------------------

    @staticmethod
    def _looks_like_profile_url(
        url: str,
        username: str,
    ) -> bool:
        """
        Keep normal HTTP/HTTPS profile URLs.
        """

        if not url:
            return False

        lower_url = url.lower()

        if (
            lower_url.startswith("https://")
            or lower_url.startswith("http://")
        ):
            return True

        return False

    @staticmethod
    def _platform_from_url(url: str) -> str:
        """
        Extract hostname from a URL.
        """

        match = re.match(
            r"https?://(?:www\.)?([^/]+)",
            url,
        )

        if match:
            return match.group(1)

        return "unknown"

    @staticmethod
    def _short(
        text: str,
        limit: int = 240,
    ) -> str:
        """
        Make an error message short enough for CLI output.
        """

        text = " ".join(
            text.split()
        )

        if len(text) > limit:
            return text[:limit] + "..."

        return text

    @staticmethod
    def _deduplicate(
        findings: list[Finding],
    ) -> list[Finding]:
        """
        Remove duplicate source/URL combinations.
        """

        seen = set()
        result = []

        for finding in findings:

            key = (
                finding.source,
                finding.source_url
                or finding.value,
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(finding)

        return result
