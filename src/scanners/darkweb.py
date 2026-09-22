from __future__ import annotations

import re

import requests
from bs4 import BeautifulSoup

from ..models import Evidence, Finding, Identifier
from .base import Scanner


class DarkWebScanner(Scanner):
    name = "darkweb"
    supported_types = {"username", "domain", "url"}

    def scan(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
        run_id: str | None = None,
    ) -> list[Finding]:
        query = identifier.value.strip()

        if not query:
            return []

        findings: list[Finding] = []

        for technique in (
            self._ahmia,
            self._darksearch,
        ):
            try:
                findings.extend(
                    technique(
                        query,
                        investigation_id,
                        actor_id,
                        run_id,
                    )
                )
            except Exception:
                continue

        return self._deduplicate(findings)

    def _ahmia(
        self,
        query: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        try:
            response = requests.get(
                "https://ahmia.fi/search/",
                params={"q": query},
                timeout=15,
                headers={
                    "User-Agent": (
                        "PRALAYX-OSINT-Engine/1.0 "
                        "(SIH26151; passive-index-search)"
                    )
                },
            )
            response.raise_for_status()
        except requests.RequestException:
            return []

        try:
            soup = BeautifulSoup(
                response.text,
                "html.parser",
            )
        except Exception:
            return []

        findings: list[Finding] = []

        results = (
            soup.select("li.result")
            or soup.select(".result")
        )

        for result in results:
            link_tag = result.find("a")

            if not link_tag:
                continue

            href = str(
                link_tag.get("href", "")
            )

            onion_match = re.search(
                r"https?://[a-z2-7]{16,56}\.onion\S*",
                href,
            )

            if not onion_match:
                onion_match = re.search(
                    r"https?://[a-z2-7]{16,56}\.onion\S*",
                    result.get_text(" ", strip=True),
                )

            if not onion_match:
                continue

            onion_url = onion_match.group(0)

            title = (
                link_tag.get_text(
                    " ",
                    strip=True,
                )
                or None
            )

            excerpt_tag = result.find("p")

            excerpt = (
                excerpt_tag.get_text(
                    " ",
                    strip=True,
                )
                if excerpt_tag
                else None
            )

            context = self._extract_onion_context(
                f"{title or ''} {excerpt or ''}",
                query,
            )

            finding_type = (
                "forum_profile"
                if context["found"]
                else "url"
            )

            evidence = Evidence(
                source="ahmia",
                source_url=onion_url,
                title=title,
                excerpt=excerpt,
                metadata={
                    "matched_query": context["found"],
                    "context": context["context"],
                },
            )

            findings.append(
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type=finding_type,
                    value=onion_url,
                    source="ahmia",
                    source_url=onion_url,
                    confidence=0.65
                    if context["found"]
                    else 0.55,
                    evidence=[evidence],
                    metadata={
                        "onion_url": onion_url,
                        "platform": "ahmia",
                        "title": title,
                        "excerpt": excerpt,
                        "matched_query": context["found"],
                        "context": context["context"],
                        "query": query,
                    },
                )
            )

        return findings

    def _darksearch(
        self,
        query: str,
        investigation_id: str,
        actor_id: str | None,
        run_id: str | None,
    ) -> list[Finding]:
        try:
            response = requests.get(
                "https://darksearch.io/api/search",
                params={"query": query},
                timeout=15,
                headers={
                    "User-Agent": (
                        "PRALAYX-OSINT-Engine/1.0 "
                        "(SIH26151; passive-index-search)"
                    )
                },
            )

            response.raise_for_status()

            data = response.json()

        except requests.RequestException:
            return []
        except ValueError:
            return []

        results = data.get(
            "data",
            [],
        )

        if not isinstance(
            results,
            list,
        ):
            return []

        findings: list[Finding] = []

        for item in results:
            if not isinstance(
                item,
                dict,
            ):
                continue

            link = str(
                item.get(
                    "link",
                    "",
                )
                or ""
            ).strip()

            if not link:
                continue

            title = item.get(
                "title"
            )

            description = item.get(
                "description"
            )

            context = self._extract_onion_context(
                f"{title or ''} {description or ''}",
                query,
            )

            finding_type = (
                "forum_profile"
                if context["found"]
                else "url"
            )

            evidence = Evidence(
                source="darksearch",
                source_url=link,
                title=title,
                excerpt=description,
                metadata={
                    "matched_query": context["found"],
                    "context": context["context"],
                },
            )

            findings.append(
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type=finding_type,
                    value=link,
                    source="darksearch",
                    source_url=link,
                    confidence=0.60
                    if context["found"]
                    else 0.50,
                    evidence=[evidence],
                    metadata={
                        "platform": "darksearch",
                        "title": title,
                        "description": description,
                        "matched_query": context["found"],
                        "context": context["context"],
                        "query": query,
                    },
                )
            )

        return findings

    def _extract_onion_context(
        self,
        text: str,
        query: str,
    ) -> dict:
        if not text or not query:
            return {
                "found": False,
                "context": None,
            }

        lower_text = text.lower()
        lower_query = query.lower()

        index = lower_text.find(
            lower_query
        )

        if index == -1:
            return {
                "found": False,
                "context": None,
            }

        start = max(
            0,
            index - 100,
        )

        end = min(
            len(text),
            index + len(query) + 100,
        )

        return {
            "found": True,
            "context": text[start:end],
        }

    @staticmethod
    def _deduplicate(
        findings: list[Finding],
    ) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        result: list[Finding] = []

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
