"""Dark web scanner for the OSINT engine.

Searches public dark-web indexing services (Ahmia, DarkSearch) for
mentions of a username, domain, or URL. These are passive, surface-web
API calls against services that already crawl .onion content — no
direct Tor connection is required.
"""

import re

import requests
from bs4 import BeautifulSoup

from ..models import Identifier, Finding
from .base import Scanner


class DarkWebScanner(Scanner):
    """Scanner that queries public dark-web search indexes for an identifier."""

    name = "darkweb"
    supported_types = {"username", "domain", "url"}

    def scan(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
    ) -> list[Finding]:
        """Query all dark-web indexes for the identifier and return combined findings."""
        query = identifier.value
        findings: list[Finding] = []

        for technique in (self._ahmia, self._darksearch):
            try:
                findings.extend(technique(query, investigation_id, actor_id))
            except Exception:
                continue

        return findings

    def _ahmia(self, query: str, iid: str, aid: str | None) -> list[Finding]:
        """Search Ahmia's public dark-web index and extract .onion result links."""
        try:
            resp = requests.get(
                "https://ahmia.fi/search/",
                params={"q": query},
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            resp.raise_for_status()
        except Exception:
            return []

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return []

        findings: list[Finding] = []
        results = soup.select("li.result") or soup.select(".result")

        for result in results:
            link_tag = result.find("a")
            if not link_tag:
                continue

            href = link_tag.get("href", "")
            onion_match = re.search(r"https?://[a-z2-7]{16,56}\.onion\S*", href)
            if not onion_match:
                # Ahmia sometimes wraps a redirect URL containing the real onion link in text.
                onion_match = re.search(
                    r"https?://[a-z2-7]{16,56}\.onion\S*", result.get_text()
                )
            if not onion_match:
                continue

            onion_url = onion_match.group(0)
            title = link_tag.get_text(strip=True) or None
            excerpt_tag = result.find("p")
            excerpt = excerpt_tag.get_text(strip=True) if excerpt_tag else None

            context = self._extract_onion_context(
                f"{title or ''} {excerpt or ''}", query
            )

            finding_type = "forum_profile" if context["found"] else "url"

            finding = Finding(
                investigation_id=iid,
                actor_id=aid,
                finding_type=finding_type,
                value=onion_url,
                source="ahmia",
                source_url=onion_url,
                confidence=0.65,
                metadata={
                    "onion_url": onion_url,
                    "source": "ahmia",
                    "title": title,
                    "excerpt": excerpt,
                    "matched_query": context["found"],
                    "context": context["context"],
                },
            )
            findings.append(finding)

        return findings

    def _darksearch(self, query: str, iid: str, aid: str | None) -> list[Finding]:
        """Search DarkSearch's public API and return matching results as findings."""
        try:
            resp = requests.get(
                "https://darksearch.io/api/search",
                params={"query": query},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        results = data.get("data", [])
        findings: list[Finding] = []

        for item in results:
            link = item.get("link", "")
            title = item.get("title")
            description = item.get("description")

            context = self._extract_onion_context(
                f"{title or ''} {description or ''}", query
            )

            finding_type = "forum_profile" if context["found"] else "url"

            finding = Finding(
                investigation_id=iid,
                actor_id=aid,
                finding_type=finding_type,
                value=link,
                source="darksearch",
                source_url=link,
                confidence=0.60,
                metadata={
                    "title": title,
                    "description": description,
                    "matched_query": context["found"],
                    "context": context["context"],
                },
            )
            findings.append(finding)

        return findings

    def _extract_onion_context(self, text: str, username: str) -> dict:
        """Check whether the query term appears in text and return the surrounding context.

        Returns {"found": bool, "context": str | None}, where context is
        up to 200 characters centered on the match.
        """
        if not text or not username:
            return {"found": False, "context": None}

        lower_text = text.lower()
        lower_query = username.lower()
        idx = lower_text.find(lower_query)

        if idx == -1:
            return {"found": False, "context": None}

        start = max(0, idx - 100)
        end = min(len(text), idx + len(username) + 100)
        return {"found": True, "context": text[start:end]}
