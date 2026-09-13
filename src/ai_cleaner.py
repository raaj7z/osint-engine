"""AI-assisted cleaning layer for raw dark-web crawler output.

Filters noise (throwaway usernames, irrelevant posts) and scores
remaining content for relevance before it's handed to the OSINT
engine as an InvestigationInput.
"""

import json
import re

from .models import Identifier, InvestigationInput

TRASH_USERNAMES = {
    "admin", "administrator", "root", "user", "guest",
    "anonymous", "anon", "test", "null", "undefined",
    "moderator", "mod", "staff", "support", "help",
    "info", "contact", "noreply", "no-reply", "webmaster",
    "postmaster", "abuse", "security", "system", "bot",
    "api", "service", "daemon", "operator", "nobody",
}

RELEVANCE_KEYWORDS = [
    "exploit", "hack", "sell", "buy", "drug", "weapon",
    "data", "leak", "breach", "fraud", "carding", "money",
    "btc", "xmr", "monero", "bitcoin", "wallet", "escrow",
    "vendor", "verified", "trusted", "pgp", "jabber",
    "ransomware", "malware", "botnet", "ddos", "rat",
    "stealer", "logger", "crypt", "bypass", "shell",
]

COMMON_ENGLISH_WORDS = {
    "the", "and", "for", "with", "this", "that", "have",
    "from", "your", "you", "are", "was", "were",
}


class AICleaner:
    """Cleans and scores raw crawler output before it enters the OSINT engine."""

    def __init__(self):
        """Compile regex patterns used for cleaning."""
        self._relevance_pattern = re.compile(
            "|".join(re.escape(k) for k in RELEVANCE_KEYWORDS), re.IGNORECASE
        )
        self._all_numeric_pattern = re.compile(r"^\d+$")

    def clean_crawler_output(self, raw: dict) -> dict:
        """Transform raw crawler JSON into filtered, scored, actionable intelligence."""
        usernames = raw.get("usernames", [])
        posts = raw.get("posts", [])

        cleaned_usernames = self._clean_usernames(usernames)
        cleaned_posts = self._clean_posts(posts)
        threat_indicators = self._extract_threat_indicators(raw)
        actor_profile = self._consolidate_profile(raw)

        identifiers = [
            {
                "type": "username",
                "value": u["value"],
                "confidence": u["confidence"],
                "context": u["reason"],
            }
            for u in cleaned_usernames
        ]

        for email in raw.get("emails", []):
            identifiers.append(
                {"type": "email", "value": email, "confidence": 0.8, "context": "crawler-extracted"}
            )

        for addr in raw.get("crypto_addresses", []):
            identifiers.append(
                {"type": "crypto", "value": addr, "confidence": 0.75, "context": "crawler-extracted"}
            )

        for link in raw.get("links", []):
            identifiers.append(
                {"type": "url", "value": link, "confidence": 0.6, "context": "crawler-extracted"}
            )

        opsec_leaks = [m for m in raw.get("misconfigs", []) if isinstance(m, dict)]

        return {
            "identifiers": identifiers,
            "relevant_posts": cleaned_posts,
            "threat_indicators": threat_indicators,
            "opsec_leaks": opsec_leaks,
            "actor_profile": actor_profile,
            "cleaning_stats": {
                "removed": len(usernames) - len(cleaned_usernames),
                "kept": len(cleaned_usernames),
                "relevance_scores": [p["relevance_score"] for p in cleaned_posts],
            },
        }

    def _clean_usernames(self, usernames: list) -> list:
        """Filter out throwaway/junk usernames and score the rest by relevance."""
        results = []

        for raw_username in usernames:
            username = raw_username.get("value") if isinstance(raw_username, dict) else raw_username
            context = raw_username.get("context", "") if isinstance(raw_username, dict) else ""

            if not username:
                continue

            lower = username.lower().strip()

            if lower in TRASH_USERNAMES:
                continue
            if len(lower) < 3 or len(lower) > 25:
                continue
            if self._all_numeric_pattern.match(lower):
                continue
            if lower in COMMON_ENGLISH_WORDS:
                continue

            score = self._score_relevance(f"{username} {context}")
            results.append(
                {
                    "value": username,
                    "confidence": round(0.5 + score * 0.5, 2),
                    "reason": f"relevance_score={score:.2f}",
                }
            )

        return results

    def _score_relevance(self, text: str) -> float:
        """Score text 0.0-1.0 based on the density of threat-relevant keywords."""
        if not text:
            return 0.0
        matches = self._relevance_pattern.findall(text)
        return min(len(matches) * 0.15, 1.0)

    def _clean_posts(self, posts: list, min_score: float = 0.3) -> list:
        """Score posts by relevance, drop low-relevance ones, and sort by score descending."""
        scored = []
        for post in posts:
            text = post.get("text", "") if isinstance(post, dict) else str(post)
            score = self._score_relevance(text)
            if score < min_score:
                continue
            entities = self._relevance_pattern.findall(text)
            scored.append(
                {
                    **(post if isinstance(post, dict) else {"text": text}),
                    "relevance_score": score,
                    "matched_keywords": list({e.lower() for e in entities}),
                }
            )

        return sorted(scored, key=lambda p: p["relevance_score"], reverse=True)

    def _extract_threat_indicators(self, data: dict) -> list:
        """Pull out drug/weapon/data-sale indicators, financial fraud signals, and critical misconfigs."""
        indicators = []
        drug_weapon_pattern = re.compile(
            r"\b(cocaine|heroin|fentanyl|mdma|weapon|firearm|gun|ammunition)\b", re.IGNORECASE
        )
        fraud_pattern = re.compile(
            r"\b(ransomware|fraud|carding|stolen data|dump)\b", re.IGNORECASE
        )

        for post in data.get("posts", []):
            text = post.get("text", "") if isinstance(post, dict) else str(post)

            for match in drug_weapon_pattern.findall(text):
                indicators.append(
                    {
                        "type": "illicit_goods",
                        "value": match,
                        "severity": "HIGH",
                        "context": text[:200],
                    }
                )

            for match in fraud_pattern.findall(text):
                indicators.append(
                    {
                        "type": "financial_crime",
                        "value": match,
                        "severity": "HIGH",
                        "context": text[:200],
                    }
                )

        for addr in data.get("crypto_addresses", []):
            addr_text = addr if isinstance(addr, str) else json.dumps(addr)
            if fraud_pattern.search(addr_text):
                indicators.append(
                    {
                        "type": "crypto_fraud",
                        "value": addr_text,
                        "severity": "MEDIUM",
                        "context": "matched in crypto address context",
                    }
                )

        for misconfig in data.get("misconfigs", []):
            if isinstance(misconfig, dict) and misconfig.get("severity") == "CRITICAL":
                indicators.append(
                    {
                        "type": "opsec_misconfig",
                        "value": misconfig.get("value", ""),
                        "severity": "CRITICAL",
                        "context": misconfig.get("description", ""),
                    }
                )

        return indicators

    def _consolidate_profile(self, data: dict) -> dict:
        """Merge PGP keys, contact methods, aliases, and comms channels into one deduped profile."""
        pgp_keys = list(dict.fromkeys(data.get("pgp_keys", [])))
        contact_methods = list(
            dict.fromkeys(
                data.get("emails", []) + data.get("jabber_ids", []) + data.get("telegram_handles", [])
            )
        )
        aliases = list(
            dict.fromkeys(
                [u.get("value") if isinstance(u, dict) else u for u in data.get("usernames", [])]
            )
        )
        comms_channels = list(dict.fromkeys(data.get("trust_links", [])))

        return {
            "pgp_keys": pgp_keys,
            "contact_methods": contact_methods,
            "aliases": aliases,
            "communication_channels": comms_channels,
        }

    def clean_and_prepare(self, crawler_json_path: str) -> InvestigationInput:
        """Load a crawler JSON export, clean it, and return a ready-to-run InvestigationInput."""
        with open(crawler_json_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        cleaned = self.clean_crawler_output(raw)

        identifiers = [
            Identifier(
                type=i["type"],
                value=i["value"],
                source="ai_cleaner",
                confidence=i["confidence"],
            )
            for i in cleaned["identifiers"]
        ]

        investigation_id = raw.get("investigation_id") or raw.get("scan_id") or "AI-CLEANED"
        actor_id = raw.get("actor_id")

        return InvestigationInput(
            investigation_id=investigation_id,
            actor_id=actor_id,
            identifiers=identifiers,
            notes=json.dumps(
                {
                    "threat_indicators": cleaned["threat_indicators"],
                    "opsec_leaks": cleaned["opsec_leaks"],
                    "actor_profile": cleaned["actor_profile"],
                    "cleaning_stats": cleaned["cleaning_stats"],
                },
                default=str,
            ),
        )
