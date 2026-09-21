from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from .models import FindingType, Identifier, InvestigationInput


_EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)

_IPV4_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)

_IPV6_RE = re.compile(
    r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$"
)

_DOMAIN_RE = re.compile(
    r"^(?!https?://)"
    r"(?:[a-zA-Z0-9-]+\.)+"
    r"[a-zA-Z]{2,}(?:\.onion)?$"
)

_URL_RE = re.compile(
    r"^https?://",
    re.IGNORECASE,
)

_BTC_RE = re.compile(
    r"^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$"
)

_ETH_RE = re.compile(
    r"^0x[a-fA-F0-9]{40}$"
)

_XMR_RE = re.compile(
    r"^4[0-9AB][0-9a-zA-Z]{93}$"
)

_PGP_FINGERPRINT_RE = re.compile(
    r"^[A-Fa-f0-9]{16,40}$"
)


class Normalizer:
    """
    Canonicalizes identifiers before scanners/providers execute.

    The normalizer is intentionally conservative:
    - raw values are not destroyed
    - source/source_url/confidence/metadata are preserved
    - only the value used for matching is normalized
    """

    # ------------------------------------------------------------------
    # Identifier normalization
    # ------------------------------------------------------------------

    def normalize_identifier(
        self,
        identifier: Identifier,
    ) -> Identifier:
        """
        Return a normalized copy of an Identifier.
        """

        value = identifier.value.strip()

        if identifier.type == "username":
            value = self.normalize_username(value)

        elif identifier.type == "email":
            value = self.normalize_email(value)

        elif identifier.type == "domain":
            value = self.normalize_domain(value)

        elif identifier.type == "url":
            value = self.normalize_url(value)

        elif identifier.type == "ip":
            value = self.normalize_ip(value)

        elif identifier.type == "crypto":
            value = self.normalize_crypto(value)

        elif identifier.type == "pgp":
            value = self.normalize_pgp(value)

        return identifier.model_copy(
            update={
                "value": value,
            }
        )

    # ------------------------------------------------------------------
    # Username
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_username(
        value: str,
    ) -> str:
        """
        Normalize common username representations.

        Examples:

            @dealer_xyz  -> dealer_xyz
            dealer_xyz   -> dealer_xyz
        """
        return value.strip().lstrip("@")

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_email(
        value: str,
    ) -> str:
        """
        Email matching is case-insensitive in the local OSINT context.
        """
        return value.strip().lower()

    # ------------------------------------------------------------------
    # Domain
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_domain(
        value: str,
    ) -> str:
        """
        Convert common domain representations into a canonical hostname.

        Examples:

            https://example.com/path -> example.com
            www.example.com          -> example.com
            EXAMPLE.COM              -> example.com
        """
        value = value.strip().lower()

        # Remove scheme.
        value = re.sub(
            r"^https?://",
            "",
            value,
            flags=re.IGNORECASE,
        )

        # Remove credentials/port/path when possible.
        value = value.split("/", 1)[0]
        value = value.split("?", 1)[0]
        value = value.split("#", 1)[0]

        # Remove common www prefix.
        if value.startswith("www."):
            value = value[4:]

        # Remove trailing dot.
        value = value.rstrip(".")

        return value

    # ------------------------------------------------------------------
    # URL
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_url(
        value: str,
    ) -> str:
        """
        Normalize a URL while preserving its meaningful path/query.

        A missing scheme is given http:// so downstream URL tools receive
        a syntactically valid URL.
        """
        value = value.strip()

        if not value:
            return value

        if not _URL_RE.match(value):
            value = f"http://{value}"

        try:
            parsed = urlsplit(value)

            scheme = parsed.scheme.lower()

            hostname = (
                parsed.hostname.lower()
                if parsed.hostname
                else ""
            )

            if not hostname:
                return value

            # Preserve an explicitly supplied port.
            netloc = hostname

            try:
                if parsed.port:
                    netloc = (
                        f"{hostname}:{parsed.port}"
                    )
            except ValueError:
                # Invalid port; leave the original URL untouched.
                return value

            return urlunsplit(
                (
                    scheme,
                    netloc,
                    parsed.path,
                    parsed.query,
                    parsed.fragment,
                )
            )

        except Exception:
            return value

    # ------------------------------------------------------------------
    # IP
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_ip(
        value: str,
    ) -> str:
        """
        Normalize an IP without changing its address semantics.
        """
        return value.strip()

    # ------------------------------------------------------------------
    # Cryptocurrency
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_crypto(
        value: str,
    ) -> str:
        """
        Normalize cryptocurrency identifiers conservatively.

        We intentionally do not modify case globally because some
        cryptocurrency formats are case-sensitive.
        """
        return value.strip()

    # ------------------------------------------------------------------
    # PGP
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_pgp(
        value: str,
    ) -> str:
        """
        Normalize a PGP fingerprint by removing whitespace and uppercasing.
        """
        return (
            value
            .strip()
            .replace(" ", "")
            .replace(":", "")
            .upper()
        )

    # ------------------------------------------------------------------
    # Type detection
    # ------------------------------------------------------------------

    def detect_type(
        self,
        value: str,
    ) -> FindingType:
        """
        Best-effort detection of an identifier type.

        This is used primarily for free-text/manual input.

        It intentionally falls back to username because usernames are the
        most common ambiguous OSINT identifier.
        """
        value = value.strip()

        if not value:
            return "username"

        if _EMAIL_RE.match(value):
            return "email"

        if (
            _URL_RE.match(value)
            or ".onion" in value.lower()
        ):
            return "url"

        if (
            _IPV4_RE.match(value)
            or _IPV6_RE.match(value)
        ):
            return "ip"

        if (
            _BTC_RE.match(value)
            or _ETH_RE.match(value)
            or _XMR_RE.match(value)
        ):
            return "crypto"

        compact = (
            value
            .replace(" ", "")
            .replace(":", "")
        )

        if (
            _PGP_FINGERPRINT_RE.match(compact)
            and len(compact) in (16, 40)
        ):
            return "pgp"

        if _DOMAIN_RE.match(value):
            return "domain"

        return "username"

    # ------------------------------------------------------------------
    # Automatic identifier creation
    # ------------------------------------------------------------------

    def identifier_from_value(
        self,
        value: str,
        *,
        source: str = "manual",
        source_url: str | None = None,
        confidence: float = 1.0,
    ) -> Identifier:
        """
        Convert arbitrary investigator/crawler text into an Identifier.
        """
        identifier_type = self.detect_type(
            value
        )

        identifier = Identifier(
            type=identifier_type,
            value=value,
            source=source,
            source_url=source_url,
            confidence=confidence,
        )

        return self.normalize_identifier(
            identifier
        )

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def deduplicate(
        self,
        identifiers: list[Identifier],
    ) -> list[Identifier]:
        """
        Normalize and remove duplicate identifiers.

        Deduplication uses:

            normalized type + normalized value

        The first occurrence is retained so its source metadata remains
        available.
        """
        seen: set[tuple[str, str]] = set()

        result: list[Identifier] = []

        for identifier in identifiers:

            normalized = (
                self.normalize_identifier(
                    identifier
                )
            )

            key = (
                str(normalized.type).lower(),
                normalized.value.lower(),
            )

            if not normalized.value:
                continue

            if key in seen:
                continue

            seen.add(key)

            result.append(
                normalized
            )

        return result

    # ------------------------------------------------------------------
    # Investigation normalization
    # ------------------------------------------------------------------

    def normalize_investigation_input(
        self,
        investigation: InvestigationInput,
    ) -> InvestigationInput:
        """
        Normalize the complete InvestigationInput.

        Investigation/session/run IDs are preserved exactly.
        Only identifier representations are normalized.
        """
        cleaned_identifiers = (
            self.deduplicate(
                investigation.identifiers
            )
        )

        return investigation.model_copy(
            update={
                "identifiers": cleaned_identifiers,
            }
        )
