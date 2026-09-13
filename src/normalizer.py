


import re

from .models import FindingType, Identifier, InvestigationInput

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
_DOMAIN_RE = re.compile(r"^(?!https?://)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\.onion)?$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_BTC_RE = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$")
_ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_XMR_RE = re.compile(r"^4[0-9AB][0-9a-zA-Z]{93}$")
_PGP_FINGERPRINT_RE = re.compile(r"^[A-Fa-f0-9]{16,40}$")


class Normalizer:
    """Normalizes and auto-detects the type of raw identifier values."""

    def normalize_identifier(self, identifier: Identifier) -> Identifier:
        """Return a cleaned copy of an Identifier with a normalized value for its type."""
        value = identifier.value.strip()

        if identifier.type == "email":
            value = self.normalize_email(value)
        elif identifier.type == "domain":
            value = self.normalize_domain(value)
        elif identifier.type == "url":
            value = self.normalize_url(value)
        elif identifier.type == "ip":
            value = self.normalize_ip(value)
        elif identifier.type == "username":
            value = self.normalize_username(value)
        elif identifier.type == "crypto":
            value = value.strip()
        elif identifier.type == "pgp":
            value = value.strip().upper().replace(" ", "")

        return identifier.model_copy(update={"value": value})

    def normalize_username(self, value: str) -> str:
        """Trim whitespace and strip a leading @ from a username."""
        return value.strip().lstrip("@")

    def normalize_email(self, value: str) -> str:
        """Trim whitespace and lowercase an email address."""
        return value.strip().lower()

    def normalize_domain(self, value: str) -> str:
        """Strip scheme/path/whitespace and lowercase a domain."""
        value = value.strip().lower()
        value = re.sub(r"^https?://", "", value)
        value = value.split("/")[0]
        value = value.lstrip("www.")
        return value

    def normalize_url(self, value: str) -> str:
        """Trim whitespace and ensure a URL has an explicit scheme."""
        value = value.strip()
        if not _URL_RE.match(value):
            value = f"http://{value}"
        return value

    def normalize_ip(self, value: str) -> str:
        """Trim whitespace from an IP address (IPv4/IPv6 untouched otherwise)."""
        return value.strip()

    def detect_type(self, value: str) -> FindingType:
        """Best-effort auto-detection of an identifier's type from its raw string form.

        Falls back to "username" if nothing more specific matches, since
        that's the most common free-text identifier in this domain.
        """
        value = value.strip()

        if _EMAIL_RE.match(value):
            return "email"
        if _URL_RE.match(value) or ".onion" in value.lower():
            return "url"
        if _IPV4_RE.match(value) or _IPV6_RE.match(value):
            return "ip"
        if _BTC_RE.match(value) or _ETH_RE.match(value) or _XMR_RE.match(value):
            return "crypto"
        if _PGP_FINGERPRINT_RE.match(value) and len(value) in (16, 40):
            return "pgp"
        if _DOMAIN_RE.match(value):
            return "domain"

        return "username"

    def deduplicate(self, identifiers: list[Identifier]) -> list[Identifier]:
        """Remove duplicate identifiers, keyed on (type, normalized value)."""
        seen: set[tuple[str, str]] = set()
        result: list[Identifier] = []

        for identifier in identifiers:
            normalized = self.normalize_identifier(identifier)
            key = (normalized.type, normalized.value.lower())
            if key in seen:
                continue
            seen.add(key)
            result.append(normalized)

        return result

    def normalize_investigation_input(self, investigation: InvestigationInput) -> InvestigationInput:
        """Return a copy of an InvestigationInput with all identifiers normalized and deduplicated."""
        cleaned_identifiers = self.deduplicate(investigation.identifiers)
        return investigation.model_copy(update={"identifiers": cleaned_identifiers})
