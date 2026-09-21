"""
Base provider interface for the OSINT engine.

Providers represent external services/APIs such as VirusTotal, Shodan,
Censys, AbuseIPDB, URLScan, etc.

The base interface keeps provider execution separate from:
- investigation persistence
- terminal/event logging
- report generation
- scheduling
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Finding, Identifier


class Provider(ABC):
    """
    Base class for all external OSINT providers.
    """

    name: str = "unknown"

    # Identifier types accepted by this provider.
    supported_types: set[str] = set()

    # Human-readable description for registry/UI.
    description: str = ""

    # Environment/API configuration metadata.
    requires_api_key: bool = False

    # Environment variable names required by this provider.
    api_key_env: str | None = None

    # Optional rate-limit information.
    requests_per_minute: int | None = None

    def supports(
        self,
        identifier: Identifier,
    ) -> bool:
        """
        Return True when this provider supports the identifier type.
        """
        return identifier.type in self.supported_types

    def registry_info(self) -> dict:
        """
        Return provider metadata without executing a request.

        This allows the engine/platform to show whether a provider exists,
        what it supports, and what configuration it requires.
        """
        return {
            "name": self.name,
            "description": self.description,
            "supported_types": sorted(
                self.supported_types
            ),
            "requires_api_key": self.requires_api_key,
            "api_key_env": self.api_key_env,
            "requests_per_minute": self.requests_per_minute,
        }

    def is_configured(self) -> bool:
        """
        Return whether the provider has its required configuration.

        Providers that do not require an API key are considered configured.

        This method deliberately does not make a network request.
        """
        if not self.requires_api_key:
            return True

        if not self.api_key_env:
            return False

        import os

        return bool(
            os.getenv(self.api_key_env)
        )

    def configuration_reason(self) -> str | None:
        """
        Return a human-readable configuration reason.

        None means the provider is configured.
        """
        if self.is_configured():
            return None

        if self.api_key_env:
            return (
                f"API key not configured "
                f"({self.api_key_env})"
            )

        return "Required provider configuration is missing"

    def validate_identifier(
        self,
        identifier: Identifier,
    ) -> bool:
        """
        Basic validation hook.

        Individual providers can override this when they require
        stricter validation.
        """
        return bool(
            identifier.value
            and identifier.value.strip()
        )

    @abstractmethod
    def query(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
        run_id: str | None = None,
    ) -> list[Finding]:
        """
        Execute the provider query.

        Implementations should:
        - return Finding objects
        - preserve source/source_url information
        - preserve evidence when available
        - avoid silently converting API/configuration errors into []
        - avoid mutating the supplied Identifier
        - attach run_id to generated findings when supported
        """
        raise NotImplementedError
