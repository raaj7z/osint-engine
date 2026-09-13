"""Base provider interface for the OSINT engine."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Finding, Identifier


class Provider(ABC):
    """Base class for all external OSINT providers."""

    name: str = "unknown"
    supported_types: set[str] = set()

    def supports(self, identifier: Identifier) -> bool:
        """Return True when this provider supports the identifier type."""
        return identifier.type in self.supported_types

    @abstractmethod
    def query(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
    ) -> list[Finding]:
        """Query the provider and return normalized findings."""
        raise NotImplementedError
