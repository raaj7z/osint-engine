from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Finding, Identifier


class Scanner(ABC):
    """
    Base interface for all local OSINT scanners.

    Scanners perform deterministic or tool-assisted analysis of an
    identifier. They do not own investigation/session/run persistence;
    that context is supplied by the engine.
    """

    name: str = "base"

    # Identifier types this scanner can process.
    supported_types: set[str] = set()

    # Human-readable description used by the engine registry/UI.
    description: str = ""

    # Whether the scanner normally requires an external API/service.
    requires_external_service: bool = False

    def supports(
        self,
        identifier: Identifier,
    ) -> bool:
        """
        Return True when this scanner can process the identifier type.
        """
        return identifier.type in self.supported_types

    def registry_info(self) -> dict:
        """
        Return metadata describing this scanner.

        This is intentionally side-effect free so the platform can expose
        scanner configuration/status without executing the scanner.
        """
        return {
            "name": self.name,
            "description": self.description,
            "supported_types": sorted(
                self.supported_types
            ),
            "requires_external_service": (
                self.requires_external_service
            ),
        }

    def validate_identifier(
        self,
        identifier: Identifier,
    ) -> bool:
        """
        Basic validation hook.

        Individual scanners can override this when they need stricter
        validation. The default behavior only requires a non-empty value.
        """
        return bool(
            identifier.value
            and identifier.value.strip()
        )

    @abstractmethod
    def scan(
        self,
        identifier: Identifier,
        investigation_id: str,
        actor_id: str | None = None,
        run_id: str | None = None,
    ) -> list[Finding]:
        
        raise NotImplementedError
