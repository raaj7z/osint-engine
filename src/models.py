from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared finding/identifier types
# ---------------------------------------------------------------------------

FindingType = Literal[
    "username",
    "email",
    "url",
    "domain",
    "dns",
    "ip",
    "pgp",
    "crypto",
    "forum_profile",
    "infrastructure",
    "evidence",
    "other",
]


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Identifier
# ---------------------------------------------------------------------------

class Identifier(BaseModel):
    """
    Input supplied to the OSINT engine.

    An identifier may originate from:
    - manual investigator input
    - crawler output
    - another OSINT module
    - a previously discovered finding
    """

    type: FindingType
    value: str

    source: str = "manual"
    source_url: str | None = None

    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class Evidence(BaseModel):
    """
    Evidence supporting a finding.

    The original source should remain identifiable so that an investigator
    can later verify where the finding came from.
    """

    source: str

    source_url: str | None = None

    title: str | None = None

    excerpt: str | None = None

    collected_at: datetime = Field(
        default_factory=utc_now
    )

    hash_sha256: str | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """
    Normalized OSINT finding.

    This is the common object exchanged between scanners/providers and
    PRALAYX.
    """

    # Investigation context
    investigation_id: str

    # Optional actor context.
    actor_id: str | None = None

    # Optional PRALAYX OSINT run context.
    #
    # The field is optional so the existing standalone OSINT engine remains
    # backwards compatible.
    run_id: str | None = None

    # What was found
    finding_type: FindingType

    value: str

    # Origin
    source: str

    source_url: str | None = None

    # Supporting evidence
    evidence: list[Evidence] = Field(
        default_factory=list
    )

    # Timestamps
    collected_at: datetime = Field(
        default_factory=utc_now
    )

    first_seen: datetime = Field(
        default_factory=utc_now
    )

    last_seen: datetime = Field(
        default_factory=utc_now
    )

    # Confidence is always normalized to 0.0 - 1.0.
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    # Additional provider/scanner information.
    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Investigation input
# ---------------------------------------------------------------------------

class InvestigationInput(BaseModel):
    """
    Input accepted by the OSINT engine.

    The same model can represent:
    - manual OSINT investigation
    - crawler -> OSINT handoff
    - future API/platform input
    """

    investigation_id: str

    actor_id: str | None = None

    # Optional session/run context supplied by PRALAYX.
    session_id: str | None = None

    run_id: str | None = None

    identifiers: list[Identifier] = Field(
        default_factory=list
    )

    notes: str | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Investigation result
# ---------------------------------------------------------------------------

class InvestigationResult(BaseModel):
    """
    Complete result returned by the OSINT engine.

    The core result remains compatible with the previous engine while
    exposing additional context needed by PRALAYX.
    """

    investigation_id: str

    actor_id: str | None = None

    session_id: str | None = None

    run_id: str | None = None

    findings: list[Finding] = Field(
        default_factory=list
    )

    started_at: datetime

    completed_at: datetime | None = None

    errors: list[str] = Field(
        default_factory=list
    )

    # Overall execution status.
    #
    # The engine uses strings here instead of a restrictive Literal so
    # future platform statuses can be introduced without breaking old
    # serialized results.
    status: str = "NO_RESULTS"

    # Detailed scanner/provider execution events.
    execution_log: list[dict[str, Any]] = Field(
        default_factory=list
    )

    # Snapshot of which components were available for this run.
    component_registry: list[dict[str, Any]] = Field(
        default_factory=list
    )

    # Raw/extra information that should survive report generation.
    metadata: dict[str, Any] = Field(
        default_factory=dict
    )
