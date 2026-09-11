from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


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
    return datetime.now(timezone.utc)


class Identifier(BaseModel):
    type: FindingType
    value: str

    source: str = "manual"
    source_url: str | None = None

    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
    )


class Evidence(BaseModel):
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


class Finding(BaseModel):
    investigation_id: str

    actor_id: str | None = None

    finding_type: FindingType
    value: str

    source: str
    source_url: str | None = None

    evidence: list[Evidence] = Field(
        default_factory=list
    )

    collected_at: datetime = Field(
        default_factory=utc_now
    )

    first_seen: datetime = Field(
        default_factory=utc_now
    )

    last_seen: datetime = Field(
        default_factory=utc_now
    )

    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class InvestigationInput(BaseModel):
    investigation_id: str

    actor_id: str | None = None

    identifiers: list[Identifier] = Field(
        default_factory=list
    )

    notes: str | None = None


class InvestigationResult(BaseModel):
    investigation_id: str

    actor_id: str | None = None

    findings: list[Finding] = Field(
        default_factory=list
    )

    started_at: datetime

    completed_at: datetime | None = None

    errors: list[str] = Field(
        default_factory=list
    )
