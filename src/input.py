from __future__ import annotations

import uuid
from typing import Any

from .models import Identifier, InvestigationInput


def _new_investigation_id() -> str:
    """Generate a standalone OSINT investigation ID."""
    return f"INV-{uuid.uuid4().hex[:8].upper()}"


def _add_identifier(
    identifiers: list[Identifier],
    *,
    identifier_type: str,
    value: Any,
    source: str,
    source_url: str | None = None,
    confidence: float = 1.0,
    metadata: dict[str, Any] | None = None,
) -> None:
    """
    Add one normalized identifier when a usable value exists.
    """
    if value is None:
        return

    value = str(value).strip()

    if not value:
        return

    identifiers.append(
        Identifier(
            type=identifier_type,
            value=value,
            source=source,
            source_url=source_url,
            confidence=confidence,
            metadata=metadata or {},
        )
    )


def make_investigation(
    *,
    username: str | None = None,
    email: str | None = None,
    url: str | None = None,
    domain: str | None = None,
    ip: str | None = None,
    pgp: str | None = None,
    wallet: str | None = None,
    actor_id: str | None = None,
    investigation_id: str | None = None,
    session_id: str | None = None,
    run_id: str | None = None,
    source: str = "manual",
    notes: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> InvestigationInput:
    """
    Build a common InvestigationInput from manual or API supplied values.

    This keeps manual OSINT input compatible with the same contract used
    when crawler findings are passed into the OSINT engine.
    """

    identifiers: list[Identifier] = []

    _add_identifier(
        identifiers,
        identifier_type="username",
        value=username,
        source=source,
    )

    _add_identifier(
        identifiers,
        identifier_type="email",
        value=email,
        source=source,
    )

    _add_identifier(
        identifiers,
        identifier_type="url",
        value=url,
        source=source,
    )

    _add_identifier(
        identifiers,
        identifier_type="domain",
        value=domain,
        source=source,
    )

    _add_identifier(
        identifiers,
        identifier_type="ip",
        value=ip,
        source=source,
    )

    _add_identifier(
        identifiers,
        identifier_type="pgp",
        value=pgp,
        source=source,
    )

    _add_identifier(
        identifiers,
        identifier_type="crypto",
        value=wallet,
        source=source,
    )

    return InvestigationInput(
        investigation_id=(
            investigation_id
            or _new_investigation_id()
        ),
        actor_id=actor_id,
        session_id=session_id,
        run_id=run_id,
        identifiers=identifiers,
        notes=notes,
        metadata=metadata or {},
    )


def _identifier_from_dict(
    item: dict[str, Any],
    *,
    default_source: str = "crawler",
) -> Identifier | None:
    """
    Safely convert a crawler identifier dictionary into an Identifier.

    Invalid entries are ignored rather than breaking the complete crawler
    -> OSINT handoff.
    """

    identifier_type = item.get("type")
    value = item.get("value")

    if not identifier_type or value is None:
        return None

    try:
        return Identifier(
            type=str(identifier_type),
            value=str(value).strip(),
            source=str(
                item.get("source")
                or default_source
            ),
            source_url=item.get("source_url"),
            confidence=float(
                item.get("confidence", 1.0)
            ),
            metadata=dict(
                item.get("metadata")
                or {}
            ),
        )

    except Exception:
        return None


def from_crawler_actor_report(
    report: dict[str, Any],
) -> InvestigationInput:
    """
    Convert a crawler Actor Report into the common OSINT input contract.

    Supported crawler fields include:

        investigation_id
        session_id
        run_id
        actor_id
        identifiers
        username
        handle
        email
        url
        domain
        ip
        pgp
        wallet
        wallet_address
        notes

    The existing investigation/session/run IDs are preserved whenever
    supplied. A new investigation ID is created only when the crawler
    report does not contain one.
    """

    if not isinstance(report, dict):
        raise TypeError(
            "Crawler actor report must be a dictionary."
        )

    investigation_id = str(
        report.get("investigation_id")
        or _new_investigation_id()
    )

    actor_id = report.get(
        "actor_id"
    )

    session_id = report.get(
        "session_id"
    )

    run_id = report.get(
        "run_id"
    )

    identifiers: list[Identifier] = []

    # --------------------------------------------------------------
    # Existing normalized identifier list
    # --------------------------------------------------------------

    raw_identifiers = report.get(
        "identifiers",
        [],
    )

    if isinstance(raw_identifiers, list):

        for item in raw_identifiers:

            if not isinstance(item, dict):
                continue

            identifier = _identifier_from_dict(
                item
            )

            if identifier is not None:
                identifiers.append(
                    identifier
                )

    # --------------------------------------------------------------
    # Common crawler fields
    # --------------------------------------------------------------

    mappings = [
        ("username", "username"),
        ("handle", "username"),
        ("email", "email"),
        ("url", "url"),
        ("domain", "domain"),
        ("ip", "ip"),
        ("pgp", "pgp"),
        ("wallet", "crypto"),
        ("wallet_address", "crypto"),
    ]

    for key, identifier_type in mappings:

        value = report.get(key)

        if value is None:
            continue

        _add_identifier(
            identifiers,
            identifier_type=identifier_type,
            value=value,
            source="crawler",
            source_url=report.get(
                f"{key}_url"
            ),
        )

    # --------------------------------------------------------------
    # Remove exact duplicate identifiers
    # --------------------------------------------------------------

    unique: dict[
        tuple[str, str],
        Identifier,
    ] = {}

    for identifier in identifiers:

        key = (
            str(identifier.type).lower(),
            identifier.value.strip().lower(),
        )

        if not key[1]:
            continue

        existing = unique.get(key)

        if existing is None:
            unique[key] = identifier
            continue

        # Prefer the higher-confidence representation.
        if (
            identifier.confidence
            > existing.confidence
        ):
            unique[key] = identifier

    return InvestigationInput(
        investigation_id=investigation_id,
        actor_id=actor_id,
        session_id=session_id,
        run_id=run_id,
        identifiers=list(
            unique.values()
        ),
        notes=report.get("notes"),
        metadata=dict(
            report.get("metadata")
            or {}
        ),
    )


def from_crawler_result(
    result: dict[str, Any],
) -> InvestigationInput:
    """
    Generic crawler-result adapter.

    This is intentionally separate from from_crawler_actor_report() because
    the crawler may eventually expose a session/result object rather than
    only an Actor Report.

    If the result contains an embedded actor report, that report is used as
    the primary source.
    """

    if not isinstance(result, dict):
        raise TypeError(
            "Crawler result must be a dictionary."
        )

    actor_report = result.get(
        "actor_report"
    )

    if isinstance(actor_report, dict):

        merged = dict(actor_report)

        # Preserve top-level PRALAYX context when present.
        for field in (
            "investigation_id",
            "session_id",
            "run_id",
            "actor_id",
        ):
            if (
                not merged.get(field)
                and result.get(field)
            ):
                merged[field] = result[field]

        return from_crawler_actor_report(
            merged
        )

    return from_crawler_actor_report(
        result
    )
