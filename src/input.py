from __future__ import annotations

import uuid
from typing import Any

from .models import Identifier, InvestigationInput


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
) -> InvestigationInput:

    identifiers: list[Identifier] = []

    values = [
        ("username", username),
        ("email", email),
        ("url", url),
        ("domain", domain),
        ("ip", ip),
        ("pgp", pgp),
        ("crypto", wallet),
    ]

    for kind, value in values:
        if value:
            identifiers.append(
                Identifier(
                    type=kind,
                    value=value,
                )
            )

    return InvestigationInput(
        investigation_id=investigation_id or str(uuid.uuid4()),
        actor_id=actor_id,
        identifiers=identifiers,
    )


def from_crawler_actor_report(
    report: dict[str, Any],
) -> InvestigationInput:
    """
    Convert a crawler Actor Report into the
    common OSINT input contract.
    """

    investigation_id = str(
        report.get("investigation_id")
        or report.get("session_id")
        or uuid.uuid4()
    )

    identifiers: list[Identifier] = []

    for item in report.get("identifiers", []):
        if (
            isinstance(item, dict)
            and item.get("type")
            and item.get("value")
        ):
            identifiers.append(
                Identifier(**item)
            )

    mappings = {
        "username": "username",
        "handle": "username",
        "email": "email",
        "url": "url",
        "domain": "domain",
        "ip": "ip",
        "pgp": "pgp",
        "wallet": "crypto",
        "wallet_address": "crypto",
    }

    for key, kind in mappings.items():
        value = report.get(key)

        if value:
            identifiers.append(
                Identifier(
                    type=kind,
                    value=str(value),
                    source="crawler",
                )
            )

    return InvestigationInput(
        investigation_id=investigation_id,
        actor_id=report.get("actor_id"),
        identifiers=identifiers,
        notes=report.get("notes"),
    )
