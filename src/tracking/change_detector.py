from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable


HIGH_CONFIDENCE_THRESHOLD = 0.80

PLATFORM_TYPES = {
    "username",
    "forum_profile",
    "forum",
    "marketplace",
    "profile",
    "social_profile",
}

WALLET_TYPES = {
    "crypto",
    "wallet",
    "crypto_wallet",
}

ALIAS_TYPES = {
    "username",
    "alias",
    "handle",
    "nickname",
}

POST_TYPES = {
    "post",
    "forum_post",
    "message",
    "content",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def value_of(finding: dict[str, Any]) -> str:
    return str(
        finding.get("normalized_value")
        or finding.get("value")
        or finding.get("identifier")
        or ""
    ).strip()


def type_of(finding: dict[str, Any]) -> str:
    return normalize(
        finding.get("finding_type")
        or finding.get("entity_type")
        or finding.get("type")
    )


def source_of(finding: dict[str, Any]) -> str:
    return normalize(
        finding.get("source")
        or finding.get("source_url")
        or ""
    )


def finding_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    return (
        type_of(finding),
        normalize(value_of(finding)),
        source_of(finding),
    )


def confidence_of(
    finding: dict[str, Any],
) -> float:
    try:
        return float(
            finding.get("confidence", 0.0)
        )
    except (TypeError, ValueError):
        return 0.0


def _looks_like_post(
    finding: dict[str, Any],
) -> bool:
    return any(
        finding.get(field)
        for field in (
            "content",
            "body",
            "message",
            "post_content",
            "post_url",
        )
    )


def _materially_changed(
    before: dict[str, Any],
    after: dict[str, Any],
) -> bool:
    ignored = {
        "last_seen",
        "first_seen",
        "updated_at",
        "observed_at",
        "timestamp",
        "timestamp_parsed",
        "collected_at",
    }

    keys = (
        set(before.keys())
        | set(after.keys())
    ) - ignored

    return any(
        before.get(key) != after.get(key)
        for key in keys
    )


def _is_profile_change(
    before: dict[str, Any],
    after: dict[str, Any],
) -> bool:
    fields = {
        "display_name",
        "username",
        "handle",
        "bio",
        "description",
        "profile_url",
        "avatar",
        "pgp",
        "pgp_key",
        "location",
        "category",
        "status",
    }

    return any(
        before.get(field) != after.get(field)
        for field in fields
        if field in before or field in after
    )


def compare_findings(
    previous: Iterable[dict[str, Any]],
    current: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    previous = list(previous or [])
    current = list(current or [])

    previous_map = {
        finding_key(item): item
        for item in previous
    }

    current_map = {
        finding_key(item): item
        for item in current
    }

    added = [
        item
        for key, item in current_map.items()
        if key not in previous_map
    ]

    removed = [
        item
        for key, item in previous_map.items()
        if key not in current_map
    ]

    changed: list[dict[str, Any]] = []

    for key, after in current_map.items():
        before = previous_map.get(key)

        if before is None:
            continue

        if _materially_changed(before, after):
            changed.append(
                {
                    "before": before,
                    "after": after,
                }
            )

    new_platforms = [
        item
        for item in added
        if type_of(item) in PLATFORM_TYPES
    ]

    new_posts = [
        item
        for item in added
        if (
            type_of(item) in POST_TYPES
            or _looks_like_post(item)
        )
    ]

    new_wallets = [
        item
        for item in added
        if type_of(item) in WALLET_TYPES
    ]

    new_aliases = [
        item
        for item in added
        if type_of(item) in ALIAS_TYPES
    ]

    profile_changes = [
        item
        for item in changed
        if _is_profile_change(
            item["before"],
            item["after"],
        )
    ]

    high_confidence = [
        item
        for item in added
        if confidence_of(item) >= HIGH_CONFIDENCE_THRESHOLD
    ]

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "new_platforms": new_platforms,
        "new_posts": new_posts,
        "new_wallets": new_wallets,
        "new_aliases": new_aliases,
        "profile_changes": profile_changes,
        "high_confidence": high_confidence,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "new_platforms": len(new_platforms),
            "new_posts": len(new_posts),
            "new_wallets": len(new_wallets),
            "new_aliases": len(new_aliases),
            "profile_changes": len(profile_changes),
            "high_confidence": len(high_confidence),
        },
        "checked_at": utc_now(),
    }


def detect_changes(
    previous: Iterable[dict[str, Any]],
    current: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    return compare_findings(
        previous,
        current,
    )


def build_change_events(
    changes: dict[str, Any],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    for finding in changes.get(
        "new_platforms",
        [],
    ):
        events.append(
            {
                "event_type": "new_platform",
                "severity": "HIGH",
                "message": (
                    f"New platform/profile found: "
                    f"{value_of(finding)}"
                ),
                "finding": finding,
            }
        )

    for finding in changes.get(
        "new_posts",
        [],
    ):
        events.append(
            {
                "event_type": "new_post",
                "severity": "MEDIUM",
                "message": (
                    f"New post/content found: "
                    f"{value_of(finding)[:200]}"
                ),
                "finding": finding,
            }
        )

    for finding in changes.get(
        "new_wallets",
        [],
    ):
        events.append(
            {
                "event_type": "new_wallet",
                "severity": "HIGH",
                "message": (
                    f"New wallet identifier found: "
                    f"{value_of(finding)}"
                ),
                "finding": finding,
            }
        )

    for finding in changes.get(
        "new_aliases",
        [],
    ):
        events.append(
            {
                "event_type": "new_alias",
                "severity": "MEDIUM",
                "message": (
                    f"New alias/handle found: "
                    f"{value_of(finding)}"
                ),
                "finding": finding,
            }
        )

    for change in changes.get(
        "profile_changes",
        [],
    ):
        after = change.get(
            "after",
            {},
        )

        events.append(
            {
                "event_type": "profile_changed",
                "severity": "MEDIUM",
                "message": (
                    f"Tracked profile changed: "
                    f"{value_of(after)}"
                ),
                "finding": after,
                "before": change.get(
                    "before",
                ),
            }
        )

    for finding in changes.get(
        "high_confidence",
        [],
    ):
        events.append(
            {
                "event_type": "high_confidence_finding",
                "severity": "HIGH",
                "message": (
                    f"High-confidence finding detected: "
                    f"{value_of(finding)}"
                ),
                "finding": finding,
            }
        )

    return events


def summarize_changes(
    changes: dict[str, Any],
) -> dict[str, Any]:
    counts = changes.get(
        "counts",
        {},
    )

    return {
        "new_findings": counts.get(
            "added",
            0,
        ),
        "removed_findings": counts.get(
            "removed",
            0,
        ),
        "changed_findings": counts.get(
            "changed",
            0,
        ),
        "new_platforms": counts.get(
            "new_platforms",
            0,
        ),
        "new_posts": counts.get(
            "new_posts",
            0,
        ),
        "new_wallets": counts.get(
            "new_wallets",
            0,
        ),
        "new_aliases": counts.get(
            "new_aliases",
            0,
        ),
        "profile_changes": counts.get(
            "profile_changes",
            0,
        ),
        "high_confidence": counts.get(
            "high_confidence",
            0,
        ),
        "checked_at": changes.get(
            "checked_at",
        ),
    }


__all__ = [
    "HIGH_CONFIDENCE_THRESHOLD",
    "compare_findings",
    "detect_changes",
    "build_change_events",
    "summarize_changes",
]
