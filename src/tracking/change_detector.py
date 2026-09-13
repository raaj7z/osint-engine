"""Detects meaningful changes between two scans of the same actor."""

from ..models import Finding


class ChangeDetector:
    """Compares two sets of findings and summarizes what changed."""

    def detect(self, previous: list[Finding], current: list[Finding]) -> dict:
        """Diff two finding sets keyed on (finding_type, value, source) and summarize the changes."""

        def key(f: Finding) -> tuple[str, str, str]:
            return (f.finding_type, f.value.lower(), f.source)

        previous_map = {key(f): f for f in previous}
        current_map = {key(f): f for f in current}

        previous_keys = set(previous_map.keys())
        current_keys = set(current_map.keys())

        added_keys = current_keys - previous_keys
        removed_keys = previous_keys - current_keys

        added = [current_map[k] for k in added_keys]
        removed = [previous_map[k] for k in removed_keys]

        new_platforms = [
            f.metadata.get("platform", f.source)
            for f in added
            if f.finding_type in ("username", "forum_profile")
        ]
        new_wallets = [f.value for f in added if f.finding_type == "crypto"]
        new_emails = [f.value for f in added if f.finding_type == "email"]
        high_confidence_new = [f for f in added if f.confidence > 0.7]

        summary = f"{len(added)} new findings, {len(new_platforms)} new platforms"

        return {
            "added": added,
            "removed": removed,
            "new_platforms": new_platforms,
            "new_wallets": new_wallets,
            "new_emails": new_emails,
            "high_confidence_new": high_confidence_new,
            "summary": summary,
        }

    def is_significant(self, diff: dict) -> bool:
        """Return True if the diff contains anything worth alerting on."""
        return bool(
            diff.get("added")
            or diff.get("new_wallets")
            or diff.get("high_confidence_new")
        )
