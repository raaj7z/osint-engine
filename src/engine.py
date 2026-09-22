from __future__ import annotations

import argparse
import importlib
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .models import Finding, Identifier, InvestigationInput, InvestigationResult
from .normalizer import Normalizer
from .providers.base import Provider
from .scanners.base import Scanner
from .tracking import TrackingManager


_SCANNER_IMPORTS = [
    (".scanners.username", "UsernameScanner"),
    (".scanners.email", "EmailScanner"),
    (".scanners.dns", "DNSScanner"),
    (".scanners.crypto", "CryptoScanner"),
    (".scanners.pgp", "PGPScanner"),
    (".scanners.ip", "IpScanner"),
    (".scanners.url", "URLScanner"),
    (".scanners.darkweb", "DarkWebScanner"),
]

_PROVIDER_IMPORTS = [
    (".providers.virustotal", "VirusTotalProvider"),
    (".providers.shodan", "ShodanProvider"),
    (".providers.urlscan", "UrlscanProvider"),
    (".providers.abuseipdb", "AbuseIPDBProvider"),
    (".providers.censys", "CensysProvider"),
]

STATUS_RUNNING = "RUNNING"
STATUS_COMPLETED = "COMPLETED"
STATUS_NO_RESULTS = "NO_RESULTS"
STATUS_NOT_RUN = "NOT_RUN"
STATUS_MISSING_CONFIG = "MISSING_CONFIG"
STATUS_ERROR = "ERROR"
STATUS_TIMEOUT = "TIMEOUT"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _try_load(module_path: str, class_name: str):
    try:
        module = importlib.import_module(
            module_path,
            package=__package__,
        )
        return getattr(module, class_name)
    except Exception:
        return None


def _serialize(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, datetime):
        return value.isoformat()

    if is_dataclass(value):
        return {
            key: _serialize(item)
            for key, item in asdict(value).items()
        }

    if isinstance(value, dict):
        return {
            str(key): _serialize(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [_serialize(item) for item in value]

    model_dump = getattr(value, "model_dump", None)

    if callable(model_dump):
        try:
            return _serialize(model_dump())
        except Exception:
            pass

    model_dict = getattr(value, "dict", None)

    if callable(model_dict):
        try:
            return _serialize(model_dict())
        except Exception:
            pass

    if hasattr(value, "__dict__"):
        return {
            key: _serialize(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }

    return str(value)


def _component_name(component: Any) -> str:
    return str(
        getattr(component, "name", None)
        or component.__class__.__name__
    )


def _component_kind(component: Any) -> str:
    if isinstance(component, Scanner):
        return "scanner"

    if isinstance(component, Provider):
        return "provider"

    return "component"


def _result_status(
    findings: list[Finding],
    errors: list[str],
) -> str:
    if findings:
        return STATUS_COMPLETED

    if errors:
        return STATUS_ERROR

    return STATUS_NO_RESULTS


class OSINTEngine:
    def __init__(
        self,
        db: Any = None,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.normalizer = Normalizer()
        self.db = db
        self.event_sink = event_sink

        self.scanners: list[Scanner] = []
        self.providers: list[Provider] = []

        self.load_errors: list[str] = []
        self.execution_log: list[dict[str, Any]] = []

        self._previous_actor_findings: dict[
            str,
            list[Finding],
        ] = {}

        self.tracking = TrackingManager(
            db=db,
            scan_callback=self._scheduled_tracking_scan,
        )

        self._load_scanners()
        self._load_providers()

    def _emit(self, event: dict[str, Any]) -> None:
        event = {
            "created_at": _utc_now().isoformat(),
            **event,
        }

        self.execution_log.append(event)

        if self.event_sink is not None:
            try:
                self.event_sink(event)
            except Exception:
                pass

    def _load_scanners(self) -> None:
        for module_path, class_name in _SCANNER_IMPORTS:
            cls = _try_load(
                module_path,
                class_name,
            )

            if cls is None:
                message = (
                    f"scanner not loaded: "
                    f"{class_name} ({module_path})"
                )

                self.load_errors.append(message)

                self._emit(
                    {
                        "component": class_name,
                        "kind": "scanner",
                        "status": STATUS_NOT_RUN,
                        "reason": "component unavailable",
                        "message": message,
                    }
                )

                continue

            try:
                self.scanners.append(cls())

            except Exception as exc:
                message = (
                    f"scanner failed to instantiate: "
                    f"{class_name}: {exc}"
                )

                self.load_errors.append(message)

                self._emit(
                    {
                        "component": class_name,
                        "kind": "scanner",
                        "status": STATUS_ERROR,
                        "reason": str(exc),
                        "message": message,
                    }
                )

    def _load_providers(self) -> None:
        for module_path, class_name in _PROVIDER_IMPORTS:
            cls = _try_load(
                module_path,
                class_name,
            )

            if cls is None:
                message = (
                    f"provider not loaded: "
                    f"{class_name} ({module_path})"
                )

                self.load_errors.append(message)

                self._emit(
                    {
                        "component": class_name,
                        "kind": "provider",
                        "status": STATUS_NOT_RUN,
                        "reason": "component unavailable",
                        "message": message,
                    }
                )

                continue

            try:
                self.providers.append(cls())

            except Exception as exc:
                message = (
                    f"provider failed to instantiate: "
                    f"{class_name}: {exc}"
                )

                self.load_errors.append(message)

                self._emit(
                    {
                        "component": class_name,
                        "kind": "provider",
                        "status": STATUS_ERROR,
                        "reason": str(exc),
                        "message": message,
                    }
                )

    def component_status(self) -> list[dict[str, Any]]:
        components: list[dict[str, Any]] = []

        for component in [
            *self.scanners,
            *self.providers,
        ]:
            components.append(
                {
                    "name": _component_name(component),
                    "kind": _component_kind(component),
                    "status": "AVAILABLE",
                    "supported_types": sorted(
                        getattr(
                            component,
                            "supported_types",
                            set(),
                        )
                        or []
                    ),
                }
            )

        for error in self.load_errors:
            components.append(
                {
                    "name": error.split(":", 1)[0],
                    "kind": "component",
                    "status": STATUS_NOT_RUN,
                    "reason": error,
                }
            )

        return components

    def _supports(
        self,
        component: Any,
        identifier: Identifier,
    ) -> bool:
        try:
            return bool(
                component.supports(identifier)
            )

        except Exception as exc:
            message = (
                f"{_component_name(component)} "
                f"supports() failed: {exc}"
            )

            self.load_errors.append(message)

            return False

    def _check_configuration(
        self,
        component: Any,
    ) -> tuple[bool | None, str | None]:
        checker = getattr(
            component,
            "is_configured",
            None,
        )

        if not callable(checker):
            return True, None

        try:
            configured = bool(
                checker()
            )

            if configured:
                return True, None

            reason_method = getattr(
                component,
                "configuration_reason",
                None,
            )

            if callable(reason_method):
                try:
                    reason = reason_method()
                except Exception:
                    reason = None

                if reason:
                    return False, str(reason)

            return (
                False,
                "required configuration is not available",
            )

        except Exception as exc:
            return (
                None,
                f"configuration check failed: {exc}",
            )

    def _run_component(
        self,
        component: Any,
        identifier: Identifier,
        investigation: InvestigationInput,
    ) -> tuple[list[Finding], dict[str, Any]]:
        name = _component_name(component)
        kind = _component_kind(component)

        base_event = {
            "component": name,
            "kind": kind,
            "identifier_type": identifier.type,
            "identifier": identifier.value,
            "run_id": investigation.run_id,
            "investigation_id": investigation.investigation_id,
            "actor_id": investigation.actor_id,
        }

        if not self._supports(
            component,
            identifier,
        ):
            event = {
                **base_event,
                "status": STATUS_NOT_RUN,
                "reason": "identifier type not supported",
                "finding_count": 0,
            }

            self._emit(event)

            return [], event

        configured, configuration_reason = (
            self._check_configuration(component)
        )

        if configured is False:
            event = {
                **base_event,
                "status": STATUS_MISSING_CONFIG,
                "reason": configuration_reason,
                "finding_count": 0,
            }

            self._emit(event)

            return [], event

        if configured is None:
            event = {
                **base_event,
                "status": STATUS_ERROR,
                "reason": configuration_reason,
                "finding_count": 0,
            }

            self._emit(event)

            return [], event

        started_at = _utc_now()

        self._emit(
            {
                **base_event,
                "status": STATUS_RUNNING,
                "started_at": started_at.isoformat(),
            }
        )

        try:
            if kind == "scanner":
                raw_findings = component.scan(
                    identifier,
                    investigation.investigation_id,
                    investigation.actor_id,
                    investigation.run_id,
                )

            else:
                raw_findings = component.query(
                    identifier,
                    investigation.investigation_id,
                    investigation.actor_id,
                    investigation.run_id,
                )

            findings = list(
                raw_findings or []
            )

            completed_at = _utc_now()

            status = (
                STATUS_COMPLETED
                if findings
                else STATUS_NO_RESULTS
            )

            event = {
                **base_event,
                "status": status,
                "finding_count": len(findings),
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
            }

            self._emit(event)

            return findings, event

        except TimeoutError as exc:
            event = {
                **base_event,
                "status": STATUS_TIMEOUT,
                "reason": (
                    str(exc)
                    or "component timeout"
                ),
                "finding_count": 0,
                "started_at": started_at.isoformat(),
                "completed_at": _utc_now().isoformat(),
            }

            self._emit(event)

            return [], event

        except Exception as exc:
            event = {
                **base_event,
                "status": STATUS_ERROR,
                "reason": str(exc),
                "finding_count": 0,
                "started_at": started_at.isoformat(),
                "completed_at": _utc_now().isoformat(),
            }

            self._emit(event)

            return [], event

    def _normalize_findings(
        self,
        findings: list[Finding],
        investigation: InvestigationInput,
    ) -> list[Finding]:
        normalized: list[Finding] = []

        for finding in findings:
            try:
                if not finding.investigation_id:
                    finding.investigation_id = (
                        investigation.investigation_id
                    )

                if (
                    finding.actor_id is None
                    and investigation.actor_id is not None
                ):
                    finding.actor_id = (
                        investigation.actor_id
                    )

                if (
                    finding.run_id is None
                    and investigation.run_id is not None
                ):
                    finding.run_id = (
                        investigation.run_id
                    )

                normalized.append(finding)

            except Exception:
                normalized.append(finding)

        return normalized

    def run(
        self,
        investigation: InvestigationInput,
    ) -> InvestigationResult:
        started_at = _utc_now()

        self.execution_log = []

        errors: list[str] = []

        errors.extend(self.load_errors)

        investigation = (
            self.normalizer
            .normalize_investigation_input(
                investigation
            )
        )

        self._emit(
            {
                "event": "osint_started",
                "status": STATUS_RUNNING,
                "investigation_id": investigation.investigation_id,
                "actor_id": investigation.actor_id,
                "run_id": investigation.run_id,
                "identifier_count": len(
                    investigation.identifiers
                ),
            }
        )

        all_findings: list[Finding] = []

        for identifier in investigation.identifiers:
            for scanner in self.scanners:
                findings, event = self._run_component(
                    scanner,
                    identifier,
                    investigation,
                )

                all_findings.extend(findings)

                if event.get("status") in {
                    STATUS_ERROR,
                    STATUS_TIMEOUT,
                }:
                    errors.append(
                        f"{event['component']} failed on "
                        f"'{identifier.value}': "
                        f"{event.get('reason', 'unknown error')}"
                    )

            for provider in self.providers:
                findings, event = self._run_component(
                    provider,
                    identifier,
                    investigation,
                )

                all_findings.extend(findings)

                if event.get("status") in {
                    STATUS_ERROR,
                    STATUS_TIMEOUT,
                }:
                    errors.append(
                        f"{event['component']} failed on "
                        f"'{identifier.value}': "
                        f"{event.get('reason', 'unknown error')}"
                    )

        all_findings = self._normalize_findings(
            all_findings,
            investigation,
        )

        deduped = self._deduplicate_findings(
            all_findings
        )

        completed_at = _utc_now()

        runtime_errors = [
            error
            for error in errors
            if " failed on " in error
        ]

        if runtime_errors and not deduped:
            overall_status = STATUS_ERROR

        elif deduped:
            overall_status = STATUS_COMPLETED

        elif runtime_errors:
            overall_status = STATUS_ERROR

        else:
            overall_status = STATUS_NO_RESULTS

        result = InvestigationResult(
            investigation_id=investigation.investigation_id,
            actor_id=investigation.actor_id,
            session_id=investigation.session_id,
            run_id=investigation.run_id,
            findings=deduped,
            started_at=started_at,
            completed_at=completed_at,
            errors=errors,
        )

        tracking_result: dict[str, Any] | None = None

        if (
            self.tracking is not None
            and investigation.actor_id
        ):
            try:
                previous_findings = (
                    self._previous_actor_findings.get(
                        investigation.actor_id,
                        [],
                    )
                )

                tracking_result = self.tracking.process(
                    previous_findings=previous_findings,
                    current_findings=deduped,
                    actor_id=investigation.actor_id,
                    investigation_id=investigation.investigation_id,
                    run_id=investigation.run_id,
                )

                self._previous_actor_findings[
                    investigation.actor_id
                ] = list(deduped)

                self._emit(
                    {
                        "event": "tracking_updated",
                        "status": STATUS_COMPLETED,
                        "investigation_id": investigation.investigation_id,
                        "actor_id": investigation.actor_id,
                        "run_id": investigation.run_id,
                        "change_summary": tracking_result.get(
                            "summary"
                        ),
                        "alert_ids": tracking_result.get(
                            "alert_ids",
                            [],
                        ),
                    }
                )

            except Exception as exc:
                tracking_result = {
                    "status": STATUS_ERROR,
                    "reason": str(exc),
                }

                self._emit(
                    {
                        "event": "tracking_updated",
                        "status": STATUS_ERROR,
                        "investigation_id": investigation.investigation_id,
                        "actor_id": investigation.actor_id,
                        "run_id": investigation.run_id,
                        "reason": str(exc),
                    }
                )

        result.execution_log = list(
            self.execution_log
        )

        result.component_registry = {
            "scanners": len(self.scanners),
            "providers": len(self.providers),
            "components": self.component_status(),
        }

        result.metadata = {
            **(
                getattr(
                    result,
                    "metadata",
                    {},
                )
                or {}
            ),
            "run_id": investigation.run_id,
            "tracking": tracking_result,
        }

        self._emit(
            {
                "event": "osint_completed",
                "status": overall_status,
                "investigation_id": (
                    investigation.investigation_id
                ),
                "actor_id": investigation.actor_id,
                "run_id": investigation.run_id,
                "finding_count": len(deduped),
                "error_count": len(errors),
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
            }
        )

        if self.db is not None:
            try:
                self.db.save_investigation(
                    result
                )

            except Exception as exc:
                result.errors.append(
                    f"database persistence failed: {exc}"
                )

        return result

    def run_dict(
        self,
        investigation: InvestigationInput,
    ) -> dict[str, Any]:
        result = self.run(
            investigation
        )

        payload = _serialize(result)

        if not isinstance(payload, dict):
            payload = {
                "result": payload
            }

        execution_status = STATUS_COMPLETED

        if not result.findings:
            execution_status = (
                STATUS_ERROR
                if result.errors
                else STATUS_NO_RESULTS
            )

        payload["status"] = execution_status
        payload["execution_log"] = list(
            self.execution_log
        )
        payload["component_registry"] = (
            self.component_status()
        )
        payload["tracking"] = (
            getattr(
                result,
                "metadata",
                {},
            )
            or {}
        ).get("tracking")

        return payload

    def _deduplicate_findings(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        best: dict[
            tuple[str, str, str],
            Finding,
        ] = {}

        for finding in findings:
            finding_type = str(
                finding.finding_type
            ).lower()

            value = str(
                finding.value
            ).strip()

            source = str(
                finding.source
            ).lower()

            if not value:
                continue

            key = (
                finding_type,
                value.lower(),
                source,
            )

            if key not in best:
                best[key] = finding
                continue

            existing = best[key]

            if (
                finding.confidence
                > existing.confidence
            ):
                winner = finding
                loser = existing
            else:
                winner = existing
                loser = finding

            existing_evidence = list(
                winner.evidence
            )

            for evidence in loser.evidence:
                if evidence not in existing_evidence:
                    existing_evidence.append(
                        evidence
                    )

            winner.evidence = existing_evidence

            merged_metadata = dict(
                loser.metadata
            )

            merged_metadata.update(
                winner.metadata
            )

            winner.metadata = merged_metadata

            best[key] = winner

        return list(
            best.values()
        )

    def _scheduled_tracking_scan(
        self,
        watch_entry: dict[str, Any],
    ) -> dict[str, Any]:
        actor_id = watch_entry.get("actor_id")

        if not actor_id:
            raise ValueError(
                "watchlist entry has no actor_id"
            )

        raw_identifiers = (
            watch_entry.get("identifiers")
            or []
        )

        if (
            not raw_identifiers
            and self.db is not None
        ):
            for method_name in (
                "list_actor_identifiers",
                "get_actor_identifiers",
                "list_identifiers_for_actor",
            ):
                method = getattr(
                    self.db,
                    method_name,
                    None,
                )

                if not callable(method):
                    continue

                try:
                    raw_identifiers = method(
                        actor_id
                    )
                except Exception:
                    raw_identifiers = []

                if raw_identifiers:
                    break

        if not raw_identifiers:
            raise ValueError(
                f"no identifiers available for "
                f"tracked actor {actor_id}"
            )

        identifiers: list[Identifier] = []

        for item in raw_identifiers:
            if isinstance(
                item,
                Identifier,
            ):
                identifiers.append(item)
                continue

            if isinstance(
                item,
                str,
            ):
                identifiers.append(
                    Identifier(
                        type="username",
                        value=item,
                        source="watchlist",
                    )
                )
                continue

            if isinstance(
                item,
                dict,
            ):
                identifiers.append(
                    Identifier(
                        **item
                    )
                )

        if not identifiers:
            raise ValueError(
                f"no valid identifiers available "
                f"for tracked actor {actor_id}"
            )

        investigation_id = (
            watch_entry.get(
                "investigation_id"
            )
            or f"MON-{actor_id}-"
            f"{int(_utc_now().timestamp())}"
        )

        investigation = InvestigationInput(
            investigation_id=investigation_id,
            actor_id=actor_id,
            identifiers=identifiers,
            metadata={
                "source": "watchlist",
                "scheduled": True,
                "watch_id": watch_entry.get(
                    "watch_id"
                ),
            },
        )

        result = self.run(
            investigation
        )

        return _serialize(result)

    def add_to_watchlist(
        self,
        actor_id: str,
        interval_minutes: int = 360,
    ) -> str:
        return self.tracking.add_actor(
            actor_id=actor_id,
            interval_minutes=interval_minutes,
        )

    def remove_from_watchlist(
        self,
        watch_id: str,
    ) -> None:
        self.tracking.remove_actor(
            watch_id
        )

    def pause_watch(
        self,
        watch_id: str,
    ) -> None:
        self.tracking.pause_actor(
            watch_id
        )

    def resume_watch(
        self,
        watch_id: str,
    ) -> None:
        self.tracking.resume_actor(
            watch_id
        )

    def start_tracking(self) -> bool:
        return self.tracking.start()

    def stop_tracking(self) -> bool:
        return self.tracking.stop()

    def tracking_status(
        self,
    ) -> dict[str, Any]:
        return self.tracking.status()

    @staticmethod
    def _build_cli_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description=(
                "PRALAYX OSINT Engine — "
                "run a single investigation"
            )
        )

        parser.add_argument(
            "--username"
        )

        parser.add_argument(
            "--domain"
        )

        parser.add_argument(
            "--email"
        )

        parser.add_argument(
            "--ip"
        )

        parser.add_argument(
            "--url"
        )

        parser.add_argument(
            "--crypto"
        )

        parser.add_argument(
            "--pgp"
        )

        parser.add_argument(
            "--actor-id",
            dest="actor_id",
        )

        return parser

    @staticmethod
    def _main() -> None:
        parser = OSINTEngine._build_cli_parser()

        args = parser.parse_args()

        identifiers: list[Identifier] = []

        for value, identifier_type in [
            (args.username, "username"),
            (args.domain, "domain"),
            (args.email, "email"),
            (args.ip, "ip"),
            (args.url, "url"),
            (args.crypto, "crypto"),
            (args.pgp, "pgp"),
        ]:
            if value:
                identifiers.append(
                    Identifier(
                        type=identifier_type,
                        value=value,
                    )
                )

        if not identifiers:
            print(
                "No identifiers provided. "
                "Use --username, --domain, --email, "
                "--ip, --url, --crypto, or --pgp."
            )

            sys.exit(1)

        label = (
            args.actor_id
            or identifiers[0].value
        )

        investigation_id = (
            f"CLI-{label}-"
            f"{int(_utc_now().timestamp())}"
        )

        investigation = InvestigationInput(
            investigation_id=investigation_id,
            actor_id=args.actor_id,
            identifiers=identifiers,
        )

        def terminal_event(
            event: dict[str, Any],
        ) -> None:
            component = event.get(
                "component",
                event.get(
                    "event",
                    "OSINT",
                ),
            )

            status = event.get(
                "status",
                "",
            )

            reason = event.get(
                "reason"
            )

            count = event.get(
                "finding_count"
            )

            message = (
                f"[{component}] {status}"
            )

            if count is not None:
                message += (
                    f" — {count} findings"
                )

            if reason:
                message += (
                    f" | {reason}"
                )

            print(message)

        engine = OSINTEngine(
            event_sink=terminal_event
        )

        if engine.load_errors:
            print(
                "\nComponent load warnings:"
            )

            for error in engine.load_errors:
                print(
                    f"  - {error}"
                )

            print()

        result = engine.run(
            investigation
        )

        print(
            f"\n{len(result.findings)} findings "
            f"for {result.investigation_id}\n"
        )

        for finding in result.findings:
            print(
                f"[{finding.finding_type}] "
                f"{finding.value} "
                f"(source={finding.source}, "
                f"confidence={finding.confidence:.2f})"
            )

        if result.errors:
            print(
                "\nRuntime errors/warnings:"
            )

            for error in result.errors:
                print(
                    f"  - {error}"
                )


if __name__ == "__main__":
    OSINTEngine._main()
