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


# ---------------------------------------------------------------------------
# Component registry
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Truthful execution states used by PRALAYX terminal/UI
# ---------------------------------------------------------------------------

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
    """
    Import a component dynamically.

    A missing optional scanner/provider must not stop the complete OSINT
    engine from starting.
    """
    try:
        module = importlib.import_module(
            module_path,
            package=__package__,
        )
        return getattr(module, class_name)

    except Exception:
        return None


def _serialize(value: Any) -> Any:
    """
    Convert Pydantic/dataclass/native objects into JSON-friendly structures.

    This is intentionally lightweight so the engine does not depend on
    a particular report serializer.
    """
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

    # Pydantic v2
    model_dump = getattr(value, "model_dump", None)

    if callable(model_dump):
        try:
            return _serialize(model_dump())
        except Exception:
            pass

    # Pydantic v1 compatibility
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


# ---------------------------------------------------------------------------
# OSINT Engine
# ---------------------------------------------------------------------------

class OSINTEngine:
    """
    Master controller for PRALAYX OSINT execution.

    Responsibilities:

    - normalize investigation input
    - load available scanners/providers
    - execute applicable components
    - expose truthful component execution status
    - isolate provider/scanner failures
    - emit terminal/event information
    - deduplicate findings
    - preserve investigation/run context
    - optionally persist the final result through a DB adapter
    """

    def __init__(
        self,
        db: Any = None,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.normalizer = Normalizer()

        # Optional database adapter.
        #
        # PRALAYX platform owns the main investigation DB. The OSINT engine
        # therefore does not assume a particular DB implementation.
        self.db = db

        # Optional callback used by platform/engine_runner.py to stream
        # execution events into the PRALAYX terminal.
        self.event_sink = event_sink

        self.scanners: list[Scanner] = []
        self.providers: list[Provider] = []

        self.load_errors: list[str] = []

        # Complete execution event history for this engine instance.
        self.execution_log: list[dict[str, Any]] = []

        self._load_scanners()
        self._load_providers()

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def _emit(self, event: dict[str, Any]) -> None:
        """
        Store an execution event and optionally forward it to PRALAYX.

        The callback must never be allowed to break the actual OSINT run.
        """
        event = {
            "created_at": _utc_now().isoformat(),
            **event,
        }

        self.execution_log.append(event)

        if self.event_sink is not None:
            try:
                self.event_sink(event)
            except Exception:
                # Event delivery failure must never stop OSINT.
                pass

    # ------------------------------------------------------------------
    # Component loading
    # ------------------------------------------------------------------

    def _load_scanners(self) -> None:
        """
        Load all scanner classes that are available.

        A missing optional scanner is recorded instead of crashing the
        complete engine.
        """
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
        """
        Load all external providers that are available.

        Provider configuration is checked at execution time when the provider
        exposes an is_configured() method.
        """
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

    # ------------------------------------------------------------------
    # Component registry
    # ------------------------------------------------------------------

    def component_status(self) -> list[dict[str, Any]]:
        """
        Return a machine-readable registry of loaded components.

        Used by PRALAYX to populate the OSINT status/terminal UI.
        """
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

    # ------------------------------------------------------------------
    # Identifier support
    # ------------------------------------------------------------------

    def _supports(
        self,
        component: Any,
        identifier: Identifier,
    ) -> bool:
        """
        Safely check whether a component supports an identifier.

        A broken supports() implementation is treated as a component error,
        not as an investigation-wide failure.
        """
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

    # ------------------------------------------------------------------
    # Configuration detection
    # ------------------------------------------------------------------

    def _check_configuration(
        self,
        component: Any,
    ) -> tuple[bool | None, str | None]:
        """
        Check provider/scanner configuration when the component exposes
        is_configured().

        Returns:
            (True, None)   -> configured
            (False, reason) -> missing configuration
            (None, reason) -> configuration check itself failed

        Components without is_configured() are treated as configured.
        """
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

            return (
                False,
                "required configuration is not available",
            )

        except Exception as exc:
            return (
                None,
                f"configuration check failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Component execution
    # ------------------------------------------------------------------

    def _run_component(
        self,
        component: Any,
        identifier: Identifier,
        investigation: InvestigationInput,
    ) -> tuple[list[Finding], dict[str, Any]]:
        """
        Execute exactly one scanner/provider.

        This method is deliberately isolated so a provider failure cannot
        terminate the entire investigation.
        """
        name = _component_name(component)
        kind = _component_kind(component)

        base_event = {
            "component": name,
            "kind": kind,
            "identifier_type": identifier.type,
            "identifier": identifier.value,
        }

        # Unsupported identifier type.
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

        # Configuration check.
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

        # Start event.
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
                )

            else:
                raw_findings = component.query(
                    identifier,
                    investigation.investigation_id,
                    investigation.actor_id,
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

    # ------------------------------------------------------------------
    # Finding normalization
    # ------------------------------------------------------------------

    def _normalize_findings(
        self,
        findings: list[Finding],
        investigation: InvestigationInput,
    ) -> list[Finding]:
        """
        Ensure findings returned by individual components carry the current
        investigation/actor context.

        Existing source/evidence/metadata are preserved.
        """
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

                normalized.append(finding)

            except Exception:
                # Do not lose a valid finding merely because its model is
                # unexpectedly immutable/custom.
                normalized.append(finding)

        return normalized

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def run(
        self,
        investigation: InvestigationInput,
    ) -> InvestigationResult:
        """
        Execute a complete OSINT investigation.

        Flow:

            input
              ↓
            normalization
              ↓
            scanners/providers
              ↓
            truthful execution events
              ↓
            finding normalization
              ↓
            deduplication
              ↓
            InvestigationResult
        """
        started_at = _utc_now()

        # Reset execution history for this run.
        self.execution_log = []

        errors: list[str] = []

        # Load errors are warnings/errors associated with unavailable
        # components. They do not prevent available components from running.
        errors.extend(self.load_errors)

        # Normalize the incoming investigation before dispatch.
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
                "identifier_count": len(
                    investigation.identifiers
                ),
            }
        )

        all_findings: list[Finding] = []

        # --------------------------------------------------------------
        # Run all identifiers
        # --------------------------------------------------------------

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

        # --------------------------------------------------------------
        # Normalize and deduplicate
        # --------------------------------------------------------------

        all_findings = self._normalize_findings(
            all_findings,
            investigation,
        )

        deduped = self._deduplicate_findings(
            all_findings
        )

        completed_at = _utc_now()

        # --------------------------------------------------------------
        # Determine overall status
        # --------------------------------------------------------------

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

        # --------------------------------------------------------------
        # Build result using the existing Pydantic model
        # --------------------------------------------------------------

        result = InvestigationResult(
            investigation_id=investigation.investigation_id,
            actor_id=investigation.actor_id,
            findings=deduped,
            started_at=started_at,
            completed_at=completed_at,
            errors=errors,
        )

        # --------------------------------------------------------------
        # Final event
        # --------------------------------------------------------------

        self._emit(
            {
                "event": "osint_completed",
                "status": overall_status,
                "investigation_id": (
                    investigation.investigation_id
                ),
                "actor_id": investigation.actor_id,
                "finding_count": len(deduped),
                "error_count": len(errors),
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
            }
        )

        # --------------------------------------------------------------
        # Optional DB persistence
        # --------------------------------------------------------------

        if self.db is not None:
            try:
                self.db.save_investigation(
                    result
                )

            except Exception as exc:
                # Database failure must be visible instead of silently
                # pretending persistence succeeded.
                result.errors.append(
                    f"database persistence failed: {exc}"
                )

        return result

    # ------------------------------------------------------------------
    # Dictionary/JSON-friendly execution
    # ------------------------------------------------------------------

    def run_dict(
        self,
        investigation: InvestigationInput,
    ) -> dict[str, Any]:
        """
        Run an investigation and return a JSON-friendly structure.

        This is the preferred entry point for platform/engine_runner.py when
        it needs to send OSINT output to the PRALAYX API.
        """
        result = self.run(
            investigation
        )

        payload = _serialize(result)

        if not isinstance(payload, dict):
            payload = {
                "result": payload
            }

        # These fields are intentionally outside InvestigationResult because
        # the existing model should remain backwards compatible.
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

        return payload

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _deduplicate_findings(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        """
        Deduplicate findings using:

            finding_type + value + source

        If multiple records represent the same finding, keep the one with
        the highest confidence and merge useful evidence/metadata where
        possible.
        """
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

            # Keep highest-confidence finding.
            if (
                finding.confidence
                > existing.confidence
            ):
                winner = finding
                loser = existing
            else:
                winner = existing
                loser = finding

            # Merge evidence from the other copy.
            existing_evidence = list(
                winner.evidence
            )

            for evidence in loser.evidence:
                if evidence not in existing_evidence:
                    existing_evidence.append(
                        evidence
                    )

            winner.evidence = existing_evidence

            # Merge metadata without overwriting the stronger/current
            # finding's existing values.
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

    # ------------------------------------------------------------------
    # CLI
    # ------------------------------------------------------------------

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

        def terminal_event(event: dict[str, Any]) -> None:
            component = event.get(
                "component",
                event.get("event", "OSINT"),
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
