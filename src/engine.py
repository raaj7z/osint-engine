

import argparse
import importlib
import sys
from datetime import datetime, timezone

from .models import Finding, Identifier, InvestigationInput, InvestigationResult
from .normalizer import Normalizer
from .providers.base import Provider
from .scanners.base import Scanner

# (dotted module path relative to this package, expected class name)
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


def _try_load(module_path: str, class_name: str):
    """Import a class by dotted module path (relative to this package); return None on any failure."""
    try:
        module = importlib.import_module(module_path, package=__package__)
        return getattr(module, class_name)
    except Exception:
        return None


class OSINTEngine:
    """Master controller that runs all available scanners/providers against an investigation."""

    def __init__(self, db=None):
        """Load all available scanners/providers and wire up an optional database.

        db, if provided, should be an OSINTDatabase-like object exposing
        save_investigation(). It's stored as self.db so other components
        (scheduler, main.py CLI) can reach it via getattr(engine, "db", None).
        """
        self.normalizer = Normalizer()
        self.db = db
        self.scanners: list[Scanner] = []
        self.providers: list[Provider] = []
        self.load_errors: list[str] = []

        self._load_scanners()
        self._load_providers()

    def _load_scanners(self) -> None:
        """Instantiate every scanner class that imports successfully; record failures."""
        for module_path, class_name in _SCANNER_IMPORTS:
            cls = _try_load(module_path, class_name)
            if cls is None:
                self.load_errors.append(f"scanner not loaded: {class_name} ({module_path})")
                continue
            try:
                self.scanners.append(cls())
            except Exception as e:
                self.load_errors.append(f"scanner failed to instantiate: {class_name}: {e}")

    def _load_providers(self) -> None:
        """Instantiate every provider class that imports successfully; record failures."""
        for module_path, class_name in _PROVIDER_IMPORTS:
            cls = _try_load(module_path, class_name)
            if cls is None:
                self.load_errors.append(f"provider not loaded: {class_name} ({module_path})")
                continue
            try:
                self.providers.append(cls())
            except Exception as e:
                self.load_errors.append(f"provider failed to instantiate: {class_name}: {e}")

    def run(self, investigation: InvestigationInput) -> InvestigationResult:
        """Run every applicable scanner and provider against each identifier in the investigation.

        Normalizes/deduplicates identifiers first, isolates each
        scanner/provider call in its own try/except, deduplicates the
        resulting findings, and persists the result if a db was provided.
        """
        started_at = datetime.now(timezone.utc)
        errors: list[str] = list(self.load_errors)

        investigation = self.normalizer.normalize_investigation_input(investigation)

        all_findings: list[Finding] = []

        for identifier in investigation.identifiers:
            for scanner in self.scanners:
                if not scanner.supports(identifier):
                    continue
                try:
                    findings = scanner.scan(
                        identifier, investigation.investigation_id, investigation.actor_id
                    )
                    all_findings.extend(findings)
                except Exception as e:
                    errors.append(
                        f"{scanner.__class__.__name__} failed on '{identifier.value}': {e}"
                    )

            for provider in self.providers:
                if not provider.supports(identifier):
                    continue
                try:
                    findings = provider.query(
                        identifier, investigation.investigation_id, investigation.actor_id
                    )
                    all_findings.extend(findings)
                except Exception as e:
                    errors.append(
                        f"{provider.__class__.__name__} failed on '{identifier.value}': {e}"
                    )

        deduped = self._deduplicate_findings(all_findings)

        result = InvestigationResult(
            investigation_id=investigation.investigation_id,
            actor_id=investigation.actor_id,
            findings=deduped,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            errors=errors,
        )

        if self.db:
            try:
                self.db.save_investigation(result)
            except Exception:
                pass

        return result

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Collapse duplicate findings (same type/value/source), keeping the highest-confidence one."""
        best: dict[tuple[str, str, str], Finding] = {}

        for finding in findings:
            key = (finding.finding_type, finding.value.lower(), finding.source)
            if key not in best or finding.confidence > best[key].confidence:
                best[key] = finding

        return list(best.values())


def _build_cli_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for `python -m src.engine ...` quick single-run testing."""
    parser = argparse.ArgumentParser(description="OSINT Engine — run a single investigation")
    parser.add_argument("--username")
    parser.add_argument("--domain")
    parser.add_argument("--email")
    parser.add_argument("--ip")
    parser.add_argument("--url")
    parser.add_argument("--crypto")
    parser.add_argument("--pgp")
    parser.add_argument("--actor-id", dest="actor_id")
    return parser


def _main() -> None:
    """Entrypoint for `python -m src.engine --username testuser` style ad-hoc test runs."""
    parser = _build_cli_parser()
    args = parser.parse_args()

    identifiers: list[Identifier] = []
    for value, id_type in [
        (args.username, "username"),
        (args.domain, "domain"),
        (args.email, "email"),
        (args.ip, "ip"),
        (args.url, "url"),
        (args.crypto, "crypto"),
        (args.pgp, "pgp"),
    ]:
        if value:
            identifiers.append(Identifier(type=id_type, value=value))

    if not identifiers:
        print("No identifiers provided. Use --username, --domain, --email, --ip, --url, --crypto, or --pgp.")
        sys.exit(1)

    label = args.actor_id or identifiers[0].value
    investigation_id = f"CLI-{label}-{int(datetime.now(timezone.utc).timestamp())}"

    investigation = InvestigationInput(
        investigation_id=investigation_id,
        actor_id=args.actor_id,
        identifiers=identifiers,
    )

    engine = OSINTEngine()

    if engine.load_errors:
        print("Load warnings (component skipped, engine still runs):")
        for err in engine.load_errors:
            print(f"  - {err}")
        print()

    result = engine.run(investigation)

    print(f"\n{len(result.findings)} findings for {result.investigation_id}\n")
    for finding in result.findings:
        print(
            f"[{finding.finding_type}] {finding.value} "
            f"(source={finding.source}, confidence={finding.confidence:.2f})"
        )

    if result.errors:
        print("\nRuntime errors/warnings:")
        for err in result.errors:
            print(f"  - {err}")


if __name__ == "__main__":
    _main()
