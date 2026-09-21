from __future__ import annotations

import socket

import requests

from .base import Scanner
from ..models import Evidence, Finding


class DNSScanner(Scanner):
    name = "dns"
    supported_types = {"domain", "url"}

    def scan(
        self,
        identifier,
        investigation_id,
        actor_id=None,
        run_id=None,
    ):
        host = (
            identifier.value
            .split("://", 1)[-1]
            .split("/", 1)[0]
            .split("?", 1)[0]
            .split("#", 1)[0]
        )

        if not host:
            return []

        results = []

        results.extend(
            self._resolve(
                host,
                investigation_id,
                actor_id,
                run_id,
            )
        )

        results.extend(
            self._whois(
                host,
                investigation_id,
                actor_id,
                run_id,
            )
        )

        results.extend(
            self._crtsh(
                host,
                investigation_id,
                actor_id,
                run_id,
            )
        )

        results.extend(
            self._wayback(
                host,
                investigation_id,
                actor_id,
                run_id,
            )
        )

        return results

    def _resolve(
        self,
        host,
        investigation_id,
        actor_id,
        run_id,
    ):
        try:
            addresses = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(
                        host,
                        None,
                    )
                }
            )
        except Exception:
            return []

        results = []

        for ip in addresses:
            results.append(
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type="ip",
                    value=ip,
                    source="dns_resolve",
                    source_url=f"dns://{host}",
                    confidence=0.90,
                    evidence=[
                        Evidence(
                            source="dns",
                            source_url=f"dns://{host}",
                            title=(
                                f"A record: "
                                f"{host} → {ip}"
                            ),
                        )
                    ],
                    metadata={
                        "resolved_from": host,
                        "record_type": "A",
                    },
                )
            )

        return results

    def _whois(
        self,
        host,
        investigation_id,
        actor_id,
        run_id,
    ):
        try:
            import whois

            data = whois.whois(host)

            registrar = str(
                data.registrar or ""
            )

            creation_date = str(
                data.creation_date or ""
            )

            expiration_date = str(
                data.expiration_date or ""
            )

            updated_date = str(
                data.updated_date or ""
            )

            country = str(
                data.country or ""
            )

            name_servers = [
                str(value)
                for value in (
                    data.name_servers or []
                )
            ][:10]

            return [
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type="domain",
                    value=host,
                    source="whois",
                    source_url=f"whois://{host}",
                    confidence=0.85,
                    evidence=[
                        Evidence(
                            source="whois",
                            source_url=f"whois://{host}",
                            title=f"WHOIS: {host}",
                            excerpt=(
                                f"Registrar: {registrar} | "
                                f"Created: {creation_date} | "
                                f"Country: {country}"
                            ),
                        )
                    ],
                    metadata={
                        "registrar": registrar,
                        "created": creation_date,
                        "expires": expiration_date,
                        "updated": updated_date,
                        "country": country,
                        "name_servers": name_servers,
                    },
                )
            ]

        except Exception:
            return []

    def _crtsh(
        self,
        host,
        investigation_id,
        actor_id,
        run_id,
    ):
        try:
            response = requests.get(
                "https://crt.sh/",
                params={
                    "q": f"%.{host}",
                    "output": "json",
                },
                timeout=15,
            )

            if response.status_code != 200:
                return []

            certificates = response.json()
        except Exception:
            return []

        results = []
        seen = set()

        for certificate in certificates:
            names = str(
                certificate.get(
                    "name_value",
                    "",
                )
            ).splitlines()

            for name in names:
                name = (
                    name
                    .strip()
                    .lower()
                    .lstrip("*.")
                    .rstrip(".")
                )

                if not name:
                    continue

                if name in seen:
                    continue

                if not (
                    name == host
                    or name.endswith(
                        f".{host}"
                    )
                ):
                    continue

                seen.add(name)

                results.append(
                    Finding(
                        investigation_id=investigation_id,
                        actor_id=actor_id,
                        run_id=run_id,
                        finding_type="domain",
                        value=name,
                        source="crt.sh",
                        source_url=(
                            f"https://crt.sh/?q={name}"
                        ),
                        confidence=0.85,
                        evidence=[
                            Evidence(
                                source="crt.sh",
                                source_url=(
                                    f"https://crt.sh/?q={name}"
                                ),
                                title=(
                                    f"SSL certificate SAN: "
                                    f"{name}"
                                ),
                                excerpt=(
                                    f"Issuer: "
                                    f"{certificate.get('issuer_name', '')} | "
                                    f"Valid from: "
                                    f"{certificate.get('not_before', '')}"
                                ),
                            )
                        ],
                        metadata={
                            "cert_id": certificate.get(
                                "id",
                                "",
                            ),
                            "issuer": certificate.get(
                                "issuer_name",
                                "",
                            ),
                            "not_before": certificate.get(
                                "not_before",
                                "",
                            ),
                            "not_after": certificate.get(
                                "not_after",
                                "",
                            ),
                        },
                    )
                )

        return results

    def _wayback(
        self,
        host,
        investigation_id,
        actor_id,
        run_id,
    ):
        try:
            response = requests.get(
                "https://archive.org/wayback/available",
                params={
                    "url": host,
                },
                timeout=10,
            )

            if response.status_code != 200:
                return []

            snapshot = (
                response
                .json()
                .get(
                    "archived_snapshots",
                    {},
                )
                .get(
                    "closest",
                    {},
                )
            )

        except Exception:
            return []

        if not snapshot.get("available"):
            return []

        archived_url = snapshot.get(
            "url",
            "",
        )

        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="url",
                value=host,
                source="wayback_machine",
                source_url=archived_url,
                confidence=0.70,
                evidence=[
                    Evidence(
                        source="wayback_machine",
                        source_url=archived_url,
                        title=f"Archived: {host}",
                        excerpt=(
                            f"Timestamp: "
                            f"{snapshot.get('timestamp', '')} | "
                            f"Status: "
                            f"{snapshot.get('status', '')}"
                        ),
                    )
                ],
                metadata={
                    "archived_url": archived_url,
                    "timestamp": snapshot.get(
                        "timestamp",
                        "",
                    ),
                    "status": snapshot.get(
                        "status",
                        "",
                    ),
                },
            )
        ]
