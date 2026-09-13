# dns.py — DNS, WHOIS, crt.sh scanner (all free, no key)

import socket, requests, json
from .base import Scanner
from ..models import Finding, Evidence

class DNSScanner(Scanner):
    name = "dns"
    supported_types = {"domain", "url"}

    def scan(self, identifier, investigation_id, actor_id):
        host = identifier.value.split("://", 1)[-1].split("/", 1)[0]
        results = []
        results += self._resolve(host, investigation_id, actor_id)
        results += self._whois(host, investigation_id, actor_id)
        results += self._crtsh(host, investigation_id, actor_id)
        results += self._wayback(host, investigation_id, actor_id)
        return results

    def _resolve(self, host, iid, aid):
        out = []
        try:
            ips = sorted({x[4][0] for x in socket.getaddrinfo(host, None)})
            for ip in ips:
                out.append(Finding(
                    investigation_id=iid, actor_id=aid,
                    finding_type="ip", value=ip,
                    source="dns_resolve", confidence=0.9,
                    evidence=[Evidence(source="dns", title=f"A record: {host} → {ip}")],
                    metadata={"resolved_from": host, "record_type": "A"}
                ))
        except Exception:
            pass
        return out

    def _whois(self, host, iid, aid):
        out = []
        try:
            import whois
            w = whois.whois(host)
            out.append(Finding(
                investigation_id=iid, actor_id=aid,
                finding_type="domain", value=host,
                source="whois", confidence=0.85,
                evidence=[Evidence(
                    source="whois",
                    title=f"WHOIS: {host}",
                    excerpt=f"Registrar: {w.registrar} | Created: {w.creation_date} | Country: {w.country}"
                )],
                metadata={
                    "registrar": str(w.registrar or ""),
                    "created": str(w.creation_date or ""),
                    "expires": str(w.expiration_date or ""),
                    "updated": str(w.updated_date or ""),
                    "country": str(w.country or ""),
                    "name_servers": [str(ns) for ns in (w.name_servers or [])][:5]
                }
            ))
        except Exception:
            pass
        return out

    def _crtsh(self, host, iid, aid):
        """crt.sh — Certificate Transparency, completely free
        Reveals subdomains and alternative names from SSL certs
        CRITICAL for dark web: reveals clearnet domains linked to onion SSL certs"""
        out = []
        try:
            r = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{host}", "output": "json"},
                timeout=15
            )
            if r.status_code == 200:
                seen = set()
                for cert in r.json():
                    name = cert.get("name_value", "").strip()
                    for san in name.split("\n"):
                        san = san.strip().lstrip("*.")
                        if san and san not in seen and host in san:
                            seen.add(san)
                            out.append(Finding(
                                investigation_id=iid, actor_id=aid,
                                finding_type="domain", value=san,
                                source="crt.sh", confidence=0.85,
                                source_url=f"https://crt.sh/?q={san}",
                                evidence=[Evidence(
                                    source="crt.sh",
                                    title=f"SSL cert SAN: {san}",
                                    excerpt=f"Issuer: {cert.get('issuer_name','')} | Date: {cert.get('not_before','')}"
                                )],
                                metadata={
                                    "cert_id": cert.get("id", ""),
                                    "issuer": cert.get("issuer_name", ""),
                                    "not_before": cert.get("not_before", ""),
                                    "not_after": cert.get("not_after", "")
                                }
                            ))
        except Exception:
            pass
        return out

    def _wayback(self, host, iid, aid):
        """Wayback Machine — historical presence check"""
        out = []
        try:
            r = requests.get(
                "https://archive.org/wayback/available",
                params={"url": host}, timeout=10
            )
            if r.status_code == 200:
                snap = r.json().get("archived_snapshots", {}).get("closest", {})
                if snap.get("available"):
                    out.append(Finding(
                        investigation_id=iid, actor_id=aid,
                        finding_type="url", value=host,
                        source="wayback_machine",
                        source_url=snap.get("url", ""),
                        confidence=0.70,
                        evidence=[Evidence(
                            source="wayback_machine",
                            title=f"Archived: {host}",
                            excerpt=f"Timestamp: {snap.get('timestamp','')} | Status: {snap.get('status','')}"
                        )],
                        metadata={
                            "archived_url": snap.get("url", ""),
                            "timestamp": snap.get("timestamp", ""),
                            "status": snap.get("status", "")
                        }
                    ))
        except Exception:
            pass
        return out
