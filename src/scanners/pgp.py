# pgp.py — PGP key lookup on keyservers


import requests, re
from .base import Scanner
from ..models import Finding, Evidence

class PGPScanner(Scanner):
    name = "pgp"
    supported_types = {"pgp"}

    KEYSERVERS = [
        "https://keys.openpgp.org/vks/v1/by-fingerprint/",
        "https://keyserver.ubuntu.com/pks/lookup?op=get&search=",
        "https://pgp.mit.edu/pks/lookup?op=get&search=",
    ]

    def scan(self, identifier, investigation_id, actor_id):
        fingerprint = identifier.value.strip().upper().replace(" ", "")
        results = []
        results += self._lookup_openpgp(fingerprint, investigation_id, actor_id)
        results += self._lookup_mit(fingerprint, investigation_id, actor_id)
        return results

    def _lookup_openpgp(self, fp, iid, aid):
        out = []
        try:
            r = requests.get(
                f"https://keys.openpgp.org/vks/v1/by-fingerprint/{fp}",
                timeout=10
            )
            if r.status_code == 200:
                key_data = r.text
                # Extract email from key
                emails = re.findall(r'<([^>]+@[^>]+)>', key_data)
                uid = re.findall(r'uid\s+(.+)', key_data)
                out.append(Finding(
                    investigation_id=iid, actor_id=aid,
                    finding_type="pgp", value=fp,
                    source="keys.openpgp.org",
                    source_url=f"https://keys.openpgp.org/vks/v1/by-fingerprint/{fp}",
                    confidence=0.95,
                    evidence=[Evidence(
                        source="keys.openpgp.org",
                        title=f"PGP key found: {fp[:16]}...",
                        excerpt=f"UIDs: {uid[:2]} | Emails: {emails[:2]}"
                    )],
                    metadata={
                        "fingerprint": fp,
                        "emails_in_key": emails[:5],
                        "uids": uid[:5],
                        "key_data": key_data[:500]
                    }
                ))
        except Exception:
            pass
        return out

    def _lookup_mit(self, fp, iid, aid):
        out = []
        try:
            r = requests.get(
                f"https://pgp.mit.edu/pks/lookup?op=get&search=0x{fp}",
                timeout=10
            )
            if r.status_code == 200 and "BEGIN PGP" in r.text:
                emails = re.findall(r'<([^>]+@[^>]+)>', r.text)
                out.append(Finding(
                    investigation_id=iid, actor_id=aid,
                    finding_type="pgp", value=fp,
                    source="pgp.mit.edu",
                    source_url=f"https://pgp.mit.edu/pks/lookup?op=vindex&search=0x{fp}",
                    confidence=0.90,
                    metadata={"fingerprint": fp, "emails_in_key": emails[:5]}
                ))
        except Exception:
            pass
        return out

