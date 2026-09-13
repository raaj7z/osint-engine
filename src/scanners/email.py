# email.py — Email scanner using Holehe + XposedOrNot + Hunter
# SIH26151 | Team Vajra | IIT Patna

import subprocess, requests, os, json
from .base import Scanner
from ..models import Finding, Evidence

class EmailScanner(Scanner):
    name = "email"
    supported_types = {"email"}

    def scan(self, identifier, investigation_id, actor_id):
        results = []
        email = identifier.value

        results += self._holehe(email, investigation_id, actor_id)
        results += self._xposedornot(email, investigation_id, actor_id)
        results += self._hunter(email, investigation_id, actor_id)

        return results

    def _holehe(self, email, iid, aid):
        """Holehe — checks if email is registered on 120+ sites"""
        out = []
        try:
            proc = subprocess.run(
                ["holehe", email, "--only-used"],
                capture_output=True, text=True, timeout=120
            )
            for line in proc.stdout.splitlines():
                if "[+]" in line:
                    platform = line.split("[+]")[-1].strip()
                    out.append(Finding(
                        investigation_id=iid, actor_id=aid,
                        finding_type="email", value=email,
                        source="holehe", confidence=0.80,
                        evidence=[Evidence(source="holehe",
                                           title=f"Email registered on {platform}")],
                        metadata={"platform": platform, "type": "account_found"}
                    ))
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            pass
        return out

    def _xposedornot(self, email, iid, aid):
        """XposedOrNot — completely free breach checker"""
        out = []
        try:
            r = requests.get(
                "https://api.xposedornot.com/v1/breach-analytics",
                params={"email": email}, timeout=10
            )
            if r.status_code == 200:
                breaches = r.json().get("breaches", {}).get("breaches_details", [])
                for b in breaches:
                    out.append(Finding(
                        investigation_id=iid, actor_id=aid,
                        finding_type="email", value=email,
                        source="xposedornot",
                        source_url="https://xposedornot.com",
                        confidence=0.95,
                        evidence=[Evidence(
                            source="xposedornot",
                            title=f"Breach: {b.get('breach','')}",
                            excerpt=f"Date: {b.get('xposed_date','')} | Data: {b.get('xposed_data','')}",
                            metadata=b
                        )],
                        metadata={
                            "breach_name": b.get("breach", ""),
                            "breach_date": b.get("xposed_date", ""),
                            "data_classes": b.get("xposed_data", ""),
                            "records": b.get("xposed_records", "")
                        }
                    ))
        except Exception:
            pass
        return out

    def _hunter(self, email, iid, aid):
        """Hunter.io — email verification, free tier"""
        out = []
        key = os.getenv("HUNTER_API_KEY", "")
        if not key:
            return out
        try:
            r = requests.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email, "api_key": key}, timeout=10
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                out.append(Finding(
                    investigation_id=iid, actor_id=aid,
                    finding_type="email", value=email,
                    source="hunter.io",
                    confidence=0.85 if data.get("result") == "deliverable" else 0.4,
                    metadata={
                        "status": data.get("result", ""),
                        "score": data.get("score", 0),
                        "disposable": data.get("disposable", False),
                        "webmail": data.get("webmail", False)
                    }
                ))
        except Exception:
            pass
        return out

