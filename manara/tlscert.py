"""The logic behind the TLS and certificates lesson.

HTTPS does two things: it encrypts the connection, and it proves you are talking
to who you think. The proof is a certificate, and a browser accepts it only if a
short list of checks all pass. This module runs those checks against a simulated
certificate so a learner can see exactly why a warning appears. There is no real
TLS here, only the validation logic.
"""
from __future__ import annotations

from typing import Dict, List

# A tiny set of certificate authorities the browser is told to trust.
TRUSTED_CAS = ["Example Trust CA", "Global Root CA", "Lets Encrypt Authority"]


def _host_matches(pattern: str, hostname: str) -> bool:
    """Match a certificate subject against a hostname, allowing one wildcard."""
    pattern, hostname = pattern.lower(), hostname.lower()
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        base = pattern[2:]
        parts = hostname.split(".", 1)
        return len(parts) == 2 and parts[1] == base
    return False


def validate(cert: Dict, hostname: str, today: str) -> Dict:
    """Run the browser's checks on a certificate.

    cert has: subject, issuer, valid_from, valid_to (dates as YYYY-MM-DD),
    self_signed (bool). today is a YYYY-MM-DD date string. Returns each check
    with a pass flag and a note, plus an overall trusted flag.
    """
    checks: List[Dict] = []

    not_expired = cert["valid_from"] <= today <= cert["valid_to"]
    checks.append({
        "name": "Within its validity dates",
        "ok": not_expired,
        "note": ("Valid from " + cert["valid_from"] + " to " + cert["valid_to"] + ".")
        if not_expired else
        ("Today is " + today + ", outside " + cert["valid_from"] + " to " + cert["valid_to"] +
         ". An expired certificate is no longer trusted."),
    })

    host_ok = _host_matches(cert["subject"], hostname)
    checks.append({
        "name": "Issued for this hostname",
        "ok": host_ok,
        "note": ("The certificate names " + cert["subject"] + ", which matches " + hostname + ".")
        if host_ok else
        ("The certificate names " + cert["subject"] + ", but you connected to " + hostname +
         ". A certificate for the wrong name proves nothing about this site."),
    })

    trusted_issuer = (not cert.get("self_signed")) and cert["issuer"] in TRUSTED_CAS
    if cert.get("self_signed"):
        issuer_note = ("The certificate signed itself. Anyone can make one, so it "
                       "proves no independent identity.")
    elif trusted_issuer:
        issuer_note = "Signed by " + cert["issuer"] + ", a trusted authority."
    else:
        issuer_note = ("Signed by " + cert["issuer"] + ", which is not a trusted "
                       "authority, so the chain of trust is broken.")
    checks.append({"name": "Signed by a trusted authority", "ok": trusted_issuer, "note": issuer_note})

    trusted = all(c["ok"] for c in checks)
    return {"hostname": hostname, "subject": cert["subject"], "checks": checks, "trusted": trusted}


# A few ready made scenarios for the lesson.
SCENARIOS = {
    "valid": {
        "label": "A normal, valid certificate",
        "cert": {"subject": "shop.example.com", "issuer": "Lets Encrypt Authority",
                 "valid_from": "2025-01-01", "valid_to": "2026-06-01", "self_signed": False},
        "hostname": "shop.example.com",
    },
    "expired": {
        "label": "An expired certificate",
        "cert": {"subject": "shop.example.com", "issuer": "Lets Encrypt Authority",
                 "valid_from": "2023-01-01", "valid_to": "2024-01-01", "self_signed": False},
        "hostname": "shop.example.com",
    },
    "wrong_host": {
        "label": "A certificate for the wrong site",
        "cert": {"subject": "other-site.com", "issuer": "Global Root CA",
                 "valid_from": "2025-01-01", "valid_to": "2026-06-01", "self_signed": False},
        "hostname": "shop.example.com",
    },
    "self_signed": {
        "label": "A self signed certificate",
        "cert": {"subject": "shop.example.com", "issuer": "shop.example.com",
                 "valid_from": "2025-01-01", "valid_to": "2026-06-01", "self_signed": True},
        "hostname": "shop.example.com",
    },
}

TODAY = "2025-09-01"


def explain() -> str:
    return (
        "When you connect over https, the site sends a certificate that does two "
        "jobs. It carries the key used to encrypt the connection, and it proves "
        "the site is who it claims to be. Your browser accepts it only if three "
        "things hold. The certificate must be within its validity dates, it must "
        "be issued for the exact hostname you visited, and it must be signed by an "
        "authority your browser already trusts, forming an unbroken chain. If any "
        "check fails, the encryption might still work, but the identity is "
        "unproven, and that is exactly what the browser warning is telling you. A "
        "self signed certificate fails the last check because anyone can make one."
    )


TAKEAWAY = (
    "A certificate warning means identity could not be proven, so treat the site "
    "as untrusted and do not click through on anything that matters. Encryption "
    "without a verified identity is encryption with a stranger."
)
