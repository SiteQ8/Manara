"""The logic behind the cookies and sessions lesson.

A session cookie is a bearer token: whoever holds it is treated as you, with no
further proof. Three flags decide how exposed that token is. This module reports,
for a given set of flags, exactly which attacks are open and which are closed.
Nothing here touches a real session or a real browser.
"""
from __future__ import annotations

import secrets
from typing import Dict, List

FLAGS = ["HttpOnly", "Secure", "SameSite"]


def new_session_id() -> str:
    """A random session id, the value an attacker would love to steal."""
    return secrets.token_hex(16)


def analyze(flags: Dict[str, bool]) -> Dict:
    """Report what a session cookie exposes given its flags.

    flags is a mapping with any of HttpOnly, Secure, SameSite set to True.
    Returns the open risks, the closed protections, and a simple exposure count.
    """
    http_only = bool(flags.get("HttpOnly"))
    secure = bool(flags.get("Secure"))
    same_site = bool(flags.get("SameSite"))

    risks: List[Dict] = []
    safe: List[Dict] = []

    def add(cond, holder, title, detail):
        (safe if cond else risks).append({"title": title, "detail": detail})

    add(http_only, safe,
        "Readable by page scripts" if not http_only else "Hidden from page scripts",
        ("Without HttpOnly, any script on the page can read the cookie. A single "
         "cross site scripting bug then hands the whole session to an attacker.")
        if not http_only else
        "HttpOnly is set, so page scripts cannot read the cookie, which blocks theft through cross site scripting.")

    add(secure, safe,
        "Sent over plain http" if not secure else "Sent only over https",
        ("Without Secure, the cookie rides along on any plain http request, where "
         "anyone on the network path can read it.")
        if not secure else
        "Secure is set, so the cookie is only ever sent over https and cannot be sniffed in the clear.")

    add(same_site, safe,
        "Sent on cross site requests" if not same_site else "Held back on cross site requests",
        ("Without SameSite, the browser attaches the cookie even to requests started "
         "by another site, which is what makes cross site request forgery work.")
        if not same_site else
        "SameSite is set, so the cookie is not sent on requests started by other sites, which blocks cross site request forgery.")

    return {
        "flags": {"HttpOnly": http_only, "Secure": secure, "SameSite": same_site},
        "risks": risks, "safe": safe,
        "exposure": len(risks), "protected": len(safe),
    }


def explain() -> str:
    return (
        "After you log in, the server gives your browser a session cookie, a "
        "random id that stands in for you on every later request. That is "
        "convenient, but it means the cookie is a key: whoever holds it is you, "
        "with no password needed. Three flags decide how well that key is guarded. "
        "HttpOnly keeps page scripts from reading it, so a cross site scripting "
        "bug cannot steal it. Secure keeps it off plain http, so it cannot be "
        "sniffed. SameSite keeps it from being sent on requests started by other "
        "sites, which is what stops cross site request forgery. Leaving any of the "
        "three off opens a specific and well known attack."
    )


TAKEAWAY = (
    "Set HttpOnly, Secure, and SameSite on session cookies, and give sessions a "
    "short life and a real logout. The cookie is a key, so guard it like one."
)
