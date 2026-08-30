"""The logic behind the cross site request forgery lesson.

This completes the web attack trio. SQL injection broke into a query, cross site
scripting broke into a page, and cross site request forgery abuses something
quieter: the browser attaches your session cookie to every request to a site,
even requests started by another site. So a hidden form on an attacker's page
can make your bank act as you. This module simulates one transfer endpoint and
shows which defense stops the forged request. No real requests are made.
"""
from __future__ import annotations

from typing import Dict, Optional

# The secret token the real site places in its own forms. An attacker's page
# cannot read it, which is the whole point.
SERVER_TOKEN = "tok-7f3a9c21"


def attempt_transfer(cross_site: bool, token: Optional[str],
                     csrf_protection: bool, same_site_cookie: bool,
                     logged_in: bool = True) -> Dict:
    """Decide whether a transfer request goes through.

    cross_site is True when the request was started by another site, such as an
    attacker's page. token is the CSRF token the request carried. The two
    defenses are csrf_protection, whether the server demands a valid token, and
    same_site_cookie, whether the session cookie is marked SameSite.
    """
    # The browser sends the session cookie unless it is SameSite and the request
    # came from another site.
    cookie_sent = logged_in and not (cross_site and same_site_cookie)
    authenticated = cookie_sent
    token_ok = (not csrf_protection) or (token == SERVER_TOKEN)
    executed = authenticated and token_ok

    if executed:
        blocked_by = None
        if cross_site:
            explanation = ("The forged request went through. The session cookie rode along "
                           "automatically and nothing else was checked, so the bank acted as you.")
        else:
            explanation = "A normal request from the real site, with the session and the right token."
    elif not authenticated:
        blocked_by = "SameSite cookie"
        explanation = ("The session cookie was marked SameSite, so the browser did not attach it "
                       "to a request from another site. The server saw no session and refused.")
    else:
        blocked_by = "CSRF token"
        explanation = ("The request reached the server with a session but without the secret token "
                       "the real forms carry. The attacker's page cannot know it, so the server refused.")

    return {
        "cross_site": cross_site, "cookie_sent": cookie_sent, "authenticated": authenticated,
        "token_ok": token_ok, "executed": executed, "blocked_by": blocked_by,
        "explanation": explanation,
    }


# Ready made scenarios for the lesson.
SCENARIOS = {
    "legit": {
        "label": "You click Transfer on the real bank site",
        "args": {"cross_site": False, "token": SERVER_TOKEN, "csrf_protection": True, "same_site_cookie": True},
    },
    "attack_open": {
        "label": "An attacker's hidden form fires, with no defenses",
        "args": {"cross_site": True, "token": None, "csrf_protection": False, "same_site_cookie": False},
    },
    "attack_vs_token": {
        "label": "The same attack, but the bank checks a CSRF token",
        "args": {"cross_site": True, "token": None, "csrf_protection": True, "same_site_cookie": False},
    },
    "attack_vs_samesite": {
        "label": "The same attack, but the cookie is SameSite",
        "args": {"cross_site": True, "token": None, "csrf_protection": False, "same_site_cookie": True},
    },
}


def explain() -> str:
    return (
        "Cross site request forgery is the quiet member of the web attack trio. It "
        "does not steal your password or inject code. It abuses a convenience: your "
        "browser attaches your session cookie to every request bound for a site, "
        "even a request started by a different site. So if you are logged in to "
        "your bank and then visit an attacker's page, a hidden form there can post a "
        "transfer to the bank, and the browser will helpfully include your session. "
        "The bank sees a request that looks like it came from you. Two defenses stop "
        "it. A CSRF token is a secret the real site puts in its own forms and checks "
        "on submit, which the attacker's page cannot know. A SameSite cookie, from "
        "the sessions lesson, tells the browser not to send the session on cross "
        "site requests at all, so the forged request arrives with no session."
    )


TAKEAWAY = (
    "Protect every state changing request with a CSRF token or SameSite cookies, "
    "and never let a plain GET change state. If a request can act as the user, make "
    "sure it truly came from your own site."
)
