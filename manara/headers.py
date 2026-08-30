"""The logic behind the security headers lesson.

Each header is a short instruction to the browser that closes off a class of
attack. The lesson lets a learner toggle each one and see what it defends. The
checker reports, for a given set of response headers, what is protected and
what is still open.
"""
from __future__ import annotations

from typing import Dict, List

# name -> (what it does, the attack it blocks, a good example value)
CATALOG = {
    "Content-Security-Policy": (
        "Lists exactly where scripts, styles, and other content may load from.",
        "Cross site scripting, where injected script runs in your page.",
        "default-src 'self'",
    ),
    "X-Content-Type-Options": (
        "Tells the browser to trust the declared content type and not guess.",
        "MIME sniffing, where a file is treated as script because the browser guessed.",
        "nosniff",
    ),
    "X-Frame-Options": (
        "Controls whether your page may be placed inside a frame.",
        "Clickjacking, where your page is framed invisibly over a decoy.",
        "DENY",
    ),
    "Strict-Transport-Security": (
        "Forces every future visit to use https, even if a link says http.",
        "Downgrade and interception on the first or a later plain http request.",
        "max-age=63072000; includeSubDomains",
    ),
    "Referrer-Policy": (
        "Limits how much of your URL is sent when a user follows a link away.",
        "Leaking paths and query strings, which can hold tokens, to other sites.",
        "strict-origin-when-cross-origin",
    ),
}


def check(headers: Dict[str, str]) -> Dict:
    """Report present and missing security headers for a response.

    headers is a mapping of header name to value; names are matched case
    insensitively.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    present, missing = [], []
    for name, (does, blocks, example) in CATALOG.items():
        entry = {"name": name, "does": does, "blocks": blocks, "example": example}
        if name.lower() in lower:
            entry["value"] = lower[name.lower()]
            present.append(entry)
        else:
            missing.append(entry)
    score = round(100 * len(present) / len(CATALOG))
    return {"present": present, "missing": missing, "protected_pct": score}


def explain() -> str:
    return (
        "A web server can send a handful of response headers that tell the "
        "browser how to protect the page. They cost nothing and each one closes "
        "a specific door. A Content Security Policy limits where scripts may come "
        "from, which is the strongest defense against injected script. nosniff "
        "stops the browser guessing a file into something dangerous. Frame "
        "options stop your page being used in a clickjacking overlay. Strict "
        "transport security pins the site to https. A referrer policy stops your "
        "URLs, which may carry tokens, leaking to other sites. Missing headers "
        "are not a breach by themselves, they are removed safety nets."
    )


TAKEAWAY = (
    "Set the security headers on every response. They are cheap, they break "
    "little, and each one removes a whole class of browser side attack."
)
