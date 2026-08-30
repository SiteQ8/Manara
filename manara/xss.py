"""The logic behind the cross site scripting lesson.

Cross site scripting is the sibling of SQL injection: instead of input breaking
into a database query, input breaks into the HTML of a page and runs as script.
This module shows the danger without ever running anything. It inspects a comment
and reports whether a vulnerable page would execute it, and shows the escaped,
safe version. Detection is descriptive only, so nothing here executes input.
"""
from __future__ import annotations

import re
from typing import Dict, List

# Patterns that would run in a page that inserts input without escaping.
_TRIGGERS = [
    (re.compile(r"<script", re.I), "a <script> block, which runs immediately"),
    (re.compile(r"on\w+\s*=", re.I), "an inline event handler such as onerror or onload, which runs on the element"),
    (re.compile(r"javascript:", re.I), "a javascript: URL, which runs when followed"),
    (re.compile(r"<iframe", re.I), "an injected iframe, which can load hostile content"),
]


def escape_html(text: str) -> str:
    """The fix: turn markup into harmless text. Order matters, ampersand first."""
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def would_execute(comment: str) -> List[str]:
    """Describe what a vulnerable page would run. Does not run anything."""
    hits = []
    for pattern, description in _TRIGGERS:
        if pattern.search(comment):
            hits.append(description)
    return hits


def render_unsafe(comment: str) -> Dict:
    """What happens when a page inserts the comment straight into its HTML.

    Returns the raw markup that would be placed on the page and a description of
    what would execute. This is the dangerous pattern, shown so it is understood.
    """
    triggers = would_execute(comment)
    return {"inserted": comment, "would_execute": bool(triggers), "triggers": triggers, "safe": False}


def render_safe(comment: str) -> Dict:
    """What happens when the page escapes the comment first.

    The same input becomes literal text on the page. A script tag shows up as the
    characters of a script tag; nothing runs.
    """
    return {"inserted": escape_html(comment), "would_execute": False, "triggers": [], "safe": True}


# A few example comments for the lesson.
SAMPLES = [
    "Nice write up, thanks!",
    "<script>fetch('/steal?c='+document.cookie)</script>",
    "<img src=x onerror=\"fetch('/steal?c='+document.cookie)\">",
    "<b>bold but harmless</b>",
]


def explain() -> str:
    return (
        "Cross site scripting is SQL injection's sibling. There, input broke into "
        "a database query; here, input breaks into the HTML of a page. When a site "
        "takes something a user typed, a comment, a name, a search term, and drops "
        "it into the page without escaping, any markup in it becomes part of the "
        "page. A comment containing a script tag or an event handler then runs in "
        "every visitor's browser, where it can read their session cookie or act as "
        "them. The fix is the same shape as before: treat input as data. Escape it "
        "for the place it is going so that a script tag becomes the visible text of "
        "a script tag and never executes. A Content Security Policy and an HttpOnly "
        "cookie, from the earlier lessons, are the defenses in depth behind that."
    )


TAKEAWAY = (
    "Escape output for its context, or use a framework that does it by default, so "
    "user input is never treated as markup. Add a Content Security Policy and "
    "HttpOnly cookies as defense in depth."
)
