"""The logic behind the spot the phish lesson.

Given a URL, it points out the tricks phishers use to make a link look like it
leads somewhere it does not. Each signal comes with a short teaching note. The
verdict is deliberately cautious, the way a careful reader would be.
"""
from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import urlparse

# A few brands that are impersonated constantly, for the lookalike check.
COMMON_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "bank", "outlook", "office365", "dhl", "fedex",
]

# Digits and letters that stand in for each other in lookalike domains.
CONFUSABLE_DIGITS = {"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"}


def _host_of(url: str):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return parsed, parsed.hostname or ""


def _is_ip_literal(host: str) -> bool:
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in host  # crude IPv6 check


def _registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def analyze(url: str) -> Dict:
    """Return signals and a verdict for a URL.

    signals: list of {level, title, detail}, level is 'danger' or 'note'.
    verdict: 'suspicious' if any danger signal, else 'looks ok'.
    """
    url = url.strip()
    parsed, host = _host_of(url)
    host_l = host.lower()
    authority = url.split("://", 1)[-1].split("/", 1)[0]
    signals: List[Dict] = []

    def danger(title, detail):
        signals.append({"level": "danger", "title": title, "detail": detail})

    def note(title, detail):
        signals.append({"level": "note", "title": title, "detail": detail})

    if "@" in authority:
        shown = authority.split("@", 1)[0]
        real = authority.split("@", 1)[1]
        danger("The part before the @ is ignored",
                "A browser sends you to what comes after the @ sign. Here that is "
                + (real or "the real host") + ", not " + (shown or "the text you see") + ".")

    if "xn--" in host_l:
        danger("Punycode in the domain",
                "xn-- marks a domain written in non Latin letters. It can render as "
                "a name that looks identical to a real one while pointing elsewhere.")

    if _is_ip_literal(host_l):
        danger("The address is a raw IP, not a name",
                "Real services almost always use a domain name. A bare IP address in a "
                "link is a common sign of something hiding.")

    labels = host_l.split(".")
    if len(labels) >= 4:
        note("Many subdomains",
             "A long stack of subdomains like a.b.c.example.com can bury the real "
             "domain, which is always the last two labels, here " + _registered_domain(host_l) + ".")

    reg = _registered_domain(host_l)
    for brand in COMMON_BRANDS:
        if brand in host_l and brand not in reg:
            danger("A brand name sits in the subdomain",
                    "The name " + brand + " appears, but the real domain is " + reg +
                    ", not " + brand + ". Anyone can put a brand in front of their own domain.")
            break

    stripped = host_l.replace(".", "")
    for brand in COMMON_BRANDS:
        for digit, letter in CONFUSABLE_DIGITS.items():
            faked = brand.replace(letter, digit)
            if faked != brand and faked in stripped:
                danger("A lookalike of a known brand",
                        "This contains " + faked + ", a version of " + brand +
                        " with a digit standing in for a letter to fool a quick glance.")
                break

    if any(ord(c) > 127 for c in host_l):
        danger("Non standard characters in the domain",
                "The domain uses characters outside the plain Latin set, which can be "
                "chosen to look like ordinary letters.")

    if parsed.scheme == "http":
        note("Not using https",
             "The link is plain http, so the connection is not encrypted. On its own "
             "this is not phishing, but sensitive sites should always use https.")

    verdict = "suspicious" if any(s["level"] == "danger" for s in signals) else "looks ok"
    return {"url": url, "registered_domain": reg, "signals": signals, "verdict": verdict}


def explain() -> str:
    return (
        "A phishing link works by looking like one thing and leading to another. "
        "The single most useful habit is to find the real domain, which is always "
        "the last two labels before the first single slash, and ignore everything "
        "dressed up around it. Attackers pad links with a trusted brand in a "
        "subdomain, swap letters for lookalike digits or foreign characters, hide "
        "the true host after an @ sign, or use a raw IP address. None of these "
        "change where you actually land, only how the link reads at a glance."
    )


TAKEAWAY = (
    "Read a link from the right. Find the real domain, the last two labels before "
    "the first slash, and do not trust the rest. When unsure, do not click, go to "
    "the site yourself."
)
