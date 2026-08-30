"""The logic behind the password strength lesson.

It estimates how much true randomness a password has, in bits, and turns that
into an honest sense of how long a guessing attack would take. The estimate
assumes the attacker knows the shape of the password, which is the safe way to
think about it.
"""
from __future__ import annotations

import math
from typing import Dict

LOWER = set("abcdefghijklmnopqrstuvwxyz")
UPPER = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
DIGITS = set("0123456789")

# A guess rate for a fast offline attack against a weak fast hash, per second.
OFFLINE_FAST = 100_000_000_000  # one hundred billion


def charset_size(password: str) -> int:
    """The size of the pool of characters the password draws from."""
    pool = 0
    if any(c in LOWER for c in password):
        pool += 26
    if any(c in UPPER for c in password):
        pool += 26
    if any(c in DIGITS for c in password):
        pool += 10
    if any((c not in LOWER and c not in UPPER and c not in DIGITS) for c in password):
        pool += 33  # a rough count of common keyboard symbols and space
    return pool


def entropy_bits(password: str) -> float:
    """Rough entropy in bits: length times bits per character in the pool.

    This is an upper bound. A password made of dictionary words has far less
    real entropy than this number suggests, which is the point of the lesson.
    """
    if not password:
        return 0.0
    pool = charset_size(password)
    if pool <= 1:
        return 0.0
    return len(password) * math.log2(pool)


def crack_time_seconds(bits: float, guesses_per_second: float = OFFLINE_FAST) -> float:
    """Average time to guess, which is half of the whole space."""
    if guesses_per_second <= 0:
        return float("inf")
    return (2 ** bits) / 2 / guesses_per_second


def human_time(seconds: float) -> str:
    if seconds == float("inf"):
        return "effectively forever"
    if seconds < 1:
        return "less than a second"
    units = [
        ("year", 365 * 24 * 3600), ("day", 24 * 3600),
        ("hour", 3600), ("minute", 60), ("second", 1),
    ]
    if seconds > 100 * units[0][1]:
        years = seconds / units[0][1]
        if years >= 1e12:
            return "trillions of years"
        if years >= 1e9:
            return "billions of years"
        if years >= 1e6:
            return "millions of years"
        if years >= 1e3:
            return "thousands of years"
    for name, size in units:
        if seconds >= size:
            value = int(seconds // size)
            return f"{value} {name}" + ("s" if value != 1 else "")
    return "less than a second"


def strength_label(bits: float) -> str:
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "reasonable"
    if bits < 128:
        return "strong"
    return "very strong"


def estimate(password: str, guesses_per_second: float = OFFLINE_FAST) -> Dict:
    bits = entropy_bits(password)
    secs = crack_time_seconds(bits, guesses_per_second)
    return {
        "length": len(password),
        "charset_size": charset_size(password),
        "entropy_bits": round(bits, 1),
        "label": strength_label(bits),
        "crack_time_seconds": secs,
        "crack_time": human_time(secs),
    }


def explain() -> str:
    return (
        "Password strength is not about symbols and capital letters, it is "
        "about how many equally likely possibilities an attacker has to search. "
        "That number is entropy, measured in bits, and each extra bit doubles "
        "the work. Length adds bits far faster than complexity does, which is "
        "why a long passphrase of ordinary words beats a short scramble of "
        "symbols. The catch is that these estimates assume every character is "
        "random. A real password built from a common word has much less "
        "entropy than the formula shows, because an attacker guesses words, "
        "not characters."
    )


TAKEAWAY = (
    "Favor length over complexity. A long unique passphrase, kept in a password "
    "manager and paired with two factor authentication, beats a short clever one."
)
