"""The logic behind the encoding is not encryption lesson.

base64, a Caesar shift, and XOR with a key are all reversible by anyone who
sees the output, because no secret is needed to undo them. That is the whole
point: they hide nothing. This lesson exists so a learner never again mistakes
encoding or obfuscation for encryption.
"""
from __future__ import annotations

import base64
from typing import Dict

ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def b64_decode(data: str) -> str:
    return base64.b64decode(data.encode("ascii")).decode("utf-8", "replace")


def caesar(text: str, shift: int) -> str:
    out = []
    for ch in text:
        low = ch.lower()
        if low in ALPHABET:
            idx = (ALPHABET.index(low) + shift) % 26
            new = ALPHABET[idx]
            out.append(new.upper() if ch.isupper() else new)
        else:
            out.append(ch)
    return "".join(out)


def xor_hex(text: str, key: str) -> str:
    """XOR text with a repeating key, returned as hex."""
    if not key:
        return text.encode("utf-8").hex()
    kb = key.encode("utf-8")
    tb = text.encode("utf-8")
    out = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(tb))
    return out.hex()


def xor_from_hex(data_hex: str, key: str) -> str:
    raw = bytes.fromhex(data_hex)
    if not key:
        return raw.decode("utf-8", "replace")
    kb = key.encode("utf-8")
    out = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(raw))
    return out.decode("utf-8", "replace")


def explain() -> str:
    return (
        "Encoding changes how data is written so it can travel safely, and "
        "obfuscation scrambles it so it is not obvious at a glance. Neither is "
        "encryption, because neither needs a secret to undo. base64 is just a "
        "way to write bytes with a safe alphabet, and anyone can decode it. A "
        "Caesar shift and a XOR against a known key can be reversed the moment "
        "the method is known. Encryption is different in one essential way: "
        "without the key, undoing it is infeasible even when the method is fully "
        "public. If there is no key, there is no secrecy."
    )


TAKEAWAY = (
    "base64, hex, and simple XOR are not security. If data must stay secret, "
    "encrypt it with a real algorithm and a real key, such as AES or the tools "
    "in a vetted library."
)
