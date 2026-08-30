"""The catalog of lessons.

Each lesson pairs a short explanation and a defensive takeaway from a topic
module with a title and a one line summary. The order is a suggested path from
the most fundamental idea to the more applied ones.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from . import bruteforce, encoding, entropy, hashing, headers, phishing, sqli


@dataclass
class Lesson:
    id: str
    title: str
    summary: str
    module: object

    @property
    def explanation(self) -> str:
        return self.module.explain()

    @property
    def takeaway(self) -> str:
        return self.module.TAKEAWAY


LESSONS: List[Lesson] = [
    Lesson("hashing", "Hashing and passwords",
           "Why storing a hash helps, why the same password hashing the same way hurts, and what salt fixes.",
           hashing),
    Lesson("strength", "How strong is a password",
           "Measure a password in bits of entropy and see why length beats complexity.",
           entropy),
    Lesson("phish", "Spot the phish",
           "Read a link the way an attacker hopes you will not, and find where it really goes.",
           phishing),
    Lesson("sqli", "SQL injection, safely",
           "See why building a query from input is dangerous, and why parameters end it.",
           sqli),
    Lesson("encoding", "Encoding is not encryption",
           "base64, Caesar, and XOR all reverse without a secret, so they hide nothing.",
           encoding),
    Lesson("headers", "Security headers",
           "Flip the browser security headers and see which attack each one blocks.",
           headers),
    Lesson("bruteforce", "Brute force and rate limiting",
           "Turn a secret and a guess rate into a time, then watch a lockout change it.",
           bruteforce),
]

BY_ID = {lesson.id: lesson for lesson in LESSONS}
