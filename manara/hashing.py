"""The logic behind the hashing lesson.

Everything here is for understanding how password storage works and why some
ways are safe and some are not. The dictionary attack runs against a tiny
built in wordlist so a learner can watch an unsalted hash fall and a salted one
survive. Nothing here attacks a real system.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

ALGORITHMS = ["md5", "sha1", "sha256"]

# Weak algorithms shown so a learner can see why they are weak.
WEAK = {"md5", "sha1"}

# A small list of the passwords people actually pick most often.
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "qwerty", "abc123",
    "111111", "iloveyou", "admin", "welcome", "monkey", "dragon",
    "letmein", "football", "sunshine", "princess", "password1", "hunter2",
]


def digest(text: str, algorithm: str = "sha256") -> str:
    """Return the hex digest of text under the named algorithm."""
    algorithm = algorithm.lower()
    if algorithm not in ALGORITHMS:
        raise ValueError("unknown algorithm: " + algorithm)
    return hashlib.new(algorithm, text.encode("utf-8")).hexdigest()


def salted_digest(password: str, salt: str, algorithm: str = "sha256") -> str:
    """Hash salt + password, the simplest form of salting."""
    return digest(salt + password, algorithm)


def same_hash(a: str, b: str, algorithm: str = "sha256") -> bool:
    """Two equal passwords always hash the same. That is the whole problem."""
    return digest(a, algorithm) == digest(b, algorithm)


def dictionary_attack(target_hash: str, algorithm: str = "sha256",
                      salt: Optional[str] = None,
                      wordlist: Optional[List[str]] = None) -> Dict:
    """Try each candidate against the target hash.

    Returns the word that matched (or None), how many tries it took, and the
    size of the list. With a salt the attacker must know it to even try, and a
    per user salt means this list would have to be run again for every user.
    """
    words = wordlist if wordlist is not None else COMMON_PASSWORDS
    target = target_hash.lower()
    for i, word in enumerate(words, 1):
        guess = salted_digest(word, salt, algorithm) if salt else digest(word, algorithm)
        if guess == target:
            return {"found": word, "attempts": i, "wordlist_size": len(words)}
    return {"found": None, "attempts": len(words), "wordlist_size": len(words)}


def explain() -> str:
    return (
        "A hash turns a password into a fixed fingerprint that cannot be "
        "reversed directly. Storing the hash instead of the password means a "
        "stolen database does not immediately hand over everyone's password. "
        "But the same password always produces the same hash, so an attacker "
        "can hash a list of common passwords once and match them against the "
        "stolen hashes. A salt, a random value stored with each user, makes "
        "every hash unique even for identical passwords, so that precomputation "
        "no longer works and the list must be run again for every single user. "
        "A slow hash built for passwords, such as bcrypt, scrypt, or Argon2, "
        "then makes each of those tries expensive."
    )


TAKEAWAY = (
    "Store passwords with a slow, salted password hash such as bcrypt, scrypt, "
    "or Argon2. Never a bare MD5 or SHA256, and never the password itself."
)
