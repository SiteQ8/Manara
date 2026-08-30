"""The logic behind the brute force and rate limiting lesson.

It turns the size of a secret and the speed of guessing into a time, then shows
how a lockout after a few wrong tries changes that time from seconds to years.
The PIN simulation guesses in order so a learner can watch it land.
"""
from __future__ import annotations

from typing import Dict, Optional


def space_size(length: int, alphabet_size: int) -> int:
    return alphabet_size ** length


def time_to_break(space: int, guesses_per_second: float) -> float:
    """Average time, which is half the space divided by the guess rate."""
    if guesses_per_second <= 0:
        return float("inf")
    return (space / 2) / guesses_per_second


def simulate_pin(secret: str, lockout_after: Optional[int] = None,
                 lockout_seconds: float = 300.0,
                 online_guesses_per_second: float = 10.0) -> Dict:
    """Guess 0000 upward until the secret is found.

    Returns the number of tries, and how long it takes both without any limit
    and with a lockout that pauses the attacker every lockout_after tries.
    """
    width = len(secret)
    space = 10 ** width
    tries = 0
    for n in range(space):
        tries += 1
        if str(n).zfill(width) == secret:
            break

    no_limit = tries / online_guesses_per_second
    with_lockout = None
    if lockout_after:
        lockouts = (tries - 1) // lockout_after
        with_lockout = tries / online_guesses_per_second + lockouts * lockout_seconds
    return {
        "width": width, "space": space, "tries": tries,
        "seconds_no_limit": no_limit,
        "seconds_with_lockout": with_lockout,
        "lockout_after": lockout_after,
        "lockout_seconds": lockout_seconds,
    }


def explain() -> str:
    return (
        "A brute force attack simply tries every possibility. Whether that is "
        "hopeless or trivial depends on two numbers: how many possibilities there "
        "are, and how many the attacker can try each second. A four digit PIN is "
        "only ten thousand possibilities, which falls in seconds if guessing is "
        "unlimited. Rate limiting changes the second number. If the system "
        "refuses further tries for several minutes after a few wrong ones, the "
        "same PIN now takes days or years to work through, and the attacker is "
        "loud while trying. This is why a short secret can still be safe behind a "
        "lockout, and why a long secret is safer still."
    )


TAKEAWAY = (
    "Limit and slow failed attempts, and lock out after a few. Rate limiting can "
    "make even a short secret impractical to guess, and it makes attacks visible."
)
