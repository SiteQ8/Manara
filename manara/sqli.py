"""The logic behind the SQL injection lesson.

This is a simulation for teaching, not a database. A tiny in memory table and a
minimal evaluator for the WHERE clause are enough to show why string building a
query lets input change its meaning, and why treating input as data instead
shuts that down. There is no real SQL engine and nothing here touches a real
database.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# The pretend users table. The attacker does not know these values.
USERS: List[Tuple[str, str]] = [
    ("admin", "s3cr3t-admin-pw"),
    ("maryam", "correct horse battery"),
    ("khaled", "hunter2"),
]


def _split_top_level(clause: str, keyword: str) -> List[str]:
    """Split a WHERE clause on a boolean keyword, ignoring quoted text."""
    parts, buf, i, in_str = [], "", 0, False
    up = clause.upper()
    key = " " + keyword.upper() + " "
    while i < len(clause):
        ch = clause[i]
        if ch == "'":
            in_str = not in_str
            buf += ch
            i += 1
            continue
        if not in_str and up[i:i + len(key)] == key:
            parts.append(buf)
            buf = ""
            i += len(key)
            continue
        buf += ch
        i += 1
    parts.append(buf)
    return parts


def _resolve(token: str, row: Dict[str, str]) -> str:
    """A quoted token is a literal; a bare column name resolves to the row."""
    token = token.strip()
    if len(token) >= 2 and token[0] == "'" and token[-1] == "'":
        return token[1:-1]
    if token in row:
        return row[token]
    return token


def _eval_atom(atom: str, row: Dict[str, str]) -> bool:
    """Evaluate a='b' where either side is a literal or a column of the row."""
    atom = atom.strip().strip("()").strip()
    if "=" not in atom:
        return False
    left, right = atom.split("=", 1)
    return _resolve(left, row) == _resolve(right, row)


def _eval_where(clause: str, row: Dict[str, str]) -> bool:
    """Evaluate a WHERE clause of atoms joined by AND and OR against one row."""
    or_parts = _split_top_level(clause, "OR")
    for or_part in or_parts:
        and_parts = _split_top_level(or_part, "AND")
        if all(_eval_atom(a, row) for a in and_parts):
            return True
    return False


def vulnerable_login(username: str, password: str) -> Dict:
    """Build the query by pasting input straight in, then evaluate it.

    This is the unsafe pattern. Input like  ' OR '1'='1  closes the string and
    adds a condition that is always true, so every row satisfies the WHERE
    clause and the login succeeds with no real password.
    """
    query = ("SELECT * FROM users WHERE username='" + username +
             "' AND password='" + password + "'")
    where = query.split(" WHERE ", 1)[1]
    matched = [u for u, p in USERS if _eval_where(where, {"username": u, "password": p})]
    return {"query": query, "granted": bool(matched), "matched": matched, "safe": False}


def safe_login(username: str, password: str) -> Dict:
    """Treat input as data, never as part of the query.

    The placeholders stand for values that are compared as they are, so an
    injection string is just a username that does not exist.
    """
    query = "SELECT * FROM users WHERE username=? AND password=?"
    granted = any(u == username and p == password for u, p in USERS)
    return {"query": query, "params": [username, password], "granted": granted, "safe": True}


CLASSIC_PAYLOAD = "' OR '1'='1"


def explain() -> str:
    return (
        "When an application builds a database query by pasting user input "
        "directly into the text of the query, the input can break out of where "
        "it was meant to sit and change what the query does. The classic example "
        "in a login is to enter, as the password, a quote to close the string "
        "and then a condition that is always true. The database now sees a "
        "WHERE clause that always passes, and the login succeeds with no real "
        "password. The fix is not to filter bad words, it is to never build "
        "queries by pasting. Parameterized queries send the query and the values "
        "separately, so input is always treated as data and can never become "
        "part of the command."
    )


TAKEAWAY = (
    "Never build a query by concatenating input. Use parameterized queries, also "
    "called prepared statements, so input is always data and never code."
)
