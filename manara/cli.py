"""The manara command line: a hands on version of each lesson in the terminal."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__, bruteforce, encoding, entropy, hashing, phishing, sqli
from .lessons import BY_ID, LESSONS
from .serve import run_server

C = {"b": "\x1b[1m", "d": "\x1b[2m", "g": "\x1b[92m", "y": "\x1b[93m",
     "r": "\x1b[91m", "c": "\x1b[96m", "x": "\x1b[0m"}


def _color(on: bool):
    return C if on else {k: "" for k in C}


def _wrap(text: str, width: int = 78) -> str:
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return "\n".join(out)


def cmd_list(color: bool) -> int:
    c = _color(color)
    print(f"\n{c['b']}Manara lessons{c['x']}  (learn by doing)\n")
    for i, lesson in enumerate(LESSONS, 1):
        print(f"  {c['c']}{lesson.id}{c['x']}  {c['b']}{lesson.title}{c['x']}")
        print(f"      {c['d']}{lesson.summary}{c['x']}")
    print(f"\nRun one with:  {c['c']}manara learn <id>{c['x']}\n")
    return 0


def _header(lesson, c):
    print(f"\n{c['b']}{lesson.title}{c['x']}\n")
    print(_wrap(lesson.explanation))
    print()


def _footer(lesson, c):
    print(f"\n{c['g']}Takeaway:{c['x']} {_wrap(lesson.takeaway)}\n")


def _demo_hashing(c):
    pw = "hunter2"
    print(f"Two people both choose the password {c['c']}{pw}{c['x']}.")
    print(f"  sha256({pw}) = {c['d']}{hashing.digest(pw)}{c['x']}")
    print(f"  sha256({pw}) = {c['d']}{hashing.digest(pw)}{c['x']}")
    print(f"They hash to the same value, so cracking one cracks both.\n")
    target = hashing.digest(pw)
    res = hashing.dictionary_attack(target)
    print(f"Running a {res['wordlist_size']} word list against the unsalted hash...")
    print(f"  {c['r']}found in {res['attempts']} tries: {res['found']}{c['x']}\n")
    salt = "a1b2c3d4"
    salted = hashing.salted_digest(pw, salt)
    res2 = hashing.dictionary_attack(salted, salt=None)
    print(f"Now with a per user salt the attacker does not have:")
    print(f"  salted hash = {c['d']}{salted}{c['x']}")
    print(f"  same word list against it: {c['g']}{res2['found'] or 'nothing found'}{c['x']}")


def _demo_strength(c):
    for pw in ["hunter2", "P@ssw0rd", "correct-horse-battery-staple"]:
        e = entropy.estimate(pw)
        col = c['r'] if e['entropy_bits'] < 40 else (c['y'] if e['entropy_bits'] < 60 else c['g'])
        print(f"  {col}{pw}{c['x']}")
        print(f"      {e['entropy_bits']} bits, {e['label']}, cracks in about {e['crack_time']}")


def _demo_phish(c):
    for url in ["https://www.paypal.com/account",
                "http://paypal.com.secure-login.ru/verify",
                "https://paypa1.com/login",
                "http://user@192.168.0.5/reset"]:
        r = phishing.analyze(url)
        col = c['r'] if r['verdict'] == "suspicious" else c['g']
        print(f"  {col}{r['verdict']:>10}{c['x']}  {url}")
        for s in r['signals']:
            if s['level'] == "danger":
                print(f"             {c['d']}- {s['title']}{c['x']}")


def _demo_sqli(c):
    print(f"A login that pastes input into the query. Attacker enters as password:")
    print(f"  {c['c']}{sqli.CLASSIC_PAYLOAD}{c['x']}")
    r = sqli.vulnerable_login("admin", sqli.CLASSIC_PAYLOAD)
    print(f"  query: {c['d']}{r['query']}{c['x']}")
    print(f"  access granted: {c['r']}{r['granted']}{c['x']}  (no real password needed)\n")
    r2 = sqli.safe_login("admin", sqli.CLASSIC_PAYLOAD)
    print(f"The same input against a parameterized query:")
    print(f"  query: {c['d']}{r2['query']}{c['x']}  params={r2['params']}")
    print(f"  access granted: {c['g']}{r2['granted']}{c['x']}  (input is data, not code)")


def _demo_encoding(c):
    msg = "attack at dawn"
    b = encoding.b64_encode(msg)
    print(f"  plaintext: {c['c']}{msg}{c['x']}")
    print(f"  base64:    {c['d']}{b}{c['x']}  ->  decodes back to  {encoding.b64_decode(b)}")
    print(f"  caesar +3: {c['d']}{encoding.caesar(msg, 3)}{c['x']}  ->  undo with -3  {encoding.caesar(encoding.caesar(msg,3),-3)}")
    x = encoding.xor_hex(msg, "key")
    print(f"  xor 'key': {c['d']}{x}{c['x']}  ->  undo with same key  {encoding.xor_from_hex(x,'key')}")
    print(f"\n  None needed a secret to reverse. That is why none is encryption.")


def _demo_headers(c):
    from . import headers as H
    print(f"A response with no security headers:")
    r = H.check({})
    print(f"  protected: {c['r']}{r['protected_pct']}%{c['x']}")
    for m in r['missing']:
        print(f"      {c['d']}missing {m['name']}: blocks {m['blocks']}{c['x']}")
    good = {name: v[2] for name, v in H.CATALOG.items()}
    r2 = H.check(good)
    print(f"\n  With all of them set: {c['g']}{r2['protected_pct']}% protected{c['x']}")


def _demo_bruteforce(c):
    r = bruteforce.simulate_pin("7391", lockout_after=3, lockout_seconds=300, online_guesses_per_second=10)
    print(f"  A 4 digit PIN is {r['space']} possibilities.")
    print(f"  Guessing in order found it in {r['tries']} tries.")
    print(f"  With no limit at 10 per second: {c['r']}about {bruteforce.time_to_break(r['space'],10)/3600:.0f} hours worst case{c['x']}")
    lock_days = r['seconds_with_lockout'] / 86400
    print(f"  With a lockout every 3 tries for 5 minutes: {c['g']}about {lock_days:.0f} days{c['x']}")


def _demo_sessions(c):
    from . import sessions as S
    sid = S.new_session_id()
    print(f"  A session cookie holds a random id like {c['d']}{sid}{c['x']}")
    print(f"  Whoever holds it is you, so its flags decide how exposed it is.\n")
    bare = S.analyze({})
    print(f"  {c['r']}With no flags set ({bare['exposure']} risks open):{c['x']}")
    for risk in bare["risks"]:
        print(f"      - {risk['title']}")
    good = S.analyze({"HttpOnly": True, "Secure": True, "SameSite": True})
    print(f"\n  {c['g']}With HttpOnly, Secure, and SameSite all set:{c['x']} {good['protected']} of 3 attacks closed.")


def _demo_tls(c):
    from . import tlscert as T
    for key in ["valid", "expired", "wrong_host", "self_signed"]:
        sc = T.SCENARIOS[key]
        r = T.validate(sc["cert"], sc["hostname"], T.TODAY)
        col = c['g'] if r["trusted"] else c['r']
        verdict = "trusted" if r["trusted"] else "warning shown"
        print(f"  {col}{verdict:>13}{c['x']}  {sc['label']}")
        for chk in r["checks"]:
            if not chk["ok"]:
                print(f"                 {c['d']}x {chk['name']}{c['x']}")


def _demo_traffic(c):
    from . import traffic as TR
    res = TR.detect_port_scan(TR.SAMPLE_LOG)
    print(f"  Reading a {len(TR.SAMPLE_LOG)} line connection log, grouped by source:\n")
    for row in res["rows"][:6]:
        mark = c['r'] + " <- scanning" + c['x'] if row["distinct_ports"] >= res["threshold"] else ""
        print(f"      {row['source']:<12} {row['distinct_ports']:>2} distinct ports{mark}")
    for s in res["scanners"]:
        print(f"\n  {c['r']}Port scan from {s['source']}{c['x']}: {s['distinct_ports']} ports on {s['target']}")
        print(f"      sample ports {c['d']}{s['sample_ports']}{c['x']}")


DEMOS = {
    "hashing": _demo_hashing, "strength": _demo_strength, "phish": _demo_phish,
    "sqli": _demo_sqli, "encoding": _demo_encoding, "headers": _demo_headers,
    "bruteforce": _demo_bruteforce, "sessions": _demo_sessions, "tls": _demo_tls,
    "traffic": _demo_traffic,
}


def cmd_learn(lesson_id: str, color: bool) -> int:
    lesson = BY_ID.get(lesson_id)
    if not lesson:
        print(f"manara: no lesson called {lesson_id!r}. Try: manara list", file=sys.stderr)
        return 2
    c = _color(color)
    _header(lesson, c)
    DEMOS[lesson_id](c)
    _footer(lesson, c)
    return 0


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="Plain text without colors.")
    p = argparse.ArgumentParser(prog="manara", parents=[common],
                                description="Learn cybersecurity by doing. Short hands on lessons, each with the defensive takeaway.")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("list", help="List the lessons.", parents=[common])
    lp = sub.add_parser("learn", help="Work through a lesson in the terminal.", parents=[common])
    lp.add_argument("lesson", help="The lesson id, for example hashing.")
    sv = sub.add_parser("serve", help="Open the lessons in a browser.", parents=[common])
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8100)
    sv.add_argument("--open", action="store_true")
    sub.add_parser("version", help="Print the version.", parents=[common])
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    color = (not args.no_color) and sys.stdout.isatty()
    if args.command == "version":
        print(f"manara {__version__}")
        return 0
    if args.command == "serve":
        return run_server(args.host, args.port, open_browser=args.open)
    if args.command == "learn":
        return cmd_learn(args.lesson, color)
    if args.command == "list" or args.command is None:
        return cmd_list(color)
    return 0
