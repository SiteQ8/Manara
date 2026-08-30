"""The quiz: a short check of understanding across the lessons.

Each question names the lesson it comes from, offers a few options, marks the
correct one, and carries a one line explanation shown after answering. The
grader takes a list of chosen option indices, parallel to the question list, and
returns the score and which were right. Keeping the bank here makes it testable
and lets the same questions run in the terminal and the browser.
"""
from __future__ import annotations

from typing import Dict, List, Optional

# Each question: lesson id, prompt, options, index of the correct option, why.
QUESTIONS: List[Dict] = [
    {"lesson": "hashing",
     "q": "Why is storing a bare SHA256 of a password still risky?",
     "options": ["It can be decrypted with the right key",
                 "The same password always hashes the same, so common ones can be matched from a precomputed list",
                 "SHA256 is too slow to be practical",
                 "It cannot store long passwords"],
     "answer": 1,
     "why": "Hashes are deterministic, so identical passwords share a hash and a wordlist can be matched against many users at once."},
    {"lesson": "hashing",
     "q": "What does adding a per user salt achieve?",
     "options": ["It encrypts the password",
                 "It makes the hash shorter",
                 "It makes each hash unique, so a precomputed list must be redone for every user",
                 "It removes the need for a slow hash"],
     "answer": 2,
     "why": "A unique salt per user defeats precomputation, though a slow password hash is still needed to make each guess expensive."},
    {"lesson": "strength",
     "q": "Which password is strongest against guessing?",
     "options": ["A short one with symbols like P@ss1!",
                 "A long passphrase of several ordinary words",
                 "A common word with a number on the end",
                 "Anything with a capital letter"],
     "answer": 1,
     "why": "Length adds far more entropy than complexity, so a long passphrase beats a short scramble of symbols."},
    {"lesson": "bruteforce",
     "q": "How does a lockout after a few wrong tries help against brute force?",
     "options": ["It makes the secret longer",
                 "It encrypts the attempts",
                 "It slows the guess rate to a crawl and raises alarms",
                 "It hides the login page"],
     "answer": 2,
     "why": "Rate limiting changes the guesses per second, turning a fast attack into a slow, noisy one."},
    {"lesson": "encoding",
     "q": "Why is base64 not a way to keep something secret?",
     "options": ["It is too short",
                 "Anyone can decode it, since no key is needed",
                 "It only works on text",
                 "It changes every time"],
     "answer": 1,
     "why": "Encoding needs no secret to reverse, so it hides nothing. Only encryption with a key keeps data secret."},
    {"lesson": "phish",
     "q": "In http://paypal.com.secure-login.ru/verify, where does the link really go?",
     "options": ["paypal.com", "secure-login.ru", "verify", "It is safe because it says paypal"],
     "answer": 1,
     "why": "The real domain is the last two labels before the first slash, here secure-login.ru. The brand in front is decoration."},
    {"lesson": "phish",
     "q": "What is the safest habit when a link looks suspicious?",
     "options": ["Click it to check",
                 "Trust it if it uses https",
                 "Do not click; go to the site yourself",
                 "Forward it to a friend first"],
     "answer": 2,
     "why": "https only means encrypted, not trustworthy. When unsure, navigate to the site directly instead of clicking."},
    {"lesson": "sqli",
     "q": "Why does entering ' OR '1'='1 as a password bypass a naive login?",
     "options": ["It guesses the real password",
                 "It closes the string and adds an always true condition, so the query matches every row",
                 "It crashes the database",
                 "It is a known admin backdoor"],
     "answer": 1,
     "why": "The input breaks out of the string and changes the query's logic to something always true."},
    {"lesson": "sqli",
     "q": "What actually stops SQL injection?",
     "options": ["Filtering out bad words",
                 "Parameterized queries that treat input as data, never as query text",
                 "Hiding error messages",
                 "Using a longer password"],
     "answer": 1,
     "why": "Parameters send the query and the values separately, so input can never become part of the command."},
    {"lesson": "xss",
     "q": "What makes cross site scripting possible?",
     "options": ["A weak password",
                 "Input placed into a page without escaping, so markup in it runs",
                 "An expired certificate",
                 "A missing salt"],
     "answer": 1,
     "why": "Unescaped output lets a comment's script tag or event handler become part of the page and execute."},
    {"lesson": "xss",
     "q": "What is the primary fix for cross site scripting?",
     "options": ["Escape output for its context so input is shown as text",
                 "Rename the input fields",
                 "Use a faster server",
                 "Block all HTML forms"],
     "answer": 0,
     "why": "Escaping output turns markup into harmless text. A Content Security Policy and HttpOnly cookies are defense in depth."},
    {"lesson": "csrf",
     "q": "How does cross site request forgery make a bank act as you?",
     "options": ["It steals your password",
                 "The browser attaches your session cookie even to a request started by another site",
                 "It reads your screen",
                 "It guesses your session id"],
     "answer": 1,
     "why": "The browser sends your session cookie automatically, so a hidden form on another site can post as you."},
    {"lesson": "csrf",
     "q": "Which pair of defenses stops cross site request forgery?",
     "options": ["A longer password and a captcha",
                 "A secret CSRF token in your forms, and SameSite cookies",
                 "Hiding the transfer button",
                 "Encrypting the database"],
     "answer": 1,
     "why": "A CSRF token cannot be known by the attacker's page, and a SameSite cookie is not sent cross site at all."},
    {"lesson": "sessions",
     "q": "What does the HttpOnly flag on a session cookie prevent?",
     "options": ["The cookie being sent over http",
                 "Page scripts reading the cookie, blocking theft through cross site scripting",
                 "The user logging out",
                 "The cookie expiring"],
     "answer": 1,
     "why": "HttpOnly hides the cookie from JavaScript, so an XSS bug cannot steal the session."},
    {"lesson": "headers",
     "q": "Which header most directly limits where scripts may load from?",
     "options": ["Referrer-Policy", "Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"],
     "answer": 1,
     "why": "A Content Security Policy restricts script sources, the strongest header level defense against injected script."},
    {"lesson": "tls",
     "q": "A site's certificate is valid and unexpired but issued for another hostname. What should happen?",
     "options": ["The browser trusts it anyway",
                 "The browser warns, because identity is not proven for this site",
                 "It is fine as long as it is https",
                 "The connection is faster"],
     "answer": 1,
     "why": "A certificate for the wrong name proves nothing about this site, so the browser cannot trust the identity."},
    {"lesson": "traffic",
     "q": "In a connection log, what is the signature of a port scan?",
     "options": ["One source reaching many different ports or hosts in a short span",
                 "A single connection to port 443",
                 "Two users talking to the same server",
                 "A slow download"],
     "answer": 0,
     "why": "A scanner fans out across many ports or hosts. That spread, not any one connection, is the tell."},
]


def grade(answers: List[Optional[int]]) -> Dict:
    """Grade a list of chosen indices parallel to QUESTIONS.

    A None or out of range answer counts as wrong. Returns the score, total, and
    a per question breakdown with the correct index and explanation.
    """
    results = []
    correct = 0
    for i, q in enumerate(QUESTIONS):
        chosen = answers[i] if i < len(answers) else None
        ok = chosen == q["answer"]
        if ok:
            correct += 1
        results.append({"lesson": q["lesson"], "chosen": chosen, "answer": q["answer"],
                        "correct": ok, "why": q["why"]})
    return {"score": correct, "total": len(QUESTIONS), "results": results}


def by_lesson(lesson_id: str) -> List[Dict]:
    return [q for q in QUESTIONS if q["lesson"] == lesson_id]
