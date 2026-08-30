# Changelog

## 0.3.0

Completes the web attack trio and makes each lesson self checking.

- New lesson, cross site request forgery, the third of the trio after SQL
  injection and cross site scripting. Watch a hidden form on an attacker's page
  make your bank transfer money using your own logged in session, then turn on a
  CSRF token or a SameSite cookie and watch the forged request get refused. It
  pays off the SameSite flag from the sessions lesson. No real requests are made.
- Every lesson now ends with a quick check, one or two questions drawn from the
  quiz bank, so you can test what you just saw without leaving the lesson.
- The full quiz grows to seventeen questions across all twelve lessons.

Twelve lessons in all. 63 tests pass. Still zero dependencies, still sandboxed
with no real attack tooling and no live targets.

## 0.2.0

Adds a keystone lesson and a way to check what you have learned.

- New lesson, cross site scripting. Post a comment to a guestbook and watch a
  script inside it run in a vulnerable page, then turn on escaping and watch the
  same comment become plain text. It is the sibling of the SQL injection lesson,
  and it ties together the Content Security Policy and HttpOnly cookie lessons as
  its defenses in depth. The danger is described and shown safely, never run.
- New quiz mode. Fifteen questions across all eleven lessons, with an
  explanation after every answer and a running score. In the browser it is one
  click from the lesson list; in the terminal it is manara quiz.

Eleven lessons in all, and the browser still remembers which you have finished.
Everything is sandboxed for learning, with no real attack tooling and no live
targets. 56 tests pass.

## 0.1.0

First release. Manara is a hands on cybersecurity learning tool: short lessons,
each pairing a plain explanation with an interactive exercise and a defensive
takeaway. It runs in the browser with nothing to install, and the same lessons
run offline as a zero dependency Python command line tool.

Ten lessons, a suggested path from fundamentals to applied topics: hashing and
passwords, password strength, brute force and rate limiting, encoding is not
encryption, spotting a phishing link, SQL injection in a safe sandbox, cookies
and sessions, security headers, TLS and certificates, and reading traffic for a
port scan. The browser version remembers which lessons you have completed.
