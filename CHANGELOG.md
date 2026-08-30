# Changelog

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
