# Changelog

## 0.1.0

First release. Manara is a hands on cybersecurity learning tool: short lessons,
each pairing a plain explanation with an interactive exercise and a defensive
takeaway. It runs in the browser with nothing to install, and the same lessons
run offline as a zero dependency Python command line tool.

Ten lessons, a suggested path from fundamentals to applied topics:

- Hashing and passwords, with a live salt versus no salt dictionary attack
- How strong is a password, entropy in bits and an honest crack time
- Brute force and rate limiting, and how a lockout changes the math
- Encoding is not encryption, base64 and Caesar and XOR reversed with no secret
- Spot the phish, reading a link apart to find where it truly goes
- SQL injection in a safe simulated sandbox, and how parameters end it
- Cookies and sessions, the flags that guard a session cookie
- Security headers, the browser defenses each response can set
- TLS and certificates, the three checks behind every certificate warning
- Reading traffic, spotting a port scan in a connection log by hand

The browser version remembers which lessons you have completed, on your device.
Everything is sandboxed for learning, with no real attack tooling and no live
targets. 44 tests pass.
