/* Manara browser lessons. Each lesson renders its own hands on widget.
   Everything runs in the browser; nothing is sent anywhere. */
(function () {
  "use strict";
  var VERSION = "0.2.0";
  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  }
  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  /* ---- shared logic, ported from the Python core ---- */
  async function sha256Hex(text) {
    var buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.prototype.map.call(new Uint8Array(buf),
      function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }
  var COMMON_PASSWORDS = ["123456", "password", "123456789", "12345678", "qwerty",
    "abc123", "111111", "iloveyou", "admin", "welcome", "monkey", "dragon",
    "letmein", "football", "sunshine", "princess", "password1", "hunter2"];

  var LOWER = /[a-z]/, UPPER = /[A-Z]/, DIGIT = /[0-9]/;
  function charsetSize(pw) {
    var pool = 0;
    if (LOWER.test(pw)) pool += 26;
    if (UPPER.test(pw)) pool += 26;
    if (DIGIT.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
    return pool;
  }
  function entropyBits(pw) {
    if (!pw) return 0;
    var pool = charsetSize(pw);
    return pool <= 1 ? 0 : pw.length * Math.log2(pool);
  }
  function humanTime(seconds) {
    if (!isFinite(seconds)) return "effectively forever";
    if (seconds < 1) return "less than a second";
    var units = [["year", 31536000], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
    var years = seconds / 31536000;
    if (years >= 1e12) return "trillions of years";
    if (years >= 1e9) return "billions of years";
    if (years >= 1e6) return "millions of years";
    if (years >= 1e3) return "thousands of years";
    for (var i = 0; i < units.length; i++) {
      if (seconds >= units[i][1]) {
        var v = Math.floor(seconds / units[i][1]);
        return v + " " + units[i][0] + (v !== 1 ? "s" : "");
      }
    }
    return "less than a second";
  }
  function strengthLabel(bits) {
    if (bits < 28) return ["very weak", "bad"];
    if (bits < 36) return ["weak", "bad"];
    if (bits < 60) return ["reasonable", "warn"];
    if (bits < 128) return ["strong", "good"];
    return ["very strong", "good"];
  }

  var BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "bank", "outlook", "office365", "dhl", "fedex"];
  var CONFUSABLE = { "0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t" };
  function regDomain(host) {
    var labels = host.split(".");
    return labels.length >= 2 ? labels.slice(-2).join(".") : host;
  }
  function isIp(host) {
    var p = host.split(".");
    if (p.length === 4 && p.every(function (x) { return /^\d+$/.test(x) && +x <= 255; })) return true;
    return host.indexOf(":") >= 0;
  }
  function analyzeUrl(url) {
    url = url.trim();
    var full = url.indexOf("://") >= 0 ? url : "http://" + url;
    var scheme = full.split("://", 1)[0].toLowerCase();
    var authority = full.split("://")[1].split("/", 1)[0];
    var host = authority.split("@").pop().split(":")[0].toLowerCase();
    var signals = [];
    function danger(t, d) { signals.push({ level: "danger", title: t, detail: d }); }
    function note(t, d) { signals.push({ level: "note", title: t, detail: d }); }
    if (authority.indexOf("@") >= 0) {
      var shown = authority.split("@")[0], real = authority.split("@")[1];
      danger("The part before the @ is ignored",
        "A browser sends you to what comes after the @ sign. Here that is " + (real || "the real host") +
        ", not " + (shown || "the text you see") + ".");
    }
    if (host.indexOf("xn--") >= 0)
      danger("Punycode in the domain",
        "xn-- marks a domain written in non Latin letters. It can render as a name that looks identical to a real one while pointing elsewhere.");
    if (isIp(host))
      danger("The address is a raw IP, not a name",
        "Real services almost always use a domain name. A bare IP address in a link is a common sign of something hiding.");
    var labels = host.split(".");
    if (labels.length >= 4)
      note("Many subdomains",
        "A long stack of subdomains can bury the real domain, which is always the last two labels, here " + regDomain(host) + ".");
    var reg = regDomain(host);
    for (var i = 0; i < BRANDS.length; i++) {
      if (host.indexOf(BRANDS[i]) >= 0 && reg.indexOf(BRANDS[i]) < 0) {
        danger("A brand name sits in the subdomain",
          "The name " + BRANDS[i] + " appears, but the real domain is " + reg + ", not " + BRANDS[i] +
          ". Anyone can put a brand in front of their own domain.");
        break;
      }
    }
    var stripped = host.replace(/\./g, "");
    outer: for (var b = 0; b < BRANDS.length; b++) {
      for (var d in CONFUSABLE) {
        var faked = BRANDS[b].split(CONFUSABLE[d]).join(d);
        if (faked !== BRANDS[b] && stripped.indexOf(faked) >= 0) {
          danger("A lookalike of a known brand",
            "This contains " + faked + ", a version of " + BRANDS[b] + " with a digit standing in for a letter to fool a quick glance.");
          break outer;
        }
      }
    }
    if (/[^\x00-\x7F]/.test(host))
      danger("Non standard characters in the domain",
        "The domain uses characters outside the plain Latin set, which can be chosen to look like ordinary letters.");
    if (scheme === "http")
      note("Not using https", "The link is plain http, so the connection is not encrypted. On its own this is not phishing, but sensitive sites should always use https.");
    var verdict = signals.some(function (s) { return s.level === "danger"; }) ? "suspicious" : "looks ok";
    return { registered_domain: reg, signals: signals, verdict: verdict };
  }

  var USERS = [["admin", "s3cr3t-admin-pw"], ["maryam", "correct horse battery"], ["khaled", "hunter2"]];
  function splitTop(clause, keyword) {
    var parts = [], buf = "", i = 0, inStr = false, up = clause.toUpperCase(), key = " " + keyword.toUpperCase() + " ";
    while (i < clause.length) {
      var ch = clause[i];
      if (ch === "'") { inStr = !inStr; buf += ch; i++; continue; }
      if (!inStr && up.substr(i, key.length) === key) { parts.push(buf); buf = ""; i += key.length; continue; }
      buf += ch; i++;
    }
    parts.push(buf);
    return parts;
  }
  function resolveTok(tok, row) {
    tok = tok.trim();
    if (tok.length >= 2 && tok[0] === "'" && tok[tok.length - 1] === "'") return tok.slice(1, -1);
    if (tok in row) return row[tok];
    return tok;
  }
  function evalAtom(atom, row) {
    atom = atom.trim().replace(/^\(+|\)+$/g, "").trim();
    if (atom.indexOf("=") < 0) return false;
    var idx = atom.indexOf("="), left = atom.slice(0, idx), right = atom.slice(idx + 1);
    return resolveTok(left, row) === resolveTok(right, row);
  }
  function evalWhere(clause, row) {
    var ors = splitTop(clause, "OR");
    for (var i = 0; i < ors.length; i++) {
      var ands = splitTop(ors[i], "AND");
      if (ands.every(function (a) { return evalAtom(a, row); })) return true;
    }
    return false;
  }
  function vulnerableLogin(u, p) {
    var query = "SELECT * FROM users WHERE username='" + u + "' AND password='" + p + "'";
    var where = query.split(" WHERE ")[1];
    var matched = USERS.filter(function (r) { return evalWhere(where, { username: r[0], password: r[1] }); });
    return { query: query, granted: matched.length > 0, matched: matched };
  }
  function safeLogin(u, p) {
    var granted = USERS.some(function (r) { return r[0] === u && r[1] === p; });
    return { query: "SELECT * FROM users WHERE username=? AND password=?", params: [u, p], granted: granted };
  }

  function b64e(s) { return btoa(unescape(encodeURIComponent(s))); }
  function b64d(s) { try { return decodeURIComponent(escape(atob(s))); } catch (e) { return "(not valid base64)"; } }
  var ALPHA = "abcdefghijklmnopqrstuvwxyz";
  function caesar(text, shift) {
    return text.replace(/[a-z]/gi, function (ch) {
      var low = ch.toLowerCase(), idx = ALPHA.indexOf(low);
      if (idx < 0) return ch;
      var nc = ALPHA[(idx + shift % 26 + 26) % 26];
      return ch === ch.toUpperCase() ? nc.toUpperCase() : nc;
    });
  }
  function xorHex(text, key) {
    var out = "";
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i) ^ (key.length ? key.charCodeAt(i % key.length) : 0);
      out += c.toString(16).padStart(2, "0");
    }
    return out;
  }

  var HEADERS = {
    "Content-Security-Policy": ["Lists exactly where scripts, styles, and other content may load from.",
      "Cross site scripting, where injected script runs in your page.", "default-src 'self'"],
    "X-Content-Type-Options": ["Tells the browser to trust the declared content type and not guess.",
      "MIME sniffing, where a file is treated as script because the browser guessed.", "nosniff"],
    "X-Frame-Options": ["Controls whether your page may be placed inside a frame.",
      "Clickjacking, where your page is framed invisibly over a decoy.", "DENY"],
    "Strict-Transport-Security": ["Forces every future visit to use https, even if a link says http.",
      "Downgrade and interception on a plain http request.", "max-age=63072000; includeSubDomains"],
    "Referrer-Policy": ["Limits how much of your URL is sent when a user follows a link away.",
      "Leaking paths and query strings, which can hold tokens, to other sites.", "strict-origin-when-cross-origin"]
  };

  function simulatePin(secret, lockoutAfter, lockoutSeconds, gps) {
    var width = secret.length, space = Math.pow(10, width), tries = 0;
    for (var n = 0; n < space; n++) { tries++; if (String(n).padStart(width, "0") === secret) break; }
    var noLimit = tries / gps;
    var withLockout = null;
    if (lockoutAfter) withLockout = tries / gps + Math.floor((tries - 1) / lockoutAfter) * lockoutSeconds;
    return { width: width, space: space, tries: tries, noLimit: noLimit, withLockout: withLockout };
  }

  function analyzeSession(flags) {
    var httpOnly = !!flags.HttpOnly, secure = !!flags.Secure, sameSite = !!flags.SameSite;
    var risks = [], safe = [];
    (httpOnly ? safe : risks).push(httpOnly
      ? { title: "Hidden from page scripts", detail: "HttpOnly is set, so page scripts cannot read the cookie, which blocks theft through cross site scripting." }
      : { title: "Readable by page scripts", detail: "Without HttpOnly, any script on the page can read the cookie. A single cross site scripting bug then hands the whole session to an attacker." });
    (secure ? safe : risks).push(secure
      ? { title: "Sent only over https", detail: "Secure is set, so the cookie is only ever sent over https and cannot be sniffed in the clear." }
      : { title: "Sent over plain http", detail: "Without Secure, the cookie rides along on any plain http request, where anyone on the network path can read it." });
    (sameSite ? safe : risks).push(sameSite
      ? { title: "Held back on cross site requests", detail: "SameSite is set, so the cookie is not sent on requests started by other sites, which blocks cross site request forgery." }
      : { title: "Sent on cross site requests", detail: "Without SameSite, the browser attaches the cookie even to requests started by another site, which is what makes cross site request forgery work." });
    return { risks: risks, safe: safe, exposure: risks.length, protected: safe.length };
  }

  var TRUSTED_CAS = ["Example Trust CA", "Global Root CA", "Lets Encrypt Authority"];
  function hostMatches(pattern, hostname) {
    pattern = pattern.toLowerCase(); hostname = hostname.toLowerCase();
    if (pattern === hostname) return true;
    if (pattern.indexOf("*.") === 0) {
      var base = pattern.slice(2), parts = hostname.split(/\.(.+)/);
      return parts.length >= 2 && parts[1] === base;
    }
    return false;
  }
  function validateCert(cert, hostname, today) {
    var checks = [];
    var notExpired = cert.valid_from <= today && today <= cert.valid_to;
    checks.push({ name: "Within its validity dates", ok: notExpired,
      note: notExpired ? "Valid from " + cert.valid_from + " to " + cert.valid_to + "."
        : "Today is " + today + ", outside " + cert.valid_from + " to " + cert.valid_to + ". An expired certificate is no longer trusted." });
    var hostOk = hostMatches(cert.subject, hostname);
    checks.push({ name: "Issued for this hostname", ok: hostOk,
      note: hostOk ? "The certificate names " + cert.subject + ", which matches " + hostname + "."
        : "The certificate names " + cert.subject + ", but you connected to " + hostname + ". A certificate for the wrong name proves nothing about this site." });
    var trustedIssuer = (!cert.self_signed) && TRUSTED_CAS.indexOf(cert.issuer) >= 0;
    var issuerNote = cert.self_signed ? "The certificate signed itself. Anyone can make one, so it proves no independent identity."
      : trustedIssuer ? "Signed by " + cert.issuer + ", a trusted authority."
      : "Signed by " + cert.issuer + ", which is not a trusted authority, so the chain of trust is broken.";
    checks.push({ name: "Signed by a trusted authority", ok: trustedIssuer, note: issuerNote });
    return { hostname: hostname, subject: cert.subject, checks: checks, trusted: checks.every(function (c) { return c.ok; }) };
  }
  var CERT_SCENARIOS = {
    valid: { label: "A normal, valid certificate", hostname: "shop.example.com",
      cert: { subject: "shop.example.com", issuer: "Lets Encrypt Authority", valid_from: "2025-01-01", valid_to: "2026-06-01", self_signed: false } },
    expired: { label: "An expired certificate", hostname: "shop.example.com",
      cert: { subject: "shop.example.com", issuer: "Lets Encrypt Authority", valid_from: "2023-01-01", valid_to: "2024-01-01", self_signed: false } },
    wrong_host: { label: "A certificate for the wrong site", hostname: "shop.example.com",
      cert: { subject: "other-site.com", issuer: "Global Root CA", valid_from: "2025-01-01", valid_to: "2026-06-01", self_signed: false } },
    self_signed: { label: "A self signed certificate", hostname: "shop.example.com",
      cert: { subject: "shop.example.com", issuer: "shop.example.com", valid_from: "2025-01-01", valid_to: "2026-06-01", self_signed: true } }
  };
  var CERT_TODAY = "2025-09-01";

  var SAMPLE_LOG = [
    ["10.0.0.5", "10.0.0.20", 443], ["10.0.0.5", "10.0.0.20", 443],
    ["10.0.0.7", "10.0.0.20", 80], ["10.0.0.7", "10.0.0.21", 443],
    ["10.0.0.9", "10.0.0.20", 443]
  ];
  [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443].forEach(function (p) {
    SAMPLE_LOG.push(["10.0.0.66", "10.0.0.20", p]);
  });
  SAMPLE_LOG.push(["10.0.0.8", "10.0.0.21", 443]);
  function summarizeLog(log) {
    var by = {};
    log.forEach(function (r) {
      var e = by[r[0]] || (by[r[0]] = { source: r[0], ports: {}, hosts: {}, connections: 0 });
      e.ports[r[2]] = 1; e.hosts[r[1]] = 1; e.connections++;
    });
    var rows = Object.keys(by).map(function (k) {
      var e = by[k];
      return { source: e.source, distinct_ports: Object.keys(e.ports).length,
        distinct_hosts: Object.keys(e.hosts).length, connections: e.connections,
        ports: Object.keys(e.ports).map(Number).sort(function (a, b) { return a - b; }) };
    });
    rows.sort(function (a, b) { return b.distinct_ports - a.distinct_ports; });
    return rows;
  }
  function detectPortScan(log, threshold) {
    threshold = threshold || 15;
    var rows = summarizeLog(log), scanners = [];
    rows.forEach(function (r) {
      if (r.distinct_ports >= threshold)
        scanners.push({ source: r.source, distinct_ports: r.distinct_ports,
          target: r.distinct_hosts === 1 ? "a single host" : null, sample_ports: r.ports.slice(0, 12) });
    });
    return { rows: rows, scanners: scanners, threshold: threshold };
  }

  var XSS_TRIGGERS = [
    [/<script/i, "a <script> block, which runs immediately"],
    [/on\w+\s*=/i, "an inline event handler such as onerror or onload, which runs on the element"],
    [/javascript:/i, "a javascript: URL, which runs when followed"],
    [/<iframe/i, "an injected iframe, which can load hostile content"]
  ];
  function escapeHtml(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function xssTriggers(comment) {
    var hits = [];
    XSS_TRIGGERS.forEach(function (t) { if (t[0].test(comment)) hits.push(t[1]); });
    return hits;
  }
  function renderUnsafe(comment) {
    var t = xssTriggers(comment);
    return { inserted: comment, would_execute: t.length > 0, triggers: t, safe: false };
  }
  function renderSafe(comment) {
    return { inserted: escapeHtml(comment), would_execute: false, triggers: [], safe: true };
  }

  var QUIZ = [
    { lesson: "hashing", q: "Why is storing a bare SHA256 of a password still risky?",
      options: ["It can be decrypted with the right key", "The same password always hashes the same, so common ones can be matched from a precomputed list", "SHA256 is too slow to be practical", "It cannot store long passwords"],
      answer: 1, why: "Hashes are deterministic, so identical passwords share a hash and a wordlist can be matched against many users at once." },
    { lesson: "hashing", q: "What does adding a per user salt achieve?",
      options: ["It encrypts the password", "It makes the hash shorter", "It makes each hash unique, so a precomputed list must be redone for every user", "It removes the need for a slow hash"],
      answer: 2, why: "A unique salt per user defeats precomputation, though a slow password hash is still needed to make each guess expensive." },
    { lesson: "strength", q: "Which password is strongest against guessing?",
      options: ["A short one with symbols like P@ss1!", "A long passphrase of several ordinary words", "A common word with a number on the end", "Anything with a capital letter"],
      answer: 1, why: "Length adds far more entropy than complexity, so a long passphrase beats a short scramble of symbols." },
    { lesson: "bruteforce", q: "How does a lockout after a few wrong tries help against brute force?",
      options: ["It makes the secret longer", "It encrypts the attempts", "It slows the guess rate to a crawl and raises alarms", "It hides the login page"],
      answer: 2, why: "Rate limiting changes the guesses per second, turning a fast attack into a slow, noisy one." },
    { lesson: "encoding", q: "Why is base64 not a way to keep something secret?",
      options: ["It is too short", "Anyone can decode it, since no key is needed", "It only works on text", "It changes every time"],
      answer: 1, why: "Encoding needs no secret to reverse, so it hides nothing. Only encryption with a key keeps data secret." },
    { lesson: "phish", q: "In http://paypal.com.secure-login.ru/verify, where does the link really go?",
      options: ["paypal.com", "secure-login.ru", "verify", "It is safe because it says paypal"],
      answer: 1, why: "The real domain is the last two labels before the first slash, here secure-login.ru. The brand in front is decoration." },
    { lesson: "phish", q: "What is the safest habit when a link looks suspicious?",
      options: ["Click it to check", "Trust it if it uses https", "Do not click; go to the site yourself", "Forward it to a friend first"],
      answer: 2, why: "https only means encrypted, not trustworthy. When unsure, navigate to the site directly instead of clicking." },
    { lesson: "sqli", q: "Why does entering ' OR '1'='1 as a password bypass a naive login?",
      options: ["It guesses the real password", "It closes the string and adds an always true condition, so the query matches every row", "It crashes the database", "It is a known admin backdoor"],
      answer: 1, why: "The input breaks out of the string and changes the query's logic to something always true." },
    { lesson: "sqli", q: "What actually stops SQL injection?",
      options: ["Filtering out bad words", "Parameterized queries that treat input as data, never as query text", "Hiding error messages", "Using a longer password"],
      answer: 1, why: "Parameters send the query and the values separately, so input can never become part of the command." },
    { lesson: "xss", q: "What makes cross site scripting possible?",
      options: ["A weak password", "Input placed into a page without escaping, so markup in it runs", "An expired certificate", "A missing salt"],
      answer: 1, why: "Unescaped output lets a comment's script tag or event handler become part of the page and execute." },
    { lesson: "xss", q: "What is the primary fix for cross site scripting?",
      options: ["Escape output for its context so input is shown as text", "Rename the input fields", "Use a faster server", "Block all HTML forms"],
      answer: 0, why: "Escaping output turns markup into harmless text. A Content Security Policy and HttpOnly cookies are defense in depth." },
    { lesson: "sessions", q: "What does the HttpOnly flag on a session cookie prevent?",
      options: ["The cookie being sent over http", "Page scripts reading the cookie, blocking theft through cross site scripting", "The user logging out", "The cookie expiring"],
      answer: 1, why: "HttpOnly hides the cookie from JavaScript, so an XSS bug cannot steal the session." },
    { lesson: "headers", q: "Which header most directly limits where scripts may load from?",
      options: ["Referrer-Policy", "Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"],
      answer: 1, why: "A Content Security Policy restricts script sources, the strongest header level defense against injected script." },
    { lesson: "tls", q: "A site's certificate is valid and unexpired but issued for another hostname. What should happen?",
      options: ["The browser trusts it anyway", "The browser warns, because identity is not proven for this site", "It is fine as long as it is https", "The connection is faster"],
      answer: 1, why: "A certificate for the wrong name proves nothing about this site, so the browser cannot trust the identity." },
    { lesson: "traffic", q: "In a connection log, what is the signature of a port scan?",
      options: ["One source reaching many different ports or hosts in a short span", "A single connection to port 443", "Two users talking to the same server", "A slow download"],
      answer: 0, why: "A scanner fans out across many ports or hosts. That spread, not any one connection, is the tell." }
  ];
  function gradeQuiz(answers) {
    var correct = 0, results = [];
    QUIZ.forEach(function (q, i) {
      var chosen = i < answers.length ? answers[i] : null;
      var ok = chosen === q.answer;
      if (ok) correct++;
      results.push({ lesson: q.lesson, chosen: chosen, answer: q.answer, correct: ok, why: q.why });
    });
    return { score: correct, total: QUIZ.length, results: results };
  }

  /* ---- lessons ---- */
  var LESSONS = [
    {
      id: "hashing", n: "Lesson 1", title: "Hashing and passwords",
      summary: "Why storing a hash helps, why identical passwords hashing alike hurts, and what salt fixes.",
      explain: "A hash turns a password into a fixed fingerprint that cannot be reversed directly. Storing the hash instead of the password means a stolen database does not immediately hand over everyone's password. But the same password always produces the same hash, so an attacker can hash a list of common passwords once and match them against the stolen hashes. A salt, a random value stored with each user, makes every hash unique even for identical passwords, so that precomputation no longer works. A slow hash built for passwords, such as bcrypt, scrypt, or Argon2, then makes each try expensive.",
      takeaway: "Store passwords with a slow, salted password hash such as bcrypt, scrypt, or Argon2. Never a bare MD5 or SHA256, and never the password itself.",
      render: function (root) {
        root.appendChild(el("h4", null, "Type a password and watch it hash"));
        root.appendChild(el("p", "hint", "Try a common one like password or hunter2, then press crack it."));
        var inp = el("input"); inp.type = "text"; inp.value = "hunter2"; root.appendChild(inp);
        var out = el("div", "out"); root.appendChild(out);
        var salt = "";
        var controls = el("div", "row");
        var crackBtn = el("button", "btn primary small", "Crack it with a wordlist");
        var saltBtn = el("button", "btn small", "Add a salt");
        controls.appendChild(crackBtn); controls.appendChild(saltBtn); root.appendChild(controls);
        var result = el("div", "out"); root.appendChild(result);
        async function refresh() {
          var pw = inp.value;
          var h = await sha256Hex(pw);
          var sh = salt ? await sha256Hex(salt + pw) : null;
          out.innerHTML = "<div class='kv'>sha256 of your password</div>" +
            "<div class='hashline'>" + esc(h) + "</div>" +
            "<div class='kv'>anyone else typing the same password gets the very same hash</div>" +
            (salt ? "<div class='kv' style='margin-top:10px'>with the salt <b>" + esc(salt) + "</b> stored for this user</div><div class='hashline'>" + esc(sh) + "</div>" : "");
        }
        crackBtn.onclick = async function () {
          var pw = inp.value;
          var target = salt ? await sha256Hex(salt + pw) : await sha256Hex(pw);
          var found = null, attempts = COMMON_PASSWORDS.length;
          for (var i = 0; i < COMMON_PASSWORDS.length; i++) {
            var g = salt ? await sha256Hex(salt + COMMON_PASSWORDS[i]) : await sha256Hex(COMMON_PASSWORDS[i]);
            if (g === target) { found = COMMON_PASSWORDS[i]; attempts = i + 1; break; }
          }
          if (found) result.innerHTML = "<span class='pill bad'>cracked</span> found <b>" + esc(found) + "</b> in " + attempts + " tries against an " + COMMON_PASSWORDS.length + " word list.";
          else result.innerHTML = "<span class='pill good'>survived</span> the " + COMMON_PASSWORDS.length + " word list found nothing" + (salt ? ", because the attacker does not have this user's salt." : ".");
        };
        saltBtn.onclick = function () {
          if (salt) { salt = ""; saltBtn.textContent = "Add a salt"; }
          else { salt = Math.random().toString(16).slice(2, 10); saltBtn.textContent = "Remove the salt"; }
          result.innerHTML = ""; refresh();
        };
        inp.oninput = function () { result.innerHTML = ""; refresh(); };
        refresh();
      }
    },
    {
      id: "strength", n: "Lesson 2", title: "How strong is a password",
      summary: "Measure a password in bits of entropy and see why length beats complexity.",
      explain: "Password strength is not about symbols and capital letters, it is about how many equally likely possibilities an attacker must search. That number is entropy, measured in bits, and each extra bit doubles the work. Length adds bits far faster than complexity does, which is why a long passphrase of ordinary words beats a short scramble of symbols. The catch is that these estimates assume every character is random; a password built from a common word has far less real entropy, because an attacker guesses words, not characters.",
      takeaway: "Favor length over complexity. A long unique passphrase, kept in a password manager and paired with two factor authentication, beats a short clever one.",
      render: function (root) {
        root.appendChild(el("h4", null, "Build a password and watch the strength"));
        root.appendChild(el("p", "hint", "Compare a short complex one against a long passphrase."));
        var inp = el("input"); inp.type = "text"; inp.value = "P@ss1!"; root.appendChild(inp);
        var meter = el("div", "meter"); var bar = el("span"); meter.appendChild(bar); root.appendChild(meter);
        var out = el("div", "out"); root.appendChild(out);
        var presets = el("div", "row");
        [["P@ss1!", "short + complex"], ["correct horse battery staple", "long passphrase"], ["Tr0ub4dour&3", "the famous one"]].forEach(function (p) {
          var b = el("button", "btn small", esc(p[1])); b.onclick = function () { inp.value = p[0]; refresh(); }; presets.appendChild(b);
        });
        root.appendChild(presets);
        function refresh() {
          var pw = inp.value, bits = entropyBits(pw), lab = strengthLabel(bits);
          var gps = 1e11, secs = isFinite(bits) ? Math.pow(2, bits) / 2 / gps : Infinity;
          var pct = Math.min(100, bits / 128 * 100);
          var col = lab[1] === "good" ? "var(--green)" : lab[1] === "warn" ? "var(--yellow)" : "var(--red)";
          bar.style.width = pct + "%"; bar.style.background = col;
          out.innerHTML = "<div><span class='big-num'>" + bits.toFixed(0) + "</span> bits of entropy &middot; <span class='pill " + lab[1] + "'>" + lab[0] + "</span></div>" +
            "<div class='kv' style='margin-top:8px'>length " + pw.length + ", drawing from a pool of " + charsetSize(pw) + " characters</div>" +
            "<div class='kv'>an offline attacker at 100 billion guesses per second would need about <b>" + humanTime(secs) + "</b></div>";
        }
        inp.oninput = refresh; refresh();
      }
    },
    {
      id: "phish", n: "Lesson 3", title: "Spot the phish",
      summary: "Read a link the way an attacker hopes you will not, and find where it really goes.",
      explain: "A phishing link works by looking like one thing and leading to another. The single most useful habit is to find the real domain, which is always the last two labels before the first single slash, and ignore everything dressed up around it. Attackers pad links with a trusted brand in a subdomain, swap letters for lookalike digits or foreign characters, hide the true host after an @ sign, or use a raw IP address. None of these change where you land, only how the link reads at a glance.",
      takeaway: "Read a link from the right. Find the real domain, the last two labels before the first slash, and do not trust the rest. When unsure, do not click; go to the site yourself.",
      render: function (root) {
        root.appendChild(el("h4", null, "Paste a link, or try one of these"));
        var inp = el("input"); inp.type = "text"; inp.value = "http://paypal.com.secure-login.ru/verify"; root.appendChild(inp);
        var ex = el("div", "row");
        ["https://www.paypal.com/account", "http://paypal.com.secure-login.ru/verify", "https://paypa1.com/login", "http://you@192.168.0.5/reset"].forEach(function (u) {
          var b = el("button", "btn small", esc(u.length > 34 ? u.slice(0, 32) + "..." : u)); b.onclick = function () { inp.value = u; refresh(); }; ex.appendChild(b);
        });
        root.appendChild(ex);
        var out = el("div", "out"); root.appendChild(out);
        function refresh() {
          var r = analyzeUrl(inp.value);
          var pill = r.verdict === "suspicious" ? "<span class='pill bad'>suspicious</span>" : "<span class='pill good'>looks ok</span>";
          var h = "<div>" + pill + " &nbsp; the link really goes to <b class='mono'>" + esc(r.registered_domain) + "</b></div>";
          r.signals.forEach(function (s) {
            h += "<div class='sig " + s.level + "'><div class='t'>" + esc(s.title) + "</div><div class='d'>" + esc(s.detail) + "</div></div>";
          });
          if (!r.signals.length) h += "<div class='kv' style='margin-top:10px'>No deception signals found.</div>";
          out.innerHTML = h;
        }
        inp.oninput = refresh; refresh();
      }
    },
    {
      id: "sqli", n: "Lesson 4", title: "SQL injection, safely",
      summary: "See why building a query from input is dangerous, and why parameters end it.",
      explain: "When an application builds a database query by pasting user input into the text of the query, the input can break out of where it was meant to sit and change what the query does. The classic login example is to enter, as the password, a quote to close the string and then a condition that is always true. The database now sees a WHERE clause that always passes. The fix is not to filter bad words, it is to never build queries by pasting. Parameterized queries send the query and the values separately, so input is always data and can never become part of the command.",
      takeaway: "Never build a query by concatenating input. Use parameterized queries, also called prepared statements, so input is always data and never code.",
      render: function (root) {
        root.appendChild(el("h4", null, "A pretend login over a tiny users table"));
        root.appendChild(el("p", "hint", "This is a simulation, not a real database. Try the injection button as the password."));
        var u = el("input"); u.type = "text"; u.value = "admin";
        var p = el("input"); p.type = "text"; p.value = "' OR '1'='1";
        root.appendChild(el("label", "fl", "username")); root.appendChild(u);
        root.appendChild(el("label", "fl", "password")); root.appendChild(p);
        var row = el("div", "row");
        var mode = el("select");
        mode.appendChild(el("option", null, "vulnerable: builds the query from input")); mode.children[0].value = "vuln";
        mode.appendChild(el("option", null, "safe: parameterized query")); mode.children[1].value = "safe";
        var payload = el("button", "btn small", "Use the classic injection");
        var go = el("button", "btn primary small", "Try to log in");
        row.appendChild(mode); row.appendChild(payload); row.appendChild(go); root.appendChild(row);
        var out = el("div", "out"); root.appendChild(out);
        payload.onclick = function () { p.value = "' OR '1'='1"; };
        go.onclick = function () {
          var r = mode.value === "safe" ? safeLogin(u.value, p.value) : vulnerableLogin(u.value, p.value);
          var q = mode.value === "safe" ? esc(r.query) + "  <span class='kv'>params = [" + r.params.map(function (x) { return "'" + esc(x) + "'"; }).join(", ") + "]</span>" : esc(r.query);
          var grant = r.granted ? "<span class='grant yes'>access granted</span>" : "<span class='grant no'>access denied</span>";
          var extra = "";
          if (mode.value !== "safe" && r.granted && r.matched.length === USERS.length) extra = " <span class='kv'>every row matched, so the whole users table just leaked</span>";
          out.innerHTML = "<div class='kv'>the query that ran</div><div class='hashline'>" + q + "</div><div>" + grant + extra + "</div>";
        };
        go.onclick();
      }
    },
    {
      id: "encoding", n: "Lesson 5", title: "Encoding is not encryption",
      summary: "base64, Caesar, and XOR all reverse without a secret, so they hide nothing.",
      explain: "Encoding changes how data is written so it can travel safely, and obfuscation scrambles it so it is not obvious at a glance. Neither is encryption, because neither needs a secret to undo. base64 is just a way to write bytes with a safe alphabet, and anyone can decode it. A Caesar shift and a XOR against a known key reverse the moment the method is known. Encryption is different in one essential way: without the key, undoing it is infeasible even when the method is fully public. If there is no key, there is no secrecy.",
      takeaway: "base64, hex, and simple XOR are not security. If data must stay secret, encrypt it with a real algorithm and a real key, such as AES or the tools in a vetted library.",
      render: function (root) {
        root.appendChild(el("h4", null, "Scramble some text, then watch it come right back"));
        var inp = el("textarea"); inp.value = "attack at dawn"; root.appendChild(inp);
        var row = el("div", "row");
        var method = el("select");
        [["base64", "base64"], ["caesar", "Caesar shift 3"], ["xor", "XOR with key 'key'"]].forEach(function (m, i) {
          var o = el("option", null, m[1]); o.value = m[0]; method.appendChild(o);
        });
        row.appendChild(method); root.appendChild(row);
        var out = el("div", "out"); root.appendChild(out);
        function refresh() {
          var t = inp.value, enc, dec, label;
          if (method.value === "base64") { enc = b64e(t); dec = b64d(enc); label = "base64"; }
          else if (method.value === "caesar") { enc = caesar(t, 3); dec = caesar(enc, -3); label = "Caesar +3, undone with -3"; }
          else { enc = xorHex(t, "key"); dec = (function () { var raw = enc.match(/.{2}/g) || []; return raw.map(function (h, i) { return String.fromCharCode(parseInt(h, 16) ^ "key".charCodeAt(i % 3)); }).join(""); })(); label = "XOR 'key', undone with the same key"; }
          out.innerHTML = "<div class='kv'>" + esc(label) + "</div><div class='hashline'>" + esc(enc) + "</div>" +
            "<div class='kv'>reversed with no secret, just the method</div><div class='hashline'>" + esc(dec) + "</div>" +
            "<div style='margin-top:8px'><span class='pill warn'>not secret</span> anyone who sees the output can undo it</div>";
        }
        inp.oninput = refresh; method.onchange = refresh; refresh();
      }
    },
    {
      id: "headers", n: "Lesson 6", title: "Security headers",
      summary: "Flip the browser security headers and see which attack each one blocks.",
      explain: "A web server can send a handful of response headers that tell the browser how to protect the page. They cost nothing and each one closes a specific door. A Content Security Policy limits where scripts may come from. nosniff stops the browser guessing a file into something dangerous. Frame options stop your page being used in a clickjacking overlay. Strict transport security pins the site to https. A referrer policy stops your URLs, which may carry tokens, leaking to other sites. Missing headers are not a breach by themselves, they are removed safety nets.",
      takeaway: "Set the security headers on every response. They are cheap, they break little, and each one removes a whole class of browser side attack.",
      render: function (root) {
        root.appendChild(el("h4", null, "Toggle each header on your imaginary response"));
        var meter = el("div", "meter"); var bar = el("span"); meter.appendChild(bar); root.appendChild(meter);
        var pctline = el("div", "out"); root.appendChild(pctline);
        var box = el("div"); root.appendChild(box);
        var state = {};
        Object.keys(HEADERS).forEach(function (name) {
          state[name] = false;
          var wrap = el("label", "chk");
          var cb = el("input"); cb.type = "checkbox";
          cb.onchange = function () { state[name] = cb.checked; refresh(); };
          var txt = el("div");
          txt.appendChild(el("div", "t", "<b class='mono'>" + esc(name) + "</b>"));
          txt.appendChild(el("div", "d", esc(HEADERS[name][0]) + " Blocks " + esc(HEADERS[name][1])));
          wrap.appendChild(cb); wrap.appendChild(txt); box.appendChild(wrap);
        });
        function refresh() {
          var on = Object.keys(state).filter(function (k) { return state[k]; });
          var pct = Math.round(100 * on.length / Object.keys(HEADERS).length);
          bar.style.width = pct + "%";
          bar.style.background = pct >= 100 ? "var(--green)" : pct >= 40 ? "var(--yellow)" : "var(--red)";
          pctline.innerHTML = "<span class='big-num'>" + pct + "%</span> protected &middot; " + on.length + " of " + Object.keys(HEADERS).length + " headers set";
        }
        refresh();
      }
    },
    {
      id: "bruteforce", n: "Lesson 7", title: "Brute force and rate limiting",
      summary: "Turn a secret and a guess rate into a time, then watch a lockout change it.",
      explain: "A brute force attack simply tries every possibility. Whether that is hopeless or trivial depends on two numbers: how many possibilities there are, and how many the attacker can try each second. A four digit PIN is only ten thousand possibilities, which falls in seconds if guessing is unlimited. Rate limiting changes the second number. If the system refuses further tries for several minutes after a few wrong ones, the same PIN now takes days or years, and the attacker is loud while trying.",
      takeaway: "Limit and slow failed attempts, and lock out after a few. Rate limiting can make even a short secret impractical to guess, and it makes attacks visible.",
      render: function (root) {
        root.appendChild(el("h4", null, "Pick a PIN and let an attacker guess it"));
        root.appendChild(el("p", "hint", "The attacker guesses in order at ten tries per second."));
        var inp = el("input"); inp.type = "text"; inp.value = "7391"; inp.maxLength = 6; root.appendChild(inp);
        var row = el("div", "row");
        var lockCb = el("label", "chk");
        var cb = el("input"); cb.type = "checkbox"; cb.checked = true;
        var t = el("div"); t.appendChild(el("div", "t", "Lock out for 5 minutes after 3 wrong tries"));
        lockCb.appendChild(cb); lockCb.appendChild(t);
        row.appendChild(lockCb); root.appendChild(row);
        var go = el("button", "btn primary small", "Run the attack"); go.style.marginTop = "12px"; root.appendChild(go);
        var out = el("div", "out"); root.appendChild(out);
        go.onclick = function () {
          var pin = inp.value.replace(/\D/g, "") || "0000";
          var r = simulatePin(pin, cb.checked ? 3 : null, 300, 10);
          var noLimit = humanTime(Math.pow(10, r.width) / 2 / 10);
          var h = "<div class='kv'>a " + r.width + " digit PIN is <b>" + r.space.toLocaleString() + "</b> possibilities</div>" +
            "<div style='margin-top:8px'>guessing in order found <b>" + esc(pin) + "</b> in " + r.tries.toLocaleString() + " tries</div>" +
            "<div style='margin-top:10px'><span class='pill bad'>no limit</span> worst case about <b>" + noLimit + "</b> at ten per second</div>";
          if (r.withLockout != null) h += "<div style='margin-top:8px'><span class='pill good'>with lockout</span> now about <b>" + humanTime(r.withLockout) + "</b>, and thousands of alarms raised</div>";
          out.innerHTML = h;
        };
        go.onclick();
      }
    },
    {
      id: "xss", n: "Lesson 7", title: "Cross site scripting",
      summary: "Watch a comment break into a page and run, then watch escaping turn it into plain text.",
      explain: "Cross site scripting is SQL injection's sibling. There, input broke into a database query; here, input breaks into the HTML of a page. When a site takes something a user typed, a comment, a name, a search term, and drops it into the page without escaping, any markup in it becomes part of the page. A comment containing a script tag or an event handler then runs in every visitor's browser, where it can read their session cookie or act as them. The fix is the same shape as before: treat input as data. Escape it for the place it is going, so a script tag becomes the visible text of a script tag and never executes. A Content Security Policy and an HttpOnly cookie, from the earlier lessons, are the defenses in depth behind that.",
      takeaway: "Escape output for its context, or use a framework that does it by default, so user input is never treated as markup. Add a Content Security Policy and HttpOnly cookies as defense in depth.",
      render: function (root) {
        root.appendChild(el("h4", null, "Post a comment to a guestbook"));
        root.appendChild(el("p", "hint", "This safely shows what would happen; injected script is described, never run."));
        var inp = el("textarea"); inp.value = "<script>fetch('/steal?c='+document.cookie)</script>"; root.appendChild(inp);
        var row = el("div", "row");
        var mode = el("select");
        var o1 = el("option", null, "vulnerable: inserts your comment as raw HTML"); o1.value = "vuln";
        var o2 = el("option", null, "safe: escapes your comment first"); o2.value = "safe";
        mode.appendChild(o1); mode.appendChild(o2);
        var samples = el("button", "btn small", "Try an attack payload");
        var go = el("button", "btn primary small", "Post comment");
        row.appendChild(mode); row.appendChild(samples); row.appendChild(go); root.appendChild(row);
        var out = el("div", "out"); root.appendChild(out);
        samples.onclick = function () { inp.value = "<img src=x onerror=\"fetch('/steal?c='+document.cookie)\">"; };
        go.onclick = function () {
          var comment = inp.value;
          if (mode.value === "safe") {
            var r = renderSafe(comment);
            out.innerHTML = "<div class='kv'>the guestbook page now contains, as literal text</div>" +
              "<div class='hashline'>" + esc(r.inserted) + "</div>" +
              "<div style='margin-top:8px'><span class='pill good'>nothing runs</span> the markup became characters, so it only displays</div>";
          } else {
            var u = renderUnsafe(comment);
            var h = "<div class='kv'>the page inserted your comment as raw HTML</div><div class='hashline'>" + esc(u.inserted) + "</div>";
            if (u.would_execute) {
              h += "<div style='margin:8px 0'><span class='pill bad'>this would run in every visitor's browser</span></div>";
              u.triggers.forEach(function (t) { h += "<div class='sig danger'><div class='d'>" + esc(t) + "</div></div>"; });
              h += "<div class='kv' style='margin-top:8px'>with your real session cookie in reach, unless HttpOnly is set</div>";
            } else {
              h += "<div style='margin-top:8px'><span class='pill good'>nothing to run</span> this comment has no script or handler in it</div>";
            }
            out.innerHTML = h;
          }
        };
        go.onclick();
      }
    },
    {
      id: "sessions", n: "Lesson 8", title: "Cookies and sessions",
      summary: "A session cookie is a key. Toggle its flags and see which attacks open and close.",
      explain: "After you log in, the server gives your browser a session cookie, a random id that stands in for you on every later request. That is convenient, but it means the cookie is a key: whoever holds it is you, with no password needed. Three flags decide how well that key is guarded. HttpOnly keeps page scripts from reading it, so a cross site scripting bug cannot steal it. Secure keeps it off plain http, so it cannot be sniffed. SameSite keeps it from being sent on requests started by other sites, which stops cross site request forgery. Leaving any of the three off opens a specific and well known attack.",
      takeaway: "Set HttpOnly, Secure, and SameSite on session cookies, and give sessions a short life and a real logout. The cookie is a key, so guard it like one.",
      render: function (root) {
        root.appendChild(el("h4", null, "A session cookie, and the flags that guard it"));
        var sid = "";
        for (var i = 0; i < 32; i++) sid += "0123456789abcdef"[Math.floor(Math.random() * 16)];
        root.appendChild(el("div", "hashline", "session=" + sid));
        var box = el("div"); root.appendChild(box);
        var state = { HttpOnly: false, Secure: false, SameSite: false };
        ["HttpOnly", "Secure", "SameSite"].forEach(function (name) {
          var wrap = el("label", "chk");
          var cb = el("input"); cb.type = "checkbox";
          cb.onchange = function () { state[name] = cb.checked; refresh(); };
          var t = el("div"); t.appendChild(el("div", "t", "<b class='mono'>" + name + "</b>"));
          wrap.appendChild(cb); wrap.appendChild(t); box.appendChild(wrap);
        });
        var out = el("div", "out"); root.appendChild(out);
        function refresh() {
          var r = analyzeSession(state);
          var h = "<div><span class='pill " + (r.exposure ? "bad" : "good") + "'>" + r.exposure + " of 3 attacks open</span></div>";
          r.risks.forEach(function (s) { h += "<div class='sig danger'><div class='t'>" + esc(s.title) + "</div><div class='d'>" + esc(s.detail) + "</div></div>"; });
          r.safe.forEach(function (s) { h += "<div class='sig note' style='border-left-color:var(--green)'><div class='t'>" + esc(s.title) + "</div><div class='d'>" + esc(s.detail) + "</div></div>"; });
          out.innerHTML = h;
        }
        refresh();
      }
    },
    {
      id: "tls", n: "Lesson 9", title: "TLS and certificates",
      summary: "See the three checks a browser runs on a certificate, and why each warning appears.",
      explain: "When you connect over https, the site sends a certificate that does two jobs. It carries the key used to encrypt the connection, and it proves the site is who it claims to be. Your browser accepts it only if three things hold. The certificate must be within its validity dates, it must be issued for the exact hostname you visited, and it must be signed by an authority your browser already trusts, forming an unbroken chain. If any check fails, the encryption might still work, but the identity is unproven, and that is exactly what the browser warning is telling you. A self signed certificate fails the last check because anyone can make one.",
      takeaway: "A certificate warning means identity could not be proven, so treat the site as untrusted and do not click through on anything that matters. Encryption without a verified identity is encryption with a stranger.",
      render: function (root) {
        root.appendChild(el("h4", null, "Inspect a certificate the way a browser does"));
        var row = el("div", "row");
        var sel = el("select");
        Object.keys(CERT_SCENARIOS).forEach(function (k) { var o = el("option", null, CERT_SCENARIOS[k].label); o.value = k; sel.appendChild(o); });
        row.appendChild(sel); root.appendChild(row);
        var out = el("div", "out"); root.appendChild(out);
        function refresh() {
          var sc = CERT_SCENARIOS[sel.value], r = validateCert(sc.cert, sc.hostname, CERT_TODAY);
          var h = "<div class='kv'>you connected to <b class='mono'>" + esc(sc.hostname) + "</b>, the certificate names <b class='mono'>" + esc(sc.cert.subject) + "</b>, issuer " + esc(sc.cert.issuer) + "</div>";
          h += "<div style='margin:10px 0'><span class='pill " + (r.trusted ? "good" : "bad") + "'>" + (r.trusted ? "trusted, no warning" : "browser shows a warning") + "</span></div>";
          r.checks.forEach(function (c) {
            h += "<div class='sig " + (c.ok ? "note" : "danger") + "'" + (c.ok ? " style='border-left-color:var(--green)'" : "") + "><div class='t'>" + (c.ok ? "\u2713 " : "\u2717 ") + esc(c.name) + "</div><div class='d'>" + esc(c.note) + "</div></div>";
          });
          out.innerHTML = h;
        }
        sel.onchange = refresh; refresh();
      }
    },
    {
      id: "traffic", n: "Lesson 10", title: "Reading traffic",
      summary: "Spot a port scan in a connection log by hand, the idea at the heart of NetHawk.",
      explain: "Most defensive work starts with reading traffic, and the most basic pattern to recognize is a port scan. Normal clients talk to a service or two on their usual ports. A scanner does the opposite: a single source reaches for a long list of ports on a target, or the same port across many hosts, probing to learn what is open. You do not need fancy tools to see it, only to group the log by source and count how many distinct ports or hosts each one touched. One address with a count far above the rest is the scanner, and that spread is its fingerprint. This is exactly what a tool like NetHawk automates over a real capture.",
      takeaway: "Watch for one source fanning out across many ports or many hosts. That spread, not any single connection, is the signature of a scan. Group by source, count the spread, and the outlier stands out.",
      render: function (root) {
        root.appendChild(el("h4", null, "A connection log. Who is scanning?"));
        root.appendChild(el("p", "hint", "Each row is one source reaching one destination on one port. Group by source and count."));
        var go = el("button", "btn primary small", "Group by source and count the spread"); root.appendChild(go);
        var out = el("div", "out"); root.appendChild(out);
        go.onclick = function () {
          var res = detectPortScan(SAMPLE_LOG);
          var h = "<div class='kv'>" + SAMPLE_LOG.length + " connections, grouped by source</div>";
          res.rows.forEach(function (r) {
            var scanning = r.distinct_ports >= res.threshold;
            h += "<div class='sig " + (scanning ? "danger" : "note") + "'" + (!scanning ? " style='border-left-color:var(--line)'" : "") + ">" +
              "<div class='t'><span class='mono'>" + esc(r.source) + "</span> &middot; " + r.distinct_ports + " distinct ports, " + r.distinct_hosts + " host" + (r.distinct_hosts > 1 ? "s" : "") +
              (scanning ? " &nbsp;<span class='pill bad'>port scan</span>" : "") + "</div>" +
              (scanning ? "<div class='d'>reached ports " + r.ports.slice(0, 12).join(", ") + " on one host, a classic vertical scan</div>" : "") + "</div>";
          });
          out.innerHTML = h;
        };
        go.onclick();
      }
    }
  ];

  /* ---- learning path order and progress ---- */
  var ORDER = ["hashing", "strength", "bruteforce", "encoding", "phish", "sqli", "xss", "sessions", "headers", "tls", "traffic"];
  function ordered() {
    return ORDER.map(function (id) { return LESSONS.filter(function (l) { return l.id === id; })[0]; })
      .filter(Boolean);
  }
  var PKEY = "manara_progress_v1";
  function loadProgress() {
    try { return JSON.parse(localStorage.getItem(PKEY)) || {}; } catch (e) { return {}; }
  }
  function saveProgress(p) {
    try { localStorage.setItem(PKEY, JSON.stringify(p)); } catch (e) {}
  }
  function isDone(id) { return !!loadProgress()[id]; }
  function setDone(id, done) {
    var p = loadProgress();
    if (done) p[id] = true; else delete p[id];
    saveProgress(p);
  }
  function doneCount() {
    var p = loadProgress(), n = 0;
    ORDER.forEach(function (id) { if (p[id]) n++; });
    return n;
  }

  /* ---- app shell ---- */
  function showList() { location.hash = ""; render(); }
  function showLesson(id) { location.hash = id; render(); }

  function progressBar() {
    var done = doneCount(), total = ORDER.length, pct = Math.round(100 * done / total);
    var wrap = el("div");
    wrap.style.margin = "0 0 20px";
    var line = el("div", "kv", "<b style='color:var(--text)'>" + done + " of " + total + "</b> lessons done");
    var meter = el("div", "meter"); var bar = el("span");
    bar.style.width = pct + "%"; bar.style.background = "var(--teal)"; meter.appendChild(bar);
    wrap.appendChild(line); wrap.appendChild(meter);
    return wrap;
  }

  function renderQuiz(app) {
    var back = el("button", "back", "\u2190 all lessons"); back.onclick = showList; app.appendChild(back);
    app.appendChild(el("h2", null, "Test your understanding"));
    app.appendChild(el("p", "tag", "One quick pass over the ideas from every lesson. Pick an answer to see whether it is right and why. Nothing is graded anywhere but here on your screen."));
    var answers = {};
    var score = el("div", "out"); score.style.margin = "0 0 16px";
    app.appendChild(score);
    function updateScore(final) {
      var answered = Object.keys(answers).length;
      var correct = 0;
      Object.keys(answers).forEach(function (i) { if (answers[i] === QUIZ[i].answer) correct++; });
      var pct = Math.round(100 * correct / QUIZ.length);
      var pill = final ? "<span class='pill " + (pct >= 70 ? "good" : pct >= 40 ? "warn" : "bad") + "'>" + pct + "%</span> " : "";
      score.innerHTML = pill + "<b>" + correct + " correct</b> of " + answered + " answered, " + QUIZ.length + " total" +
        (final ? " &middot; " + (pct >= 70 ? "well done" : "worth another look at a lesson or two") : "");
    }
    QUIZ.forEach(function (q, i) {
      var block = el("div", "lab");
      block.appendChild(el("div", "kv", "From lesson: " + q.lesson));
      block.appendChild(el("div", null, "<div style='font-weight:600;margin:4px 0 12px'>" + esc(q.q) + "</div>"));
      var opts = [];
      q.options.forEach(function (opt, j) {
        var b = el("button", "btn"); b.style.display = "block"; b.style.width = "100%";
        b.style.textAlign = "left"; b.style.marginBottom = "7px";
        b.innerHTML = esc(opt);
        b.onclick = function () {
          if (i in answers) return;
          answers[i] = j;
          opts.forEach(function (ob, k) {
            ob.disabled = true;
            if (k === q.answer) { ob.style.borderColor = "var(--green)"; ob.style.color = "var(--green)"; }
            else if (k === j) { ob.style.borderColor = "var(--red)"; ob.style.color = "var(--red)"; }
          });
          var note = el("div", "sig " + (j === q.answer ? "note" : "danger"));
          if (j === q.answer) note.style.borderLeftColor = "var(--green)";
          note.innerHTML = "<div class='t'>" + (j === q.answer ? "Correct" : "Not quite") + "</div><div class='d'>" + esc(q.why) + "</div>";
          block.appendChild(note);
          updateScore(Object.keys(answers).length === QUIZ.length);
        };
        opts.push(b); block.appendChild(b);
      });
      app.appendChild(block);
    });
    var retake = el("button", "btn", "Start over");
    retake.onclick = function () { render(); };
    app.appendChild(retake);
    updateScore(false);
    window.scrollTo(0, 0);
  }

  function render() {
    var app = document.getElementById("app");
    app.innerHTML = "";
    var id = location.hash.replace(/^#/, "");
    if (id === "quiz") { renderQuiz(app); return; }
    var list = ordered();
    var idx = ORDER.indexOf(id);
    var lesson = idx >= 0 ? list[idx] : null;
    if (!lesson) {
      app.appendChild(progressBar());
      var grid = el("div", "grid");
      list.forEach(function (l, i) {
        var done = isDone(l.id);
        var c = el("div", "card");
        c.appendChild(el("div", "n", "Lesson " + (i + 1) + (done ? " &nbsp;<span class='pill good' style='padding:1px 8px'>done</span>" : "")));
        c.appendChild(el("h3", null, esc(l.title)));
        c.appendChild(el("p", null, esc(l.summary)));
        c.onclick = function () { showLesson(l.id); };
        grid.appendChild(c);
      });
      app.appendChild(grid);
      var quizWrap = el("div"); quizWrap.style.marginTop = "18px";
      var quizBtn = el("button", "btn primary", "Test your understanding \u2192");
      quizBtn.onclick = function () { location.hash = "quiz"; render(); };
      quizWrap.appendChild(quizBtn);
      var qn = el("span", "kv"); qn.style.marginLeft = "10px";
      qn.innerHTML = QUIZ.length + " questions across all lessons";
      quizWrap.appendChild(qn);
      app.appendChild(quizWrap);
      return;
    }
    var back = el("button", "back", "\u2190 all lessons"); back.onclick = showList; app.appendChild(back);
    var head = el("div", "lesson-head");
    head.appendChild(el("div", "card-n", "<span class='pill' style='background:rgba(255,200,87,.16);color:var(--beam)'>Lesson " + (idx + 1) + " of " + ORDER.length + "</span>"));
    head.appendChild(el("h2", null, esc(lesson.title)));
    app.appendChild(head);
    app.appendChild(el("div", "explain", esc(lesson.explain)));
    var lab = el("div", "lab"); lesson.render(lab); app.appendChild(lab);
    app.appendChild(el("div", "takeaway", "<b>Takeaway.</b> " + esc(lesson.takeaway)));

    var nav = el("div", "row"); nav.style.marginTop = "18px";
    var doneBtn = el("button", "btn " + (isDone(lesson.id) ? "" : "primary"), isDone(lesson.id) ? "\u2713 done, click to unmark" : "Mark this lesson done");
    doneBtn.onclick = function () { setDone(lesson.id, !isDone(lesson.id)); render(); };
    nav.appendChild(doneBtn);
    if (idx + 1 < ORDER.length) {
      var next = el("button", "btn", "Next: " + list[idx + 1].title + " \u2192");
      next.onclick = function () { showLesson(ORDER[idx + 1]); };
      nav.appendChild(next);
    }
    app.appendChild(nav);
    window.scrollTo(0, 0);
  }

  window.addEventListener("load", function () {
    var v = document.getElementById("ver"); if (v) v.textContent = VERSION;
    window.addEventListener("hashchange", render);
    render();
  });
  window.__MANARA__ = {
    analyzeUrl: analyzeUrl, entropyBits: entropyBits, vulnerableLogin: vulnerableLogin,
    safeLogin: safeLogin, analyzeSession: analyzeSession, validateCert: validateCert,
    detectPortScan: detectPortScan, renderUnsafe: renderUnsafe, renderSafe: renderSafe,
    escapeHtml: escapeHtml, gradeQuiz: gradeQuiz, QUIZ: QUIZ,
    CERT_SCENARIOS: CERT_SCENARIOS, CERT_TODAY: CERT_TODAY,
    SAMPLE_LOG: SAMPLE_LOG, LESSONS: LESSONS, ORDER: ORDER
  };
})();
