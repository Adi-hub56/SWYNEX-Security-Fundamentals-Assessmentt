# Security Assessment Report: Intentionally Vulnerable Flask Lab App

| | |
|---|---|
| **Assessor** | Aditya Kadam |
| **Date** | 31 October 2026 |
| **Target** | `vulnapp.py`, a Flask + SQLite training app (`http://127.0.0.1:5000`) |
| **Authorization** | Self-owned lab. The app was written and run locally by the assessor. No external systems were tested. |
| **Method** | Manual black-box testing with `curl` plus white-box source review |

## 1. Scope and methodology

Routes in scope: `/login` (POST), `/search`, `/note/<id>`, `/debug`. Testing followed the OWASP Top 10 (2021) categories relevant to a small web app: injection, broken access control, security misconfiguration, identification and authentication failures. Each finding was confirmed by sending a real request and recording the real response (see `evidence/`). Fixes were then applied in `vulnapp_fixed.py` and every test was re-run against it (`evidence/retest_fixed.txt`).

**Limitations:** small single-file app; manual testing only. Findings are rated by my own judgment of impact in this context, not a formal CVSS calculation.

## 2. Findings summary

| ID | Component | Risk | Severity | OWASP / CWE |
|----|-----------|------|----------|-------------|
| F-01 | `POST /login` | SQL injection, authentication bypass | Critical | A03 / CWE-89 |
| F-02 | `GET /search?q=` | Reflected XSS | Medium | A03 / CWE-79 |
| F-03 | `GET /note/<id>` | IDOR, no authentication or ownership check | High | A01 / CWE-639, CWE-862 |
| F-04 | `GET /debug` | Unauthenticated disclosure of `secret_key` | High | A05 / CWE-200 |
| F-05 | Source code | Hardcoded secret, plaintext passwords | High | A02, A07 / CWE-798, CWE-256 |
| F-06 | `POST /login` | Verbose SQL error returned to client | Medium | A05 / CWE-209 |
| F-07 | `POST /login` | No rate limiting or account lockout | Medium | A07 / CWE-307 |
| F-08 | All responses | Missing security headers, version disclosure | Low | A05 / CWE-693 |

## 3. Detailed findings

### F-01 SQL injection in login (Critical)
**Affected component:** `POST /login`, `username` and `password` parameters.
**Cause:** the query is built with an f-string: `... WHERE username='{u}' AND password='{p}'`.
**Evidence** (`evidence/f01_sqli.txt`):
```
username=admin  password=wrong     -> HTTP 401  Invalid credentials
username=admin'--  password=x      -> HTTP 200  Welcome admin (role=admin)
```
The `--` comment removes the password check, so any account can be logged into without its password.
**Mitigation:** use parameterized queries (`WHERE username=?`), and compare password hashes rather than SQL-matching plaintext.
**Verified fix:** the same payload against the patched app returns `401 Invalid credentials`.

### F-02 Reflected XSS (Medium)
**Affected component:** `GET /search?q=`.
**Evidence** (`evidence/f02_xss.txt`): input `<script>alert(1)</script>` is returned unmodified inside the HTML body, so it would execute in a victim's browser.
**Mitigation:** HTML-encode output (`markupsafe.escape` or a template engine with autoescape) and add a Content-Security-Policy.
**Verified fix:** patched app returns `&lt;script&gt;alert(1)&lt;/script&gt;`.

### F-03 Broken access control / IDOR (High)
**Affected component:** `GET /note/<id>`.
**Evidence** (`evidence/f03_idor.txt`): with no login and no cookie, `/note/1`, `/note/2` and `/note/3` all return other users' private notes, including the admin note `backup key is K-9921`. Sequential integer IDs make enumeration trivial.
**Mitigation:** require authentication and check that the note's `owner_id` matches the session user (or the user is admin). Return 404 otherwise.
**Verified fix:** unauthenticated request now returns `401`.

### F-04 Debug endpoint leaks secret (High)
**Affected component:** `GET /debug`.
**Evidence** (`evidence/f04_debug.txt`): unauthenticated request returns `{"secret_key":"supersecret123", "db":"lab.db", "env":"development"}`. Flask signs session cookies with this key, so knowing it would allow forging sessions. Cookie forgery was **not** demonstrated in this lab.
**Mitigation:** remove debug routes from any deployed build; never expose configuration.
**Verified fix:** route removed, returns `404`.

### F-05 Hardcoded secret and plaintext passwords (High)
**Affected component:** source code (`app.secret_key = "supersecret123"`; `users.password` stores `admin123`, `password1`, `qwerty` as plaintext).
**Evidence:** source review of `app/vulnapp.py`. A database leak or repository leak exposes every credential directly.
**Mitigation:** load the key from an environment variable or secret manager, and store salted password hashes (`werkzeug.security.generate_password_hash`, or bcrypt/argon2).
**Verified fix:** `vulnapp_fixed.py` reads `APP_SECRET` from the environment and stores hashes.

### F-06 Verbose error disclosure (Medium)
**Affected component:** `POST /login`.
**Evidence** (`evidence/f01_sqli.txt`): input `'` returns `HTTP 500  SQL error: unrecognized token: "x'"`, which reveals the DB engine and confirms the injection point.
**Mitigation:** return a generic error to the client and log details server-side.
**Verified fix:** malformed input returns `401 Invalid credentials`.

### F-07 No rate limiting (Medium)
**Affected component:** `POST /login`.
**Evidence** (`evidence/f07_bruteforce.txt`): 10 consecutive wrong passwords all return `401` with no delay or lockout, and the 11th attempt with the correct password succeeds. Passwords can be brute-forced or sprayed freely.
**Mitigation:** per-IP and per-account throttling or lockout, plus MFA for privileged accounts.
**Verified fix:** the patched app returns `429` after 5 failures in 5 minutes. In the retest the limit tripped on attempt 4 because two earlier retest requests from the same IP had already counted as failures.

### F-08 Missing security headers (Low)
**Affected component:** all responses.
**Evidence** (`evidence/f08_headers.txt`): no `Content-Security-Policy`, `X-Content-Type-Options` or `X-Frame-Options`; `Server: Werkzeug/3.1.7 Python/3.12.3` discloses exact versions.
**Mitigation:** add the headers via an `after_request` hook or reverse proxy, and suppress the version banner.
**Verified fix:** the three headers are present in the patched app. The server banner comes from the Werkzeug development server and would be hidden by a production WSGI server and reverse proxy.

## 4. Retest results

`evidence/retest_fixed.txt` shows every payload above re-run against `vulnapp_fixed.py`. All eight findings are remediated in the patched app.

## 5. Key learnings

1. Most of the serious issues (F-01, F-02, F-06) come from one root cause: trusting user input and not separating data from code or markup.
2. Authentication alone is not enough. F-03 shows that authorization must be checked per object.
3. Misconfiguration (F-04, F-05, F-08) is as damaging as coding bugs and is cheap to prevent.
