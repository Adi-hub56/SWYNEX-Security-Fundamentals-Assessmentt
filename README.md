# SWYNEX Task 1: Security Fundamentals Assessment

Security assessment of an **intentionally vulnerable training application that I built and ran locally** (`127.0.0.1` only). No third-party or production system was tested.

**Full report:** [REPORT.md](REPORT.md)

## Result summary

| ID | Finding | Severity |
|----|---------|----------|
| F-01 | SQL injection in `/login` (authentication bypass) | Critical |
| F-02 | Reflected XSS in `/search` | Medium |
| F-03 | Broken access control / IDOR in `/note/<id>` | High |
| F-04 | Unauthenticated `/debug` endpoint leaks the session secret | High |
| F-05 | Hardcoded secret key and plaintext password storage | High |
| F-06 | Verbose SQL error disclosure | Medium |
| F-07 | No rate limiting or lockout on login | Medium |
| F-08 | Missing security headers, server version disclosed | Low |

## Repository layout

```
app/vulnapp.py          vulnerable lab app (port 5000)
app/vulnapp_fixed.py    patched version (port 5001)
evidence/               raw curl output for every finding + retest of the fix
REPORT.md               methodology, findings, evidence, mitigations
```

## Reproduce

```bash
pip install -r requirements.txt
cd app
python vulnapp.py          # terminal 1, vulnerable app on 127.0.0.1:5000
python vulnapp_fixed.py    # terminal 2, patched app on 127.0.0.1:5001
```

> Warning: `vulnapp.py` is deliberately insecure. Run it only on localhost. Never deploy it.
