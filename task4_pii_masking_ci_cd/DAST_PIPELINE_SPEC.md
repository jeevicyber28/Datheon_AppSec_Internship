# Automated DAST & CI/CD Security Pipeline Specification

## Architecture Overview
Security cannot rely on manual point-in-time penetration tests. This project integrates automated **Dynamic Application Security Testing (DAST)** and **Static Application Security Testing (SAST)** directly into GitHub Actions (`security_audit.yml`).

Every Pull Request and commit triggers automated security gates:
```
Git Push / Pull Request
   │
   ├── 1. Unit & Authorization Guard Tests (node:test)
   ├── 2. Secret & Token Leak Scanner (Gitleaks)
   ├── 3. Dependency Vulnerability Audit (npm audit)
   └── 4. Dynamic Application Security Scan (OWASP ZAP)
         └── Validates CSP, HSTS, X-Content-Type-Options, & PII Leakage
```

---

## 1. Secrets & Token Exfiltration Scanner (Gitleaks)
Scans git commit history and staging diffs for:
- Exposed JWT secret keys (`HS256`, `RS256`)
- Cloud provider access tokens (AWS, GCP, Azure)
- Database connection URIs (`mongodb://`, `postgres://`)

---

## 2. Dynamic DAST Scanner (OWASP ZAP)
Spins up a headless ephemeral instance of the target API server and probes public endpoints for:
- Missing HTTP security headers (Flags absent CSP or HSTS)
- Clickjacking vulnerabilities (Missing `X-Frame-Options: DENY`)
- Information disclosure headers (Suppresses `X-Powered-By: Express` and stack traces)
- Reflected parameter inputs

---

## 3. Pipeline Failure Criteria
The workflow blocks merging to `main` if:
1. Any authorization integration test in `task2_bola_remediation` fails.
2. An unmasked email or raw phone number regex is detected in public API responses.
3. High or Critical CVEs are identified in production dependencies.
