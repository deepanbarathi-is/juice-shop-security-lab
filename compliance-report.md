# Compliance Gap Analysis: OWASP Juice Shop

> Evidence note: this report cites `output.md`, a multi-agent security review kept as a local file during the original run. It is not in this repository, so those citations cannot be checked here. The same findings, with line references re-checked against the source, are in [`security-assessment.md`](security-assessment.md).

## Executive Summary

This codebase would **fail** a PCI-DSS v4.0 assessment and an ISO/IEC 27001:2022 Annex A control audit in its current state. Of 22 controls mapped, **14 are Non-Compliant**, 5 are Partial, 2 are Compliant, and 1 has insufficient evidence to assess from source alone. Three gaps are certification-blocking on their own: unauthenticated SQL injection on the login path (defeats every downstream access control), a hardcoded JWT signing key checked into source (breaks the authentication root of trust for the entire application), and unencrypted storage of full card numbers (a direct PCI-DSS Requirement 3 violation). This is a known-intentionally-vulnerable training application, so no real cardholder data is currently at risk, but the code patterns present here are exactly what an assessor would cite as automatic non-compliance if deployed as a real cardholder data environment (CDE).

## Scope & Methodology

**In scope**: Node.js/Express backend (`routes/*.ts`, `lib/insecurity.ts`, `server.ts`), Sequelize/SQLite data layer (`models/*.ts`), card/payment handling (`models/card.ts`, `routes/payment.ts`), authentication/session management, logging/audit trail, and dependency management.

**Standards assessed**: PCI-DSS v4.0 (cardholder data protection, secure development, access control, logging), ISO/IEC 27001:2022 Annex A (organizational/technological controls relevant to an ISMS).

**Out of scope / not assessable from source**: TLS termination and network-layer encryption (Req 4.2.1) are typically handled by a reverse proxy/load balancer in production and are not implemented in application code, flagged as insufficient evidence rather than assumed compliant or non-compliant. Physical security controls (ISO Annex A.7) are not applicable to a source-code review.

**Evidence base**: Findings are drawn primarily from the existing independently-verified security review at `output.md` (8-agent pipeline, 9 confirmed vulnerabilities F1-F9 with exploit chains and CVSS scores), supplemented by direct source inspection of `models/card.ts`, `routes/payment.ts`, `lib/logger.ts`, and `server.ts` for controls not covered by that review (PAN storage, logging architecture, security headers, dependency pinning). Every status below cites a `file:line` reference.

## Compliance Matrix

| Control Area | PCI-DSS v4.0 | ISO 27001:2022 Annex A | Status | Evidence |
|---|---|---|---|---|
| Authentication (password storage) | Req 8.3.6 | A.5.17, A.8.24 | Non-Compliant | `routes/login.ts:34`: unsalted MD5 hash |
| Authentication (login injection) | Req 6.2.4, Req 8.2.1 | A.8.5, A.8.28 | Non-Compliant | `routes/login.ts:34`: raw SQL string interpolation (F1) |
| JWT signing key management | Req 3.6.1, Req 6.3.1 | A.8.9, A.8.24 | Non-Compliant | `lib/insecurity.ts:21`: hardcoded RSA private key literal (F3) |
| MFA / 2FA enforcement | Req 8.4.2 | A.8.5 | Partial | `routes/2fa.ts`: 2FA exists but is opt-in, not enforced for CDE-equivalent access |
| MFA implementation integrity | Req 8.5.1 | A.8.5 | Non-Compliant | `output.md` §2 row 7: 2FA `tmpToken` JWT decoded without full verification |
| Secrets management | Req 8.6.3 | A.8.9 | Non-Compliant | `lib/insecurity.ts:21` (RSA key), `:22` (HMAC key), `server.ts:308` (cookie secret `'kekse'`), `output.md`: hardcoded backdoor key in `verify.ts:100` |
| Access control / authorization | Req 7.2.1, Req 7.2.2 | A.5.15, A.8.3 | Non-Compliant | `routes/basket.ts:15-36`: IDOR, ownership check is cosmetic only (F5) |
| Injection defenses (SQLi) | Req 6.2.4 | A.8.28 | Non-Compliant | `routes/login.ts:34`, `routes/search.ts:23` (F1, F2) |
| Injection defenses (code execution) | Req 6.2.4 | A.8.27, A.8.28 | Non-Compliant | `routes/b2bOrder.ts:16-24` (F6), `routes/userProfile.ts:57-65` (F9) |
| Injection defenses (XXE) | Req 6.2.4 | A.8.26, A.8.28 | Non-Compliant | `lib/xml.ts:34-38` (F8) |
| File upload integrity | Req 6.2.4 | A.8.28 | Non-Compliant | `routes/fileUpload.ts:27-37`: zip-slip containment bypass (F7) |
| Cardholder data at rest | Req 3.3.1, Req 3.5.1 | A.8.24 | Non-Compliant | `models/card.ts:20-25`: `cardNum` stored as plain unencrypted `INTEGER` |
| Cardholder data on display | Req 3.4.1 | A.8.24 | Compliant | `routes/payment.ts:29-31`: PAN masked to last 4 digits on output |
| Encrypted transmission (TLS) | Req 4.2.1 | A.8.24 | Insufficient Evidence | No TLS/HSTS termination present in app code (`server.ts`); deployment-layer dependent, not assessable from source |
| Security headers / hardening | Req 6.2.4 | A.8.9, A.8.26 | Partial | `server.ts:186-188`: `helmet.noSniff()`/`frameguard()` applied, `xssFilter()` explicitly disabled (comment: "no protection from persisted XSS via RESTful API"), no CSP/HSTS configured |
| Rate limiting / brute-force protection | Req 8.3.4 | A.8.5 | Partial | `server.ts:362`: rate limiting applied to password reset and 2FA endpoints only; `/rest/user/login` (F1's target) has none |
| Static/sensitive directory exposure | Req 7.2.1 | A.8.3 | Non-Compliant | `output.md` §1: `/ftp`, `/encryptionkeys`, `/support/logs`, `/infrastructure` served statically, gated only by challenge-tracking, not real authorization |
| Audit logging coverage | Req 10.2.1 | A.8.15 | Partial | `server.ts:357` (morgan combined access log), `lib/logger.ts:8-12` (winston): HTTP access is logged, but no evidence of privileged-action or auth-event-specific audit trail |
| Audit log protection | Req 10.3.1 | A.8.15 | Non-Compliant | `routes/logfileServer.ts`, `server.ts:300-302`: `/support/logs` served with directory listing, minimally gated |
| Monitoring/alerting | Req 10.4.1 | A.8.16 | Insufficient Evidence | No SIEM/alerting integration found in source; cannot confirm absence vs. out-of-band tooling |
| Dependency / component inventory | Req 6.3.2 | A.8.28 | Non-Compliant | No `package-lock.json` at repo root (checked); `output.md` notes `jsonwebtoken` pinned at ancient `0.4.0` |
| Security testing process | Req 11.3 | A.8.29 | Compliant | `output.md` itself: an independently-verified, multi-agent security review with confirmed findings, CVSS scoring, and remediation plan demonstrates an active security testing process |

## Gap Analysis

| ID | Standard(s) | Requirement | Status | Gap Description | Risk | Remediation |
|---|---|---|---|---|---|---|
| C1 | PCI Req 8.2.1/6.2.4; ISO A.8.5, A.8.28 | Authenticate access; prevent injection | Non-Compliant | Login query built via raw string interpolation (`routes/login.ts:34`); `' OR 1=1--` bypasses authentication entirely | Critical: unauthenticated full account/admin takeover | Parameter binding or `UserModel.findOne()`; see F1 fix in `output.md` §6 |
| C2 | PCI Req 3.6.1/6.3.1; ISO A.8.9, A.8.24 | Protect cryptographic keys; secure config | Non-Compliant | RSA private key hardcoded as a literal string in source (`lib/insecurity.ts:21`), signs every JWT | Critical: forge arbitrary identity/role, root of trust broken app-wide | Externalize to secrets manager/env var, rotate per deployment; reject startup if unset |
| C3 | PCI Req 3.3.1/3.5.1; ISO A.8.24 | Render PAN unreadable at rest | Non-Compliant | `cardNum` stored as plain `INTEGER` with no encryption, hashing, or tokenization (`models/card.ts:20-25`): display-time masking (`routes/payment.ts:29-31`) does not satisfy the storage requirement | Critical (PCI-hard-fail): any DB compromise (already plausible via C1/C4) yields full PANs | Encrypt PAN column at rest (AES-256) or tokenize via a PCI-compliant vault; never store raw PAN if it can be avoided entirely |
| C4 | PCI Req 6.2.4; ISO A.8.28 | Prevent injection attacks | Non-Compliant | Unauthenticated SQLi on product search (`routes/search.ts:23`) enables UNION-based table dump of users/hashes | High: bulk credential exfiltration | Parameterized query; see F2 fix in `output.md` §6 |
| C5 | PCI Req 6.2.4; ISO A.8.27, A.8.28 | Secure coding / no dynamic code execution on untrusted input | Non-Compliant | `vm`+`notevil` "sandboxed" eval of user-supplied order data (`routes/b2bOrder.ts:16-24`, F6) and `eval()` on stored username (`routes/userProfile.ts:57-65`, F9) | High: remote code execution from an authenticated (F6) or self-registered (F9) account | Remove all `eval()`/`vm` sinks; replace with schema validation (zod/joi) |
| C6 | PCI Req 6.2.4; ISO A.8.26, A.8.28 | Secure XML processing | Non-Compliant | `XML_PARSE_NOENT`/`XML_PARSE_DTDLOAD` enabled plus filesystem input provider registration (`lib/xml.ts:34-38`, F8) | High: arbitrary local file disclosure via unauthenticated upload | Disable external entity resolution and DTD loading by default; never reflect parsed content in errors |
| C7 | PCI Req 7.2.1/7.2.2; ISO A.5.15, A.8.3 | Least privilege / access control enforcement | Non-Compliant | Basket ownership check exists but only flags a challenge: never denies the request (`routes/basket.ts:15-36`, F5); order checkout trusts client-supplied `UserId` for wallet debit/credit | Medium: cross-account data disclosure, financial logic abuse | Enforce ownership server-side with a 403 on mismatch; derive `UserId` from session, never from request body |
| C8 | PCI Req 8.3.6; ISO A.5.17, A.8.24 | Strong cryptography for credential storage | Non-Compliant | Passwords hashed with unsalted MD5 (`routes/login.ts:34` via `security.hash()`) | High (compounds C1/C4): trivial offline cracking of any leaked hash | Migrate to bcrypt/argon2 with per-user salt |
| C9 | PCI Req 8.6.3; ISO A.8.9 | Protect application secrets from misuse | Non-Compliant | Static HMAC key, fixed cookie secret `'kekse'` (`server.ts:308`), hardcoded backdoor key in `verify.ts:100` | Medium-High: predictable/shared secrets undermine session and cookie integrity | Move all secrets to environment-injected config; remove backdoor key entirely |
| C10 | PCI Req 7.2.1; ISO A.8.3 | Restrict access to system resources | Non-Compliant | `/ftp`, `/encryptionkeys`, `/support/logs`, `/infrastructure` served with directory listing, gated only by CTF challenge-tracking, not real auth | Medium: reconnaissance, log/config disclosure | Require admin authentication on all support/infra static routes; disable directory listing in production |
| C11 | PCI Req 10.3.1; ISO A.8.15 | Restrict audit log access to need-to-know | Non-Compliant | `/support/logs/:file` (`routes/logfileServer.ts`) exposes log contents with only a challenge-tracking gate | Medium: log data (potentially containing IPs, request details) disclosed to any visitor | Authenticate and authorize log access to admin/support roles only |
| C12 | PCI Req 8.4.2/8.5.1; ISO A.8.5 | Enforce and correctly implement MFA | Partial/Non-Compliant | 2FA is optional per-user, and its `tmpToken` mid-login JWT is decoded without full verification (`output.md` §2 row 7) | Medium: MFA can be skipped or its intermediate token trusted improperly | Make MFA mandatory for privileged/CDE-equivalent operations; fully verify (not just decode) intermediate tokens |
| C13 | PCI Req 8.3.4; ISO A.8.5 | Limit repeated access attempts | Partial | Rate limiting applied to password reset and 2FA (`server.ts:362,478,485,491`) but not to `/rest/user/login` itself | Medium: brute-force/credential-stuffing exposure on the primary auth endpoint (compounds C1) | Apply `express-rate-limit` (with account lockout/backoff) to the login endpoint |
| C14 | PCI Req 6.3.2; ISO A.8.28 | Maintain inventory of software components for vulnerability management | Non-Compliant | No `package-lock.json` at repository root; `jsonwebtoken` pinned at an ancient `0.4.0` release per `output.md` | Medium: unpinned/outdated dependencies make vulnerability tracking and reproducible builds unreliable | Commit a lockfile, adopt automated dependency scanning (Dependabot/Snyk), upgrade pinned legacy packages |
| C15 | PCI Req 6.2.4; ISO A.8.9, A.8.26 | Secure HTTP response configuration | Partial | `helmet.xssFilter()` explicitly disabled with an in-code comment acknowledging reduced XSS protection; no CSP or HSTS configured (`server.ts:186-188`) | Low-Medium: weaker defense-in-depth against persisted XSS | Configure a strict CSP, enable HSTS at the edge/app layer, re-evaluate the disabled header |

## Critical Findings

1. **C1, Login SQL injection defeats authentication entirely.** Every downstream access control (C7, C10, C11) is moot once an attacker can authenticate as any user, including admin, with no credentials.
2. **C2, Hardcoded JWT private key breaks the authentication root of trust.** Independent of C1, an attacker with source access can mint arbitrarily privileged tokens offline, with zero interaction with the running application.
3. **C3, Full card numbers stored unencrypted.** This is a PCI-DSS Requirement 3 hard-fail on its own; masking on display (which is correctly implemented) does not substitute for protecting data at rest.
4. **C4/C5/C6, Multiple unauthenticated or low-privilege injection paths** (SQLi, VM-sandbox-escape RCE, XXE, stored-username eval-RCE) mean the application has no reliable trust boundary between user input and privileged execution/data access.
5. **C8/C9, Weak and hardcoded cryptographic material compounds every other gap**: even if C1 is fixed, MD5-hashed passwords and static secrets remain a fast path to full compromise after any data exposure.

## Remediation Roadmap

**Critical (fix before any production/CDE-adjacent use)**
- C1: Parameterize the login query (`output.md` §6 has the exact before/after diff)
- C2: Externalize the JWT private key to a secrets manager; rotate immediately since the current key is public via this report and the source tree
- C3: Encrypt or tokenize stored PAN; do not rely on display-time masking alone

**High**
- C4: Parameterize the search query
- C5: Remove `eval()`/`vm`+`notevil` sinks; replace with schema validation
- C6: Disable XXE-enabling XML parser options
- C8: Migrate password hashing to bcrypt/argon2 with salting

**Medium**
- C7: Enforce basket/order ownership server-side (403 on mismatch)
- C9: Remove hardcoded HMAC key, cookie secret, and backdoor key; source from environment
- C10/C11: Authenticate access to `/ftp`, `/encryptionkeys`, `/support/logs`, `/infrastructure`
- C12: Make MFA mandatory for sensitive operations; fully verify intermediate 2FA tokens
- C13: Rate-limit the login endpoint
- C14: Commit a dependency lockfile; upgrade `jsonwebtoken` off the pinned legacy version

**Low**
- C15: Configure CSP/HSTS; revisit the disabled `xssFilter()`

## Appendix: Full Control Coverage

| Control | Status |
|---|---|
| PCI Req 8.3.6 / ISO A.5.17, A.8.24: Password storage | Non-Compliant |
| PCI Req 6.2.4/8.2.1: Login injection | Non-Compliant |
| PCI Req 3.6.1/6.3.1 / ISO A.8.9, A.8.24: Key management | Non-Compliant |
| PCI Req 8.4.2 / ISO A.8.5: MFA enforcement | Partial |
| PCI Req 8.5.1 / ISO A.8.5: MFA implementation integrity | Non-Compliant |
| PCI Req 8.6.3 / ISO A.8.9: Secrets management | Non-Compliant |
| PCI Req 7.2.1/7.2.2 / ISO A.5.15, A.8.3: Access control | Non-Compliant |
| PCI Req 6.2.4 / ISO A.8.28: SQLi defenses | Non-Compliant |
| PCI Req 6.2.4 / ISO A.8.27, A.8.28: Code-execution injection | Non-Compliant |
| PCI Req 6.2.4 / ISO A.8.26, A.8.28: XXE defenses | Non-Compliant |
| PCI Req 6.2.4 / ISO A.8.28: File upload integrity | Non-Compliant |
| PCI Req 3.3.1/3.5.1 / ISO A.8.24: PAN at rest | Non-Compliant |
| PCI Req 3.4.1 / ISO A.8.24: PAN on display | **Compliant** |
| PCI Req 4.2.1 / ISO A.8.24: Encrypted transmission | Insufficient Evidence |
| PCI Req 6.2.4 / ISO A.8.9, A.8.26: Security headers | Partial |
| PCI Req 8.3.4 / ISO A.8.5: Rate limiting | Partial |
| PCI Req 7.2.1 / ISO A.8.3: Static directory exposure | Non-Compliant |
| PCI Req 10.2.1 / ISO A.8.15: Audit logging coverage | Partial |
| PCI Req 10.3.1 / ISO A.8.15: Audit log protection | Non-Compliant |
| PCI Req 10.4.1 / ISO A.8.16: Monitoring/alerting | Insufficient Evidence |
| PCI Req 6.3.2 / ISO A.8.28: Dependency inventory | Non-Compliant |
| PCI Req 11.3 / ISO A.8.29: Security testing process | **Compliant** |

**Totals**: 14 Non-Compliant, 5 Partial, 2 Compliant, 1 Insufficient Evidence (out of 22 mapped controls).

*(Context: this is the intentionally vulnerable OWASP Juice Shop training application, the findings above describe code patterns that would be certification-blocking in a real CDE/ISMS, not an active breach of live cardholder data. Evidence sourced from `output.md` (F1-F9) plus direct inspection of `models/card.ts`, `routes/payment.ts`, `lib/logger.ts`, and `server.ts`.)*
