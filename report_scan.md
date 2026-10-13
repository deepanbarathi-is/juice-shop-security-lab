# Snyk Scan Report: OWASP Juice Shop v20.2.0

| | |
|---|---|
| Scan date | 2026-10-11 |
| Tooling | Snyk MCP (`snyk_sca_scan`, `snyk_code_scan`, `snyk_secret_scan`, `snyk_iac_scan`, `snyk_container_scan`) |
| Snyk org | Not recorded here |
| Target | Repository root, including `frontend/` and the Terraform folders |

Juice Shop is a deliberately vulnerable training app. Many findings below are intentional, either as challenge code or as old pinned packages. Read this report as a picture of what the code looks like to a scanner, not as a list of accidental bugs.

## Contents

1. [Dependencies: production, high and critical](#1-dependencies-production-high-and-critical)
2. [Dependencies: dev dependencies and all severities](#2-dependencies-dev-dependencies-and-all-severities)
3. [SAST with Snyk Code](#3-sast-with-snyk-code)
4. [DAST](#4-dast)
5. [Secret scan](#5-secret-scan)
6. [Gaps remaining](#6-gaps-remaining)
7. [Infrastructure as Code: Terraform](#7-infrastructure-as-code-terraform)
8. [Container image scan](#8-container-image-scan)
9. [SBOM scan](#9-sbom-scan)

## Summary

| # | Scan | Type | Result |
|---|---|---|---|
| 1 | Dependencies, production only, high and above | SCA | 62 issues (7 in `frontend/`, 55 in the root) |
| 2 | Dependencies, with dev dependencies, all severities | SCA | 115 issues: 5 critical, 59 high, 49 medium, 2 low |
| 3 | Source code | SAST | 293 results: 26 error, 11 warning, 256 note |
| 4 | Running application | DAST | Not run |
| 5 | Secrets | Secret scan | Not run (feature disabled on the org) |
| 6 | Dockerfile | IaC | Not supported by the IaC scanner |
| 7 | Terraform | IaC | 10 issues: 0 critical, 0 high, 3 medium, 7 low |
| 8 | Published image `bkimminich/juice-shop:v20.2.0` | Container | 173 issues: 50 in the OS layer (1 high, 49 low), 123 in app dependencies (7 critical, 54 high, 59 medium, 3 low) |
| 9 | SBOM of the root project (714 components) | SBOM | 102 issues: 5 critical, 50 high, 45 medium, 2 low |

Preparation: `npm install --ignore-scripts` was run in the repo root (1,314 packages) and in `frontend/` (710 packages). Skipping scripts meant no postinstall code ran. `node_modules` is gitignored, and no tracked files changed.

---

## 1. Dependencies: production, high and critical

62 issues. Snyk scanned two projects: `package.json` and `frontend/package.json`.

### Critical

| Package | Issue | Introduced by | Fix |
|---|---|---|---|
| `multer@1.4.5-lts.2` (direct) | Uncaught exception, CVE-2025-48997 | `package.json` | `multer@2.0.1` (`2.3.0` covers all multer issues) |
| `handlebars@4.7.9` (2 issues) | Incomplete input filtering; type confusion (CWE-94) | `hbs@4.3.1` | `handlebars@4.7.10` |
| `decompress@4.2.1` | Directory traversal, CVE-2026-101894 | `download@8.0.0` | No fix version listed |
| `marsdb@0.6.11` (direct) | Arbitrary code injection | `package.json` | No fix version listed |

### High, grouped by package

| Package or chain | Issues | Fix |
|---|---|---|
| `express-jwt@0.1.3`, which pulls in `jsonwebtoken@0.1.0` and `moment@2.0.0` | Authorization bypass (CVE-2020-15084), authentication bypass (CVE-2015-9235), directory traversal | `express-jwt@6.0.0` |
| `jsonwebtoken@0.4.0` → `jws@0.2.6`, `base64url@0.0.6` | Signature verification flaws, forgeable tokens (CVE-2025-65945, CVE-2016-1000223) | Upgrade `jsonwebtoken` |
| `sanitize-html@1.4.2` → `lodash@2.4.2` | Prototype pollution and code injection (CVE-2021-23337, CVE-2019-10744 and others) | `sanitize-html@1.7.1` or later |
| `socket.io@3.1.2` (backend), `socket.io-client@3.1.3` (frontend), with `engine.io`, `socket.io-parser`, `ws` | Denial of service | `socket.io@4.8.0`; client `4.5.0` or later |
| `sqlite3@5.1.7` → `tar@6.2.1` | Directory traversal, symlink attacks, infinite loop, resource exhaustion | `sqlite3@6.0.1` |
| `multer@1.4.5-lts.2` | About 11 DoS, recursion and race condition issues | `multer@2.3.0` |
| `@cyclonedx/cyclonedx-npm`, `libxmljs2`, `pdfkit` → `crypto-js`, `zod`, `minimatch`, `uri-js`, `http-cache-semantics` | Command injection, type confusion, weak hash, ReDoS, infinite loop and others | Per package |

### A caution before upgrading

`express-jwt`, `jsonwebtoken`, `sanitize-html` and similar packages are pinned to very old versions. Juice Shop does this on purpose for some challenges. I did not check the pins against the challenge definitions, so compare them with the challenges and the project's tests before upgrading anything.

---

## 2. Dependencies: dev dependencies and all severities

This run used `dev: true` and no severity filter. It found 115 issues.

| Severity | Root `package.json` | `frontend/package.json` | Total |
|---|---|---|---|
| Critical | 5 | 0 | 5 |
| High | 50 | 9 | 59 |
| Medium | 45 | 4 | 49 |
| Low | 2 | 0 | 2 |
| **Total** | **102** | **13** | **115** |

### Change from section 1

- High and critical issues rose from 62 to 64. The root stays at 55, and `frontend/` goes from 7 to 9. The two extra come from dev dependencies.
- The other 51 issues are medium or low severity, which section 1 filtered out. Almost all are in the root project.
- The five critical findings are the same.

### Most affected packages, all severities

| Package | Issues |
|---|---|
| `multer` | 12 |
| `sanitize-html` | 12 |
| `tar` | 12 |
| `lodash` | 9 |
| `decompress` | 6 |
| `socket.io-parser` | 6 |
| `uri-js` | 6 |
| `moment` | 5 |
| `ws` | 5 |
| `jsonwebtoken` | 4 |

Single-issue packages include `cookie`, `express-jwt`, `file-type`, `got` and `hbs`. For comparison, `npm audit` counted 50 vulnerabilities in the root and 28 in `frontend/` across all severities. It uses a different advisory database.

### Suggested fix order

1. Upgrade `multer` to 2.3.0. One change clears about 12 issues.
2. Upgrade `handlebars` to 4.7.10, through `hbs` or an override.
3. Upgrade `socket.io` to 4.8.0 and `socket.io-client` to 4.5.0 or later.
4. Upgrade `sqlite3` to 6.0.1, which clears the `tar` issues.
5. Decide what to do about `decompress` and `marsdb`, which have no listed fix.
6. Review the deliberately old pins (`express-jwt`, `jsonwebtoken`, `sanitize-html`) against the challenges before changing them.

---

## 3. SAST with Snyk Code

Snyk Code was not enabled on the org at first (error SNYK-CODE-0005, HTTP 403). It was then enabled and the scan ran.

The scan returned **293 findings**: 26 error, 11 warning and 256 note. Most of the volume is noise. 235 results are under `test/`, and 153, 49 and 33 of them are hardcoded passwords, secrets and credentials in test fixtures, all at severity note.

### Errors and warnings in application code

| Issue | Severity | Locations |
|---|---|---|
| SQL injection | Error | `routes/login.ts:34`, `routes/search.ts:23`; also 3 in `data/static/codefixes/` (challenge example code) |
| NoSQL injection | Error | `routes/likeProductReviews.ts:25,35,43,50`, `routes/updateProductReviews.ts:17` |
| Path traversal | Error | `routes/fileServer.ts:32`, `routes/keyServer.ts:14`, `routes/logfileServer.ts:14`, `routes/quarantineServer.ts:14`, `routes/fileUpload.ts:34`, `routes/profileImageUrlUpload.ts:29` |
| SSRF | Error | `routes/profileImageUrlUpload.ts:24` |
| Cross-site scripting | Error | `routes/recycles.ts:17`, `routes/userProfile.ts:101` (4 errors and 1 warning in total; the others are outside these routes) |
| Hardcoded secret | Error | `lib/insecurity.ts:20,21,42`; also flagged as a non-crypto secret at `:21` and `:52` |
| Insecure JWT decode | Warning | `routes/authenticatedUsers.ts:20` |
| Open redirect | Warning | `routes/redirect.ts:18` |
| Prototype pollution | Warning | `routes/vulnCodeFixes.ts:92`, `routes/vulnCodeSnippet.ts:110` |
| No rate limiting on expensive operations | Warning | `routes/easterEgg.ts:12`, `routes/premiumReward.ts:12`, `routes/privacyPolicyProof.ts:12`, `routes/profileImageUrlUpload.ts:17`, `routes/videoHandler.ts:51` |
| Hardcoded password | Warning | `models/index.ts:33` |
| Weak password hash | Note | 2 results (MD5, see `lib/insecurity.ts:41`) |
| Cleartext transmission (HTTP) | Note | 6 results |

### Comparison with the earlier manual review

Snyk Code confirmed several points from `threat.md` and the compliance report: SQL injection in login and search, the hardcoded JWT key and HMAC secret in `lib/insecurity.ts`, SSRF in the profile image URL fetch, the open redirect and MD5 hashing. The path traversal at `routes/fileUpload.ts:34` also supports the file-upload risk in `threat.md` (T-06), which was unverified until now.

It also found issues that neither document had listed: NoSQL injection in the product review routes, path traversal in the file-serving routes, XSS at `routes/recycles.ts:17` and `routes/userProfile.ts:101`, prototype pollution in the vuln-code routes, and the JWT decode warning.

It did not flag the `eval()` calls in `routes/captcha.ts:22` and `routes/userProfile.ts:65`, which the manual review had listed. That is a scanner gap and does not show those calls are safe.

---

## 4. DAST

DAST was not run, for two reasons:

- Snyk's DAST product (Snyk API & Web) is a separate hosted service that attacks a live target. The Snyk MCP server does not expose it. Its tools cover code, SCA, secrets, IaC, containers, SBOM, AIBOM and package health.
- DAST needs a running application, and none was started for this report.

The repo already has `.github/workflows/zap_scan.yml` and `.zap/rules.tsv` for OWASP ZAP. Running ZAP against a local instance is the practical route to DAST coverage.

---

## 5. Secret scan

The secret scan was attempted and did not run. Snyk returned `Feature not enabled (SNYK-CLI-0016)`, HTTP 403: Snyk Secrets is disabled for the org. **This is not a clean result. No secrets were checked.**

To enable it, open Settings > Snyk Secrets for the organization in the Snyk web UI, turn it on, and run the scan again.

Until then, the best evidence for hardcoded secrets is the SAST scan in section 3, which flags `lib/insecurity.ts:20,21,42` (RSA private key and HMAC secret) and `models/index.ts:33`. It does not replace a secret scan. Snyk Code looks at code patterns, not at secrets in config files, git history or other file types.

---

## 6. Gaps remaining

- The secret scan is blocked until Snyk Secrets is enabled (section 5).
- The Dockerfile has not been analysed directly. The IaC scanner does not support Dockerfiles. The container scan in section 8 covers the published image and used the Dockerfile only as context.
- The container scan ran on the published image, not on an image built from this checkout.
- The SBOM in section 9 covers the root project only. No SBOM was generated for `frontend/`, and the SBOM file was written to a temporary folder, not saved in the repo.
- Docker Compose files and the `vagrant/` folder have not been scanned.
- Dependency findings were not checked for exploitability or reachability. Many are DoS issues in transitive packages.
- No lockfile is committed, so the SCA results reflect whatever versions npm resolved at scan time.
- This was a one-off scan. `snyk monitor` would track new vulnerabilities over time.

---

## 7. Infrastructure as Code: Terraform

The IaC scan covers Terraform, Kubernetes, CloudFormation, ARM and Serverless files. It returned `Could not find any valid IaC files` (SNYK-CLI-0012) for the root `Dockerfile`, so it was run on the Terraform folders instead. Results were not uploaded to Snyk.

| Path scanned | Files with issues | Files without issues | Issues |
|---|---|---|---|
| `terraform/` | 2 | 2 | 10 (3 medium, 7 low) |
| `infrastructure/` (includes `infrastructure/terraform/`) | 2 | 2 | 10 (3 medium, 7 low) |

Both scans returned identical findings, which suggests the two folders hold copies of the same configuration. They were not compared directly.

### Medium

| Issue | Rule | Location | Fix |
|---|---|---|---|
| Security group `alb` allows open ingress (`ingress[0]`) | SNYK-CC-TF-1 | `networking.tf` | Restrict `cidr_block` |
| Security group `alb` allows open ingress (`ingress[1]`) | SNYK-CC-TF-1 | `networking.tf` | Restrict `cidr_block` |
| Load balancer listener does not enforce HTTPS (`aws_lb_listener[http]`) | SNYK-CC-TF-47 | `networking.tf` | Set `protocol` to `HTTPS` or `TLS` |

### Low

| Issue | Rule | Location | Fix |
|---|---|---|---|
| Open egress on security group `ecs` | SNYK-CC-TF-73 | `networking.tf` | Limit `egress.cidr_blocks` |
| Open egress on security group `efs` | SNYK-CC-TF-73 | `networking.tf` | Limit `egress.cidr_blocks` |
| Open egress on security group `alb` | SNYK-CC-TF-73 | `networking.tf` | Limit `egress.cidr_blocks` |
| Load balancer is internet facing (`aws_lb[juice_shop]`) | SNYK-CC-TF-48 | `networking.tf` | Set `internal` to `true` if public access is not needed |
| Public IPs auto-assigned in subnet `public` | SNYK-CC-AWS-427 | `networking.tf` | Set `map_public_ip_on_launch` to `false` |
| ALB does not drop invalid headers | SNYK-CC-AWS-405 | `networking.tf` | Set `drop_invalid_header_fields` to `true` |
| CloudWatch log group has no customer-managed KMS key | SNYK-CC-AWS-415 | `main.tf` | Set `kms_key_id` |

### Notes

- The HTTP-only listener matches the missing-TLS gap in `threat.md` (T-11) and the compliance report. Here it shows up in the infrastructure config.
- Open ingress on a public load balancer is expected for a public web app. Confirm which ports are open before treating it as a defect.
- Nothing rated high or critical was found in the Terraform.

---

## 8. Container image scan

Docker is not installed on this machine, so Snyk pulled the published image `bkimminich/juice-shop:v20.2.0` (platform `linux/amd64`) from the registry. The repo's `Dockerfile` was passed as context for remediation advice. This is the official release image, not an image built from this checkout, so local changes are not reflected.

| Item | Detail |
|---|---|
| Base image | `gcr.io/distroless/nodejs24-debian13` (target OS: Distroless) |
| OS layer (deb) | 13 packages tested, 50 issues |
| Application layer (npm) | 643 packages tested, 123 issues |
| Dockerfile (from `grep`) | Multi-stage build (`FROM node:24 AS installer`, then the distroless image); runs as `USER 65532` |

A multi-stage build, a distroless runtime and a non-root user are all good practice.

### OS layer: 50 issues

All come from the distroless base image, so they are fixed by rebuilding on a newer base, not by changes to Juice Shop.

| Package | High | Low | Notes |
|---|---|---|---|
| `zlib/zlib1g` | 1 | 1 | The high issue is an out-of-bounds write (SNYK-DEBIAN13-ZLIB-19520500) |
| `openssl/libssl3t64` | 0 | 23 | Example: CVE-2026-14456, fixed in `3.5.7-1~deb13u2` |
| `glibc/libc6` | 0 | 23 | |
| `gcc-14/gcc-14-base` | 0 | 2 | |
| **Total** | **1** | **49** | |

### Application layer: 123 issues

| Severity | Count |
|---|---|
| Critical | 7 |
| High | 54 |
| Medium | 59 |
| Low | 3 |
| **Total** | **123** |

Snyk printed 146 entries for these 123 issues, because some issues appear under more than one dependency path. The table counts each issue once.

**Critical findings**

| Package | Issue | Fix |
|---|---|---|
| `undici@5.29.0` | CRLF injection (SNYK-JS-UNDICI-17372658) | Not listed in the output I reviewed |
| `multer@1.4.5-lts.2` | Uncaught exception (SNYK-JS-MULTER-10299078) | `multer@2.0.1` (`2.3.0` covers all multer issues) |
| `decompress@4.2.1` | Directory traversal (SNYK-JS-DECOMPRESS-20254116) | No fix listed |
| `handlebars@4.7.9` (2 issues) | Incomplete input filtering; type confusion | `handlebars@4.7.10` |
| `marsdb@0.6.11` | Arbitrary code injection | No fix listed |
| `proxy-addr@2.0.7` | User impersonation (SNYK-JS-PROXYADDR-19812342), reached through `express@4.22.2` | `proxy-addr@2.0.8` |

**Packages with the most issues:** `undici` (13), `multer` (12), `sanitize-html` (12), `tar` (12), `lodash` (9), `decompress` (6), `moment` (5), `jsonwebtoken` (4), `ip-address` (4), `brace-expansion` (3), `handlebars` (3), `socket.io-parser` (3), `http-cache-semantics` (3).

### What is new compared with sections 1 and 2

- **Three packages did not appear in the source scans:** `undici` (13 issues, one critical), `proxy-addr` (critical, through `express`) and `ip-address` (4 issues). A likely reason is that the source scans resolved dependencies on this machine, while the image holds what was installed when it was built. I did not confirm this.
- **`notevil@1.3.3`: sandbox bypass (medium, no upgrade or patch available).** `routes/b2bOrder.ts:23` uses `notevil` to evaluate order data, so this is relevant to the code-execution risk in `threat.md` (T-14).
- **Other findings repeat sections 1 and 2:** `multer`, `handlebars`, `decompress`, `marsdb`, `tar`, `lodash`, `jsonwebtoken` and `moment` show up again in the image.

### Suggested actions

1. Rebuild the image on the latest `gcr.io/distroless/nodejs24-debian13`. A newer base may clear the OS-layer `zlib` high issue and some of the low ones, but the scan does not say which fixes are available.
2. Upgrade `proxy-addr` to 2.0.8 (check whether a newer `express` brings it in) and look at the `undici` fixes.
3. Apply the dependency upgrades listed in section 2, in the same order.
4. Re-run this scan after the rebuild, and again on an image built locally from this checkout.

---

## 9. SBOM scan

An SBOM (software bill of materials) lists every component in the project. This one was generated with `snyk sbom` in CycloneDX 1.6 JSON format and then tested with Snyk's SBOM scan. Snyk labels the SBOM test as Early Access, so its behaviour may change.

| Item | Detail |
|---|---|
| Scope | Root project (`juice-shop@20.2.0`); `frontend/` is not included |
| Components | 714, all npm packages with purls |
| Result | 102 issues across 109 vulnerable paths |
| File location | A temporary scratch folder, not the repo |

The project also has its own SBOM script (`npm run sbom`, which runs `cyclonedx-npm --omit=dev` and writes `bom.json`). It was not used here.

### Results by severity

| Severity | Issues |
|---|---|
| Critical | 5 |
| High | 50 |
| Medium | 45 |
| Low | 2 |
| **Total** | **102** |

These counts match the root-project column in section 2 exactly. The SBOM scan and the dependency scan agree, so this section adds the component inventory and Snyk's recommended upgrade versions, not new findings.

### Critical findings

| Component | Issue | Path |
|---|---|---|
| `marsdb@0.6.11` | Arbitrary code injection | Direct |
| `decompress@4.2.1` | Directory traversal | `download@8.0.0` |
| `handlebars@4.7.9` (2 issues) | Incomplete input filtering; type confusion | `hbs@4.3.1` |
| `multer@1.4.5-lts.2` | Uncaught exception | Direct |

### Upgrades Snyk recommends

Each upgrade below fixes the issues listed against that parent package.

| Upgrade | To | Issues fixed |
|---|---|---|
| `sanitize-html` (also brings `lodash` fixes) | 2.17.6 | 21, mostly XSS and prototype pollution |
| `multer` | 2.3.0 | 12, including the critical one |
| `sqlite3` (clears `tar`) | 6.0.1 | 12 |
| `express-jwt` | 7.7.8 | 10, across `moment` and `jsonwebtoken` |
| `socket.io` (clears `engine.io`, `ws`, `socket.io-parser`) | 4.8.0 | 9 |
| `jsonwebtoken` | 9.0.0 | 7, including `jws` and `base64url` |
| `i18n` | 0.14.0 | 2 |
| `pdfkit` (clears `crypto-js`) | 0.12.2 | 2 |
| `@cyclonedx/cyclonedx-npm` | 6.0.0 | 2 (command injection) |
| `file-type` | 21.3.1 | 1 |
| `js-yaml` | 4.0.0 | 1 (`sprintf-js`) |

The versions for `sanitize-html` (2.17.6) and `express-jwt` (7.7.8) are the versions that clear every listed issue. Sections 1 and 2 quote lower minimum versions (`1.7.1` and `6.0.0`) that fix only some of them. Remember the warning in section 1 about deliberately old pins before upgrading.

### Issues with no direct upgrade

| Component | Issue |
|---|---|
| `libxmljs2@0.37.0` | Type confusion (2 high), via `@cyclonedx/cyclonedx-npm` |
| `uri-js@4.4.1` | Infinite loop (high), uncaught exception and encoding issue (medium), via `@cyclonedx/cyclonedx-npm` |
| `http-cache-semantics` | Origin validation and authorization issues (2 high), via `download` and `sqlite3` |
| `@tootallnate/once@1.1.2` | Incorrect control flow scoping (medium); fixed in 2.0.1 and 3.0.1, but not reachable by upgrading a direct dependency |
| `inflight@1.0.6` | Resource release issue (medium), via `sqlite3` |

### Note on the SBOM tooling

The project's own SBOM generator, `@cyclonedx/cyclonedx-npm@4.2.1`, has two command injection issues (high) and pulls in `libxmljs2` and `uri-js`, which account for most of the no-upgrade items above. It is a build-time tool, and only an upgrade to 6.0.0 clears its own issues.
