# Snyk Scan Report 2: OWASP Juice Shop v20.2.0

| | |
|---|---|
| Scan date | 2026-10-11 |
| Snyk CLI | 1.1308.0 (Homebrew, `snyk/tap`) |
| Tooling | Snyk MCP server over stdio (`snyk_sca_scan`, `snyk_code_scan`, `snyk_secret_scan`, `snyk_iac_scan`, `snyk_container_scan`, `snyk_sbom_scan`) |
| Snyk org | Not recorded here |
| Target | Repository root, including `frontend/`, both Terraform folders and the published container image |
| Companion report | `report_scan.md` (first run, compared in the last section) |

Juice Shop is a deliberately vulnerable training app. Many findings below are intentional, either as challenge code or as old pinned packages. Read this report as a picture of what the code looks like to a scanner, not as a list of accidental bugs.

## Contents

1. [Summary](#1-summary)
2. [Dependencies (SCA)](#2-dependencies-sca)
3. [Source code (SAST)](#3-source-code-sast)
4. [Secrets](#4-secrets)
5. [DAST](#5-dast)
6. [SBOM](#6-sbom)
7. [Infrastructure as Code (Terraform)](#7-infrastructure-as-code-terraform)
8. [Container image](#8-container-image)
9. [Limits of this run](#9-limits-of-this-run)
10. [Comparison with report_scan.md](#10-comparison-with-report_scanmd)

---

## 1. Summary

| # | Scan | Type | Result |
|---|---|---|---|
| 1 | Dependencies, with dev dependencies, all severities | SCA | 115 issues: 5 critical, 59 high, 49 medium, 2 low |
| 2 | Source code | SAST | 293 results: 26 high, 11 medium, 256 low |
| 3 | Secrets | Secret scan | **Not run, re-tried.** Feature still disabled on the org (SNYK-CLI-0016); needs an admin to enable it in the web UI |
| 4 | Running application | DAST | **Not run.** Not available through the Snyk MCP server |
| 5 | SBOM (714 components, CycloneDX 1.5) | SBOM | 102 issues: 5 critical, 50 high, 45 medium, 2 low |
| 6 | Terraform, `terraform/` and `infrastructure/terraform/` | IaC | 10 issues in each folder: 0 critical, 0 high, 3 medium, 7 low |
| 7 | Published image `bkimminich/juice-shop:v20.2.0` | Container | 173 issues: 50 in the OS layer, 123 in app dependencies |
| 8 | Dockerfiles | IaC | Not supported by the IaC scanner (see section 8) |

Highest-impact items:

- **Dependencies:** `multer`, `handlebars`, `decompress` and `marsdb` carry the 5 critical issues. Upgrading `multer` alone clears 12 issues.
- **Code:** SQL injection, NoSQL injection, path traversal, SSRF, XSS and hardcoded keys (26 high).
- **Container:** 7 critical application issues, including `undici`, `proxy-addr` and `notevil`, which appear in the image but not in the source scan.
- **Terraform:** open ingress on a public load balancer and an HTTP-only listener, both medium.

Preparation: `node_modules` already existed from `npm install --ignore-scripts` in the earlier run, in the repo root and in `frontend/`. No postinstall scripts ran, and no tracked files changed.

---

## 2. Dependencies (SCA)

Command options: `all_projects`, `dev`, excluding `node_modules`, `test` and `data`. Snyk found two projects.

| Severity | Root `package.json` | `frontend/package.json` | Total |
|---|---|---|---|
| Critical | 5 | 0 | 5 |
| High | 50 | 9 | 59 |
| Medium | 45 | 4 | 49 |
| Low | 2 | 0 | 2 |
| **Total** | **102** | **13** | **115** |

### Critical

| Package | Issue | Fix |
|---|---|---|
| `multer@1.4.5-lts.2` (direct) | Uncaught exception | `multer@2.0.1` (`2.3.0` covers all multer issues) |
| `handlebars@4.7.9`, via `hbs@4.3.1` (2 issues) | Incomplete list of disallowed inputs; type confusion | `handlebars@4.7.10` |
| `decompress@4.2.1`, via `download@8.0.0` | Directory traversal | No fix listed |
| `marsdb@0.6.11` (direct) | Arbitrary code injection | No fix listed |

### Most affected packages

| Package | Issues | Package | Issues |
|---|---|---|---|
| `multer` | 12 | `uri-js` | 6 |
| `sanitize-html` | 12 | `moment` | 5 |
| `tar` | 12 | `ws` | 5 |
| `lodash` | 9 | `jsonwebtoken` | 4 |
| `decompress` | 6 | `handlebars` | 3 |
| `socket.io-parser` | 6 | `http-cache-semantics` | 3 |

### Suggested fix order

1. `multer` to 2.3.0 (about 12 issues, including one critical).
2. `handlebars` to 4.7.10, through `hbs` or an override.
3. `socket.io` to 4.8.0 and `socket.io-client` to 4.5.0 or later.
4. `sqlite3` to 6.0.1, which clears the `tar` issues.
5. Decide what to do about `decompress` and `marsdb`, which have no listed fix.
6. Review the deliberately old pins (`express-jwt`, `jsonwebtoken`, `sanitize-html`) against the challenge definitions before changing them.

---

## 3. Source code (SAST)

Snyk Code returned **293 results**: 26 high, 11 medium and 256 low. Most of the volume is test fixtures. 235 results are under `test/`, and 229 of those are low-severity hardcoded passwords, secrets and credentials (148, 47 and 33), plus 6 cleartext HTTP notes and 1 hardcoded secret.

| Location | Results |
|---|---|
| `test/` | 235 |
| `routes/` | 32 |
| `frontend/` | 10 |
| `lib/` | 6 |
| `server.ts` | 5 |
| `data/` (challenge code fixes) | 3 |
| `models/`, `scripts/` | 1 each |

### High severity (26)

| Issue | Count | Locations |
|---|---|---|
| SQL injection | 5 | `routes/login.ts:34`, `routes/search.ts:23`; `data/static/codefixes/` (3, challenge example code) |
| NoSQL injection | 5 | `routes/likeProductReviews.ts:25,35,43,50`, `routes/updateProductReviews.ts:17` |
| Path traversal | 6 | `routes/fileServer.ts:32`, `routes/keyServer.ts:14`, `routes/logfileServer.ts:14`, `routes/quarantineServer.ts:14`, `routes/fileUpload.ts:34`, `routes/profileImageUrlUpload.ts:29` |
| Cross-site scripting | 4 | `routes/recycles.ts:17`, `routes/userProfile.ts:101`, `frontend/src/app/search-result/search-result.component.ts:144`, `frontend/src/app/track-result/track-result.component.ts:49` |
| Hardcoded secret | 3 | `lib/insecurity.ts:20,21,42` |
| Hardcoded non-cryptographic secret | 2 | `lib/insecurity.ts:21,52` |
| SSRF | 1 | `routes/profileImageUrlUpload.ts:24` |

### Medium severity (11)

| Issue | Count | Locations |
|---|---|---|
| No limit on resource allocation (no rate limiting) | 5 | `routes/easterEgg.ts:12`, `routes/premiumReward.ts:12`, `routes/privacyPolicyProof.ts:12`, `routes/profileImageUrlUpload.ts:17`, `routes/videoHandler.ts:51` |
| Prototype pollution | 2 | `routes/vulnCodeFixes.ts:92`, `routes/vulnCodeSnippet.ts:110` |
| Insecure JWT verification | 1 | `routes/authenticatedUsers.ts:20` |
| Hardcoded password | 1 | `models/index.ts:33` |
| Open redirect | 1 | `routes/redirect.ts:18` |
| Cross-site scripting | 1 | `frontend/src/app/last-login-ip/last-login-ip.component.ts:40` |

### Low severity in application code

Improper type validation (12), hardcoded passwords (6) and weak password hashing (2, MD5, see `lib/insecurity.ts:41`).

Snyk Code does not flag the `eval()` calls in `routes/captcha.ts` and `routes/userProfile.ts`. That is a scanner gap and does not show those calls are safe.

---

## 4. Secrets

The secret scan did not run. Snyk returned `Feature not enabled (SNYK-CLI-0016)`, HTTP 403: Snyk Secrets is disabled for the org. **This is not a clean result. No secrets were checked.**

### Re-run on 2026-10-11

The scan was run a second time and returned the same error (`SNYK-CLI-0016`, HTTP 403). Snyk Secrets is still disabled for the org. It is an org-level setting in the Snyk web UI, so it cannot be turned on from the CLI or the MCP server. The result is still **not run**.

To enable it:

1. Sign in at `app.snyk.io` as an org admin for your Snyk org.
2. Open **Settings > Snyk Secrets** for that org and switch it on. If the option is missing, the plan may not include it. Ask Snyk or switch to an org that has it (`snyk config set org=<org>`).
3. Re-run the scan: `snyk secrets test` (or the `snyk_secret_scan` tool with `exclude=node_modules`).

One finding to expect: `terraform/networking.tf` and `infrastructure/terraform/networking.tf` contain a hardcoded RSA private key in `aws_iam_server_certificate.juice_shop_tls` (the `iacLeakedKeyChallenge` snippet). Snyk IaC did not flag it, so the secret scan is the first scanner likely to. It is deliberate challenge code. In a real project, the key would be moved out of the file (see section 7).

Until the scan runs, the SAST scan is the best evidence: it flags `lib/insecurity.ts:20,21,42,52` (RSA private key, HMAC secret) and `models/index.ts:33`. It looks at code patterns only, not at config files or git history.

---

## 5. DAST

DAST did not run, for two reasons:

- Snyk's DAST product (Snyk API & Web) is a separate hosted service. The Snyk MCP server does not expose it. Its tools cover code, SCA, secrets, IaC, containers, SBOM, AIBOM and package health.
- DAST needs a running target. None was started, and no DAST tool is installed on this machine (no ZAP or Nuclei found).

The repo already has `.github/workflows/zap_scan.yml` and `.zap/rules.tsv` for OWASP ZAP. Running ZAP against a local instance is the practical route to DAST coverage.

---

## 6. SBOM

The SBOM was generated with `snyk sbom --format cyclonedx1.5+json` and tested with Snyk's SBOM scan (Early Access).

| Item | Detail |
|---|---|
| Scope | Root project `juice-shop@20.2.0`; `frontend/` is not included |
| Format | CycloneDX 1.5 JSON |
| Components | 714, all npm with purls |
| Result | 102 issues across 109 vulnerable paths |
| File location | Scratch folder, not saved in the repo |

| Severity | Issues |
|---|---|
| Critical | 5 |
| High | 50 |
| Medium | 45 |
| Low | 2 |
| **Total** | **102** |

These counts match the root-project column in section 2 exactly, so the SBOM scan and the dependency scan agree.

### Upgrades Snyk recommends

| Upgrade | To | Issues fixed |
|---|---|---|
| `sanitize-html` (also clears `lodash`) | 2.17.6 | 21 |
| `multer` | 2.3.0 | 12 |
| `sqlite3` (clears `tar`) | 6.0.1 | 12 |
| `express-jwt` | 7.7.8 | 10 |
| `socket.io` (clears `engine.io`, `ws`, `socket.io-parser`) | 4.8.0 | 9 |
| `jsonwebtoken` | 9.0.0 | 7 |
| `i18n` | 0.14.0 | 2 |
| `pdfkit` (clears `crypto-js`) | 0.12.2 | 2 |
| `@cyclonedx/cyclonedx-npm` | 6.0.0 | 2 |
| `file-type` | 21.3.1 | 1 |
| `js-yaml` | 4.0.0 | 1 |

### No direct upgrade available

`libxmljs2@0.37.0` (2 high), `uri-js@4.4.1` (1 high, 2 medium), `http-cache-semantics` (2 high), `@tootallnate/once@1.1.2` (medium) and `inflight@1.0.6` (medium). The project's own SBOM tool `@cyclonedx/cyclonedx-npm@4.2.1` brings in most of them.

---

## 7. Infrastructure as Code (Terraform)

Terraform files exist in two places: `terraform/` and `infrastructure/terraform/`. Each folder was scanned separately. Results were not uploaded to Snyk.

The two folders are not exact copies. `main.tf` differs in three lines, which are file paths to the Dockerfile and compose file. `networking.tf`, `outputs.tf` and `variables.tf` are identical. All findings are in `networking.tf` and `main.tf`, so both folders return the same 10 issues.

| Path scanned | Files with issues | Files without issues | Issues |
|---|---|---|---|
| `terraform/` | 2 | 2 | 10 (3 medium, 7 low) |
| `infrastructure/terraform/` | 2 | 2 | 10 (3 medium, 7 low) |

### Medium

| Issue | Rule | Location | Fix |
|---|---|---|---|
| Security group `alb` allows open ingress (`ingress[0]`) | SNYK-CC-TF-1 | `networking.tf` | Restrict `cidr_block` |
| Security group `alb` allows open ingress (`ingress[1]`) | SNYK-CC-TF-1 | `networking.tf` | Restrict `cidr_block` |
| Load balancer listener does not enforce HTTPS (`aws_lb_listener[http]`) | SNYK-CC-TF-47 | `networking.tf` | Set `protocol` to `HTTPS` or `TLS` |

### Low

| Issue | Rule | Location | Fix |
|---|---|---|---|
| Open egress on security groups `ecs`, `efs`, `alb` (3 issues) | SNYK-CC-TF-73 | `networking.tf` | Limit `egress.cidr_blocks` |
| Load balancer is internet facing | SNYK-CC-TF-48 | `networking.tf` | Set `internal` to `true` if public access is not needed |
| Public IPs auto-assigned in subnet `public` | SNYK-CC-AWS-427 | `networking.tf` | Set `map_public_ip_on_launch` to `false` |
| ALB does not drop invalid headers | SNYK-CC-AWS-405 | `networking.tf` | Set `drop_invalid_header_fields` to `true` |
| CloudWatch log group has no customer-managed KMS key | SNYK-CC-AWS-415 | `main.tf` | Set `kms_key_id` |

Open ingress on a public load balancer is expected for a public web app. Confirm which ports are open before treating it as a defect. Nothing rated high or critical was found.

### Fixing the three medium issues

All three are in `networking.tf`. The file exists in both `terraform/` and `infrastructure/terraform/` and is identical, so make each change in both places. The root cause: the `alb` security group opens ports 80 and 443 to `0.0.0.0/0`, and the port 80 listener forwards plain HTTP straight to the app, although an HTTPS listener already exists in the same file.

**Step 1. Redirect HTTP to HTTPS (fixes SNYK-CC-TF-47).** Replace the `default_action` of `aws_lb_listener.http`:

```hcl
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.juice_shop.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
```

Traffic on port 80 now only receives a redirect, and the app is reached over TLS. The scanner should stop flagging the listener, but confirm with the re-scan in step 4.

**Step 2. Decide on the open ingress (SNYK-CC-TF-1, `ingress[0]` port 80 and `ingress[1]` port 443).** Pick the option that matches how the site is served:

| Option | When to use | Change |
|---|---|---|
| A. Accept the risk for 443 and keep 80 for the redirect | The site must be reachable by anyone on the internet, which is the case for a public web app | No Terraform change. Record the decision in a `.snyk` policy file with a reason and an expiry date (step 3) |
| B. Put CloudFront or a WAF in front and allow only it | The site has a CDN or can have one | Replace `cidr_blocks` on both ingress rules with `prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]`, using the AWS-managed `com.amazonaws.global.cloudfront.origin-facing` prefix list |
| C. Restrict to known networks | Internal or demo use, such as a training session | Replace `0.0.0.0/0` with your office or VPN CIDR in `cidr_blocks` |

For option B, add:

```hcl
data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}
```

For option A, a further tidy-up is to remove the port 80 ingress rule once nothing needs the redirect, which clears `ingress[0]`.

**Step 3. If you accept the risk (option A), document it.** Create `.snyk` in the repo root:

```yaml
version: v1.25.0
ignore:
  SNYK-CC-TF-1:
    - 'terraform/networking.tf > resource > aws_security_group[alb] > ingress[1]':
        reason: Public web app; port 443 must be reachable from the internet
        expires: 2027-04-11T00:00:00.000Z
```

Check the exact path format against `snyk iac test` output before relying on it. Do not ignore the port 80 rule if you can remove it.

**Step 4. Verify.** Run `terraform fmt` and `terraform validate` in each folder, then re-run `snyk iac test terraform/ infrastructure/terraform/`. Expect the medium count to fall from 3 to 0 (option B or C) or to 1 or 0 with an ignore recorded (option A). The 7 low issues will remain unless you also fix them (`internal`, `map_public_ip_on_launch`, `drop_invalid_header_fields`, egress rules, `kms_key_id`).

**Related issue the scanner did not flag.** `aws_iam_server_certificate.juice_shop_tls` embeds an RSA private key in plain text. In a real deployment, read it from a file kept out of git, a Terraform variable marked `sensitive = true`, or use an ACM certificate instead (`aws_acm_certificate`), so no key is stored in the code. Here it is deliberate challenge content, so leave it unless you are removing the challenge.

Remember that `networking.tf` is challenge code (`iacLeakedKeyChallenge`). Check `data/static/codefixes/iacLeakedKeyChallenge_*.tf` and the challenge tests before changing it, or work on a copy.

---

## 8. Container image

Docker is not installed on this machine, so Snyk pulled the published image `bkimminich/juice-shop:v20.2.0` (`linux/amd64`) from the registry. The repo's `Dockerfile` was passed as context. This is the official release image, not an image built from this checkout.

| Item | Detail |
|---|---|
| Base image | `gcr.io/distroless/nodejs24-debian13` |
| OS layer (deb) | 13 packages tested, 50 issues |
| Application layer (npm) | 643 packages tested, 123 issues |

### Dockerfile scanning

The repo has five container-related files: `Dockerfile`, `infrastructure/Dockerfile`, `test/smoke/Dockerfile`, `docker-compose.test.yml` and `infrastructure/docker-compose.yml`. The IaC scanner does not support Dockerfiles (SNYK-CLI-0012 in the first run), so none were analysed as IaC. The `Dockerfile` was used as context for the image scan only.

### OS layer: 50 issues (1 high, 49 low)

| Package | High | Low |
|---|---|---|
| `zlib/zlib1g` | 1 (out-of-bounds write, SNYK-DEBIAN13-ZLIB-19520500) | 1 |
| `openssl/libssl3t64` | 0 | 23 |
| `glibc/libc6` | 0 | 23 |
| `gcc-14/gcc-14-base` | 0 | 2 |

All come from the distroless base image, so the fix is a rebuild on a newer base.

### Application layer: 123 issues

| Severity | Count |
|---|---|
| Critical | 7 |
| High | 54 |
| Medium | 59 |
| Low | 3 |
| **Total** | **123** |

| Critical | Fix |
|---|---|
| `undici@5.29.0`: CRLF injection | Not listed |
| `multer@1.4.5-lts.2`: uncaught exception | `multer@2.0.1` |
| `decompress@4.2.1`: directory traversal | No fix |
| `handlebars@4.7.9`: 2 issues | `handlebars@4.7.10` |
| `marsdb@0.6.11`: arbitrary code injection | No fix |
| `proxy-addr@2.0.7`, via `express@4.22.2`: user impersonation | `proxy-addr@2.0.8` |

Packages with the most issues: `undici` (13), `multer` (12), `sanitize-html` (12), `tar` (12), `lodash` (9), `decompress` (6), `moment` (5), `jsonwebtoken` (4), `ip-address` (4).

Findings present in the image but not in the source scan: `undici`, `proxy-addr`, `ip-address`, and `notevil@1.3.3` (sandbox bypass, medium, no fix; used by `routes/b2bOrder.ts`).

---

## 9. Limits of this run

- The secret scan is blocked until Snyk Secrets is enabled.
- DAST was not possible with the available tooling.
- The container scan covers the published image, not an image built from this checkout.
- The SBOM covers the root project only.
- Dockerfiles, Docker Compose files and `vagrant/` were not analysed.
- No lockfile is committed, so SCA results reflect whatever versions npm resolved at scan time.
- Findings were not checked for exploitability or reachability.
- This was a one-off scan. `snyk monitor` would track new vulnerabilities over time.

---

## 10. Comparison with report_scan.md

Both reports used the same tools, the same org and the same day. The headline numbers are the same except where noted.

| Area | `report_scan.md` | `report_scan_2.md` | Same? |
|---|---|---|---|
| SCA, all severities with dev | 115 (5 / 59 / 49 / 2) | 115 (5 / 59 / 49 / 2) | Yes |
| SCA, production only, high and above | 62 issues | Not run separately | Different scope |
| SAST | 293 (26 / 11 / 256) | 293 (26 / 11 / 256) | Yes |
| Secret scan | Not run (403) | Not run (403) | Yes |
| DAST | Not run | Not run | Yes |
| SBOM | 714 components, 102 issues, CycloneDX 1.6 | 714 components, 102 issues, CycloneDX 1.5 | Counts yes, format differs |
| Terraform | 10 issues (3 medium, 7 low) | 10 issues (3 medium, 7 low) | Yes |
| Container, OS layer | 50 (1 high, 49 low) | 50 (1 high, 49 low) | Yes |
| Container, app layer | 123 (7 / 54 / 59 / 3) | 123 (7 / 54 / 59 / 3) | Yes |

### Differences

1. **Production-only dependency scan.** The first report ran a second SCA scan limited to production dependencies and high severity (62 issues). This one ran only the full scan, so there is no 62 figure here. The 64 high and critical issues in the full scan include 2 from dev dependencies, which is what the first report found too.
2. **SBOM format.** The first report used CycloneDX 1.6. This one used 1.5, generated with `snyk sbom --format cyclonedx1.5+json`. The component list (714) and issue counts did not change.
3. **Terraform folders.** The first report said the two folders "suggest" identical copies and did not compare them. They are not identical: `terraform/main.tf` and `infrastructure/terraform/main.tf` differ in three path lines. The findings are the same because those lines do not affect any Snyk rule.
4. **Severity labels in SAST.** The first report used the CLI's labels (error, warning, note). The tool now returns High, Medium and Low. The counts map one to one (26, 11, 256). This report also shows frontend XSS results (3 of the 5 XSS findings: `search-result`, `track-result` and `last-login-ip` components), which the first report only mentioned as "outside these routes".
5. **zod version.** The source scan resolved `zod@4.6.5` and the image has `zod@4.4.3`. `package.json` declares `^4.4.3` and there is no lockfile, so the version depends on when npm installed it. Both versions carry the same high-severity issue (SNYK-JS-ZOD-20510278).
6. **Dockerfile coverage.** This report lists all container files in the repo. The first listed only the root `Dockerfile`.
7. **Items the first report covered that this one does not repeat.** The mapping to `threat.md` and the compliance report, the `eval()` observation in `routes/captcha.ts` (kept here as a short note) and the detailed per-package SCA tables.

### Why the results match

- **Same inputs.** The code, the installed `node_modules`, the Snyk org and the published image `v20.2.0` were unchanged between runs.
- **Same vulnerability database, same day.** Both runs queried Snyk within hours of each other, so no new advisories appeared in between.
- **Missing features stay missing.** Secrets are disabled at the org level and Snyk has no DAST tool in the MCP server. Neither report could run them, and both say so.
- **One tool upgrade only.** The CLI moved from Homebrew `snyk-cli` 1.1307.4 to `snyk/tap` 1.1308.0 between sessions. The scan output showed no change attributable to that.

If a future run differs, the likeliest causes are a new advisory in Snyk's database, a different set of resolved package versions (no lockfile), or an updated base image.
