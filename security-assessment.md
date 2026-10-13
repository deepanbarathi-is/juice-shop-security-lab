# Security Assessment: OWASP Juice Shop v20.2.0

| | |
|---|---|
| Assessment date | 2026-10-13 |
| Target | `juice-shop` repository (Node.js/Express, Angular, SQLite, Terraform, Docker) |
| Method | Four parallel read-only reviews: code analysis, secrets, dependencies, configuration. Findings were merged and deduplicated. Key file:line references were spot-checked against the source. |
| Prior evidence used | `report_scan_2.md` (Snyk SCA, SAST, IaC, container, SBOM scans of 2026-10-11) |
| Changes made to the repo | None |

Context. Juice Shop is a deliberately vulnerable training application. Most findings below are intentional challenge content. This report rates them as if the application were a real production system, which is how a scanner or an attacker sees it. The column "Intentional" marks challenge code.

## Contents

1. [Executive summary](#1-executive-summary)
2. [Findings: Part A challenge code, Part B hygiene](#2-findings)
3. [Remediation prioritisation matrix](#3-remediation-prioritisation-matrix)
4. [Top 5 immediate actions](#4-top-5-immediate-actions)
5. [Coverage and limitations](#5-coverage-and-limitations)
6. [Appendix A: architecture and trust boundaries](#appendix-a-architecture-and-trust-boundaries)
7. [Appendix B: key entry points](#appendix-b-key-entry-points)
8. [Appendix C: secrets inventory (redacted)](#appendix-c-secrets-inventory-redacted)
9. [Appendix D: dependency upgrade plan](#appendix-d-dependency-upgrade-plan)

---

## 1. Executive summary

Treated as a production system, Juice Shop has a critical risk posture. Anyone can bypass login with SQL injection, forge administrator tokens with a private key committed to the source, run code on the server through `eval`, and read keys, logs and backups from unauthenticated file directories. Dependencies carry 5 critical and 59 high Snyk issues, several from packages pinned to very old versions. The Terraform deployment exposes the app to the internet over plain HTTP and contains a second copy of a private key. This is acceptable only because the application is meant for training. It must run on an isolated network, with no real data and no internet exposure, and the Terraform in this repo should not be applied as a real deployment.

| Severity | Part A: challenge code | Part B: hygiene | Total rows |
|---|---|---|---|
| Critical | 5 | 1 | 6 |
| High | 13 | 2 | 15 |
| Medium | 6 | 6 | 12 |
| Low | 1 | 3 | 4 |
| **Total** | **25** | **12** | **37** |

The 34 distinct findings become 37 rows because three mixed findings (F-04, F-19, F-24) are split into a challenge part and a hygiene part. Part A is mostly what makes the app a training tool. Part B is the work list for anyone who deploys it: critical dependency fixes, cookie flags, TLS, security-group and container hardening, CI workflows and ignore files.

---

## 2. Findings

Findings are split by whether the weakness is deliberate Juice Shop challenge content (Part A) or needs action in any deployment (Part B). Sources: CODE = code analysis, SEC = secrets scan, DEP = dependency audit, CFG = configuration review, SNYK = the Snyk scans in `report_scan_2.md`. An issue found by several reviews is one finding with every source listed.

### Part A: Intentional challenge code (25 rows)

These weaknesses back a Juice Shop challenge. They are real vulnerabilities for any use outside a training lab, but fixing them would break the challenges. For a training deployment the control is isolation (Top 5, action 1), not code changes.

#### Critical

| ID | Finding | Location | Source | Remediation |
|---|---|---|---|---|
| F-01 | SQL injection in login and product search. Input is concatenated into raw SQL, giving login bypass as any user and UNION extraction of the Users table. | `routes/login.ts:34`, `routes/search.ts:23`, 3 snippets in `data/static/codefixes/` | CODE, SNYK | Use parameterised queries or bound replacements, return one generic login error, give the DB user least privilege. |
| F-02 | JWT RSA private key (1024-bit) hardcoded in source, also reused as an HMAC key. The public key and `/encryptionkeys` are served, and old `jsonwebtoken` and `express-jwt` do not enforce algorithms, so admin tokens can be forged. | `lib/insecurity.ts:21,150`, `encryptionkeys/` | SEC, CODE, DEP, SNYK | Generate the key at deploy time from a secrets manager, rotate it, stop serving `encryptionkeys/`, upgrade to `jsonwebtoken` 9 and `express-jwt` 8 with an explicit `algorithms` list. |
| F-03 | Remote code execution: the username is passed to `eval()`. | `routes/userProfile.ts:65` | CODE | Remove `eval`, render with an escaping template engine, allow-list the username. |
| F-04b | `marsdb@0.6.11` arbitrary code injection, no fix. It is the store behind the NoSQL challenges. | `package.json`, `data/mongodb.ts` | DEP, SNYK | Outside training, plan a data-layer rewrite. Otherwise isolate the deployment and record the accepted risk in a `.snyk` policy with an expiry. |
| F-05 | Private key embedded in `aws_iam_server_certificate` in both Terraform folders (separate directories that differ only in three path lines of `main.tf`). Snyk IaC did not report it because Snyk Secrets is off. | `terraform/networking.tf:171`, `infrastructure/terraform/networking.tf:171` | SEC, CFG | Remove and rotate the key. Use `aws_acm_certificate` or a `sensitive` variable. Add `*.tfstate*`, `*.tfvars` and `.terraform/` to `.gitignore`. |

#### High

| ID | Finding | Location | Source | Remediation |
|---|---|---|---|---|
| F-06 | HMAC key for password hashing and the cookie secret `kekse` are hardcoded, with no environment override. | `lib/insecurity.ts:42`, `server.ts:308` | SEC, CODE, CFG | Load both from environment or a secrets store and rotate them. |
| F-07 | NoSQL injection in reviews: `$where` strings and `_id` operator objects are built from request input, and updates use `multi: true`. | `routes/showProductReviews.ts:36`, `routes/updateProductReviews.ts:17-20`, `routes/likeProductReviews.ts:25-50` | CODE, SNYK | Validate `id` as a string, use plain equality queries, never `$where`, set `multi: false`. |
| F-08 | Path traversal and zip slip: the zip check does not stop escape from the upload folder, and several routes build paths from input. | `routes/fileUpload.ts:33-34`, `routes/fileServer.ts:32`, `keyServer.ts:14`, `logfileServer.ts:14`, `quarantineServer.ts:14`, `profileImageUrlUpload.ts:29` | CODE, SNYK | Resolve each path and check it starts with the intended base folder, reject `..`, use generated filenames. |
| F-09 | XXE (DTD and entity loading enabled) and YAML parsed inside a `vm` context. | `lib/xml.ts:36`, `routes/fileUpload.ts:76,108-109` | CODE | Disable DTDs and entities, use a safe YAML schema outside `vm`. |
| F-10 | SSRF: the server fetches any user-supplied URL and stores the response. | `routes/profileImageUrlUpload.ts:24` | CODE, SNYK | Allow-list hosts, block private and metadata ranges, fetch through a proxy with size and time limits. |
| F-11 | `notevil` inside `vm` evaluates B2B order data, and `eval` is used in the captcha. `notevil` is deprecated with an unfixed sandbox bypass. | `routes/b2bOrder.ts:21-23`, `routes/captcha.ts:22` | CODE, DEP | Remove evaluation and validate orders against a strict schema. |
| F-12 | Broken access control: the guard on `PUT /api/Products/:id` is commented out, `role` is accepted at registration, baskets and orders have IDOR, and there is no deny-by-default. | `server.ts:389,418,427-441`, `models/user.ts:76-94`, `routes/basket.ts:19` | CODE | Authenticate globally and opt routes out, allow-list fields, check ownership on every read and write. |
| F-13 | Unauthenticated exposure: `/ftp`, `/encryptionkeys` and `/support/logs` are listable, `/metrics` is public (registered twice), `application-configuration` is open, order PDFs go to public `ftp/`, and a KeePass file is tracked in `ftp/`. | `server.ts:288-302,625-626,695,750`, `routes/order.ts:45`, `ftp/incident-support.kdbx` | CODE, SEC | Remove these mounts or require admin auth, bind `/metrics` internally, store PDFs outside the web root. |
| F-14 | Unsalted MD5 password hashing. | `lib/insecurity.ts:41` | CODE, SNYK | Use argon2id or bcrypt with per-user salts and migrate on next login. |
| F-15 | XSS in several routes and in the `search-result`, `track-result` and `last-login-ip` frontend components, and no site-wide CSP. The profile page builds its CSP from user data and allows `unsafe-eval`. | `routes/recycles.ts:17`, `userProfile.ts:96,101`, `trackOrder.ts:17`, `createProductReviews.ts:23`, `server.ts:186-188` | CODE, CFG, SNYK | Set a fixed CSP with `helmet`, encode output, upgrade `sanitize-html`, validate `profileImage` as a URL. |
| F-17 | CORS allows every origin. | `server.ts:182-183` | CODE, CFG | `cors({ origin: [<your site>], credentials: true })`. |
| F-18 | Rate limiting is thin and bypassable. `trust proxy` has no hop count and the limiter key reads `headers['X-Forwarded-For']` (Node lowercases header names, so it falls back to a spoofable `ip`). 2FA allows 100 tries per 5 minutes with `validate: false`, and login has no limit. | `server.ts:361-366,478,485,491` | CFG, CODE | `app.set('trust proxy', 1)`, drop the custom key generator, limit login, 2FA and registration to about 5 to 10 per 15 minutes. |
| F-19b | Deliberately old pins: `sanitize-html@1.4.2` (12 issues), `express-jwt@0.1.3` (10), `jsonwebtoken@0.4.0` (7) and `notevil`. They back the XSS, forged-JWT and RCE challenges. | `package.json` | DEP, SNYK | Upgrade only if the challenges are dropped. Otherwise isolate the deployment and record the reasons in `.snyk` with expiry dates. |

#### Medium

| ID | Finding | Location | Source | Remediation |
|---|---|---|---|---|
| F-24b | End-of-life `mongo:4.4.29` image, marked as the vulnerable-image challenge. | `infrastructure/docker-compose.yml:50` | CFG | Use a supported tag pinned by digest outside training. |
| F-26 | Card numbers stored as plain numbers and masked only on read. No CVV is stored. | `models/card.ts:38`, `routes/payment.ts:31-58` | CODE | Do not store the PAN. Use a tokeniser or encrypt at rest. |
| F-27 | Open redirect: the allow-list uses `url.includes()`. | `routes/redirect.ts:14`, `lib/insecurity.ts:136` | CODE, SNYK | Exact-match allow-list of full URLs. |
| F-28 | Prototype pollution in the snippet routes, and unauthenticated WebSocket events. | `routes/vulnCodeFixes.ts:92`, `vulnCodeSnippet.ts:110`, `lib/startup/registerWebsocketEvents.ts:32-48` | CODE, SNYK | Validate keys, use a `Map`, authenticate sockets. |
| F-29 | Password change over GET with the passwords in the query string, and manual token parsing. | `routes/changePassword.ts:23-29` | CODE | Use POST with a body and the JWT middleware. |
| F-30 | Seeded plaintext passwords and a TOTP secret in `users.yml`, and the CTF key defaults to the tracked `ctf.key`. | `data/static/users.yml`, `ctf.key`, `lib/utils.ts:70-80` | SEC | Generate seed data for any non-training deployment, with no default credentials. |

#### Low

| ID | Finding | Location | Source | Remediation |
|---|---|---|---|---|
| F-33 | Chatbot prompt injection, an `X-Recruiting` header, the obsolete `Feature-Policy` header, and stack traces leaking through `errorhandler()` when manual `JSON.parse` fails. | `routes/chat.ts`, `server.ts:189-198,334-341,701` | CODE, CFG | Constrain the system prompt, use `Permissions-Policy`, disable `errorhandler()` in production. |

### Part B: Hygiene and unintentional gaps (12 rows)

These are not tied to a challenge, or could not be confirmed as challenge content (rows marked "Likely"). Fix them in any deployment, including a training one.

#### Critical

| ID | Finding | Location | Source | Intentional | Remediation |
|---|---|---|---|---|---|
| F-04a | Critical dependency drift: `multer@1.4.5-lts.2` (12 issues), `handlebars@4.7.9` via `hbs` (2), `decompress@4.2.1` via `download` (no fix), and in the image `undici@5.29.0` and `proxy-addr@2.0.7`. | `package.json`, image `bkimminich/juice-shop:v20.2.0` | DEP, SNYK | No | `multer` 2.x, `overrides` for `handlebars@^4.7.10` and `proxy-addr@^2.0.8`, replace `download` and `decompress`. See Appendix D. |

#### High

| ID | Finding | Location | Source | Intentional | Remediation |
|---|---|---|---|---|---|
| F-16 | The `token` cookie has no `httpOnly`, `secure`, `sameSite` or `maxAge`. | `lib/insecurity.ts:192`, `routes/updateUserProfile.ts:42` | CFG, CODE | Likely | `res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 6 * 3600 * 1000 })`. |
| F-19a | Outdated high-severity dependencies: `sqlite3` via `tar` (12), `socket.io` and `socket.io-client` 3.x (9), `lodash`, `moment`, `ws`, `crypto-js`, `libxmljs2`, `uri-js`, `http-cache-semantics`, `zod`, and 9 high issues in `frontend/`. | `package.json`, `frontend/package.json` | DEP, SNYK | No | Appendix D steps 2 to 6. No challenge depends on these. |

#### Medium

| ID | Finding | Location | Source | Intentional | Remediation |
|---|---|---|---|---|---|
| F-20 | The port 80 listener forwards plain HTTP (Snyk TF-47), the app sets no HSTS, and the ALB-to-container hop is HTTP. | `terraform/networking.tf:157-166`, `server.ts:186-187` | CFG, SNYK | Likely | Make the port 80 listener a `redirect` to HTTPS (`HTTP_301`) and add `helmet.hsts`. |
| F-21 | The ALB group opens ports 80 and 443 to `0.0.0.0/0` (TF-1, two issues) and three groups allow all egress (TF-73). | `terraform/networking.tf:68-80,82-87,108-113,235-240` | CFG, SNYK | Likely | Remove the port 80 rule after the redirect, front with CloudFront, WAF or a prefix list, restrict egress to the ECS, EFS and ALB groups. |
| F-22 | ECS tasks get public IPs in public subnets, with no `task_role_arn`, no read-only root filesystem, no container `user`, a mutable `latest` tag, EFS `iam = "DISABLED"`, and an ALB without `drop_invalid_header_fields`, access logs or deletion protection. | `terraform/networking.tf:23,122-127`, `terraform/main.tf:46,88,109` | CFG, SNYK | Likely | Private subnets with NAT or endpoints, a least-privilege task role, `readonlyRootFilesystem`, `user = "65532"`, immutable tags, the ALB attributes. |
| F-23 | Container build hygiene: floating base image tags, `COPY . /juice-shop` takes the repo into the image (including `ctf.key` and `encryptionkeys/`, which `.dockerignore` does not exclude), no `HEALTHCHECK`, `npm install` instead of `npm ci`, end-of-life Node 20 in the infrastructure Dockerfile, and a root user in the smoke-test image. | `Dockerfile:1,2,22,38`, `infrastructure/Dockerfile:1,6,11`, `test/smoke/Dockerfile` | CFG | No | Pin by digest, copy only the build output, add a Node `HEALTHCHECK`, use `npm ci --omit=dev`, set a non-root user. |
| F-24a | Compose and Vagrant gaps: Redis and Mongo without auth, no `cap_drop`, `read_only` or `no-new-privileges`, `infrastructure/nginx.conf` missing so TLS cannot be verified, an end-of-life Vagrant box, port 3000 published on all interfaces, and deprecated `apt-key`. | `infrastructure/docker-compose.yml:6-7,17-48`, `vagrant/Vagrantfile:9`, `vagrant/bootstrap.sh:11,21` | CFG | No | Add the nginx config, pin images, harden the services, use a supported box, bind to `127.0.0.1`. |
| F-25 | Workflow risks: `pr-compliance.yml` uses `pull_request_target` with `ORG_ADMIN_TOKEN` (whether it runs PR code is not verified), `image_actions.yml` uses the unpinned `calibreapp/image-actions@main`, and `ci.yml` has no top-level `permissions`. | `.github/workflows/pr-compliance.yml:4,438`, `image_actions.yml:33`, `ci.yml` | CFG | No | Never run PR head code under `pull_request_target`, pin actions to commit SHAs, default to `permissions: contents: read`. |

#### Low

| ID | Finding | Location | Source | Intentional | Remediation |
|---|---|---|---|---|---|
| F-31 | `.gitignore` lacks `.env*`, `*.tfstate*`, `*.tfvars` and `.terraform/`. `.dockerignore` lacks `.env*`, `*.pem`, `*.tfstate*` and the Terraform folders. `package-lock.json` is ignored, so installs drift. | `.gitignore:10`, `.dockerignore` | SEC | No | Add the patterns and commit a lockfile. |
| F-32 | Empty API-key defaults (`process.env.LLM_API_KEY ?? ''`) mean the app starts and fails only at call time. | `routes/chat.ts:110`, `routes/nftMint.ts:18`, `lib/webhook.ts:14` | SEC | No | Fail at startup when a required key is missing. |
| F-34 | Deprecated or unmaintained packages: `notevil`, `marsdb`, `decompress`, `download` (still 8.0.0), `replace`, `feature-policy`, `median`, `z85`, `express-robots-txt`, `express-security.txt`. `libxmljs2` is still in `node_modules` though `package.json` uses `libxml2-wasm`. | `package.json` | DEP | Mostly no | Replace or remove where possible and run `npm ci` from a clean checkout. |

---

## 3. Remediation prioritisation matrix

Impact is the reduction in risk if the finding is fixed. Effort is a rough estimate for a team that owns the code.

| | **Low effort** | **Medium effort** | **High effort** |
|---|---|---|---|
| **High impact** | F-03 remove `eval` · F-05 remove the Terraform key · F-12 restore the commented-out guard · F-13 remove public directories · F-16 cookie flags · F-17 CORS · F-20 HTTP-to-HTTPS redirect · `overrides` for `handlebars` and `proxy-addr` (F-04a) | F-01 parameterise SQL · F-07 fix NoSQL queries · F-08 path checks · F-10 SSRF controls · F-18 rate limits · F-15 CSP and output encoding · F-04a `multer` 2.x | F-02 and F-06 key and secret management with rotation · F-12 central authorisation model · F-14 password hash migration · F-19a major dependency upgrades |
| **Medium impact** | F-31 ignore files · F-32 startup checks · F-27 redirect allow-list · F-29 POST for password change | F-21 security groups · F-22 ECS hardening · F-23 container hygiene · F-25 CI hardening · F-09 XXE and YAML | F-11, F-04a and F-04b replace `notevil`, `marsdb`, `download` · F-26 card storage · F-24a compose and Vagrant rework |
| **Low impact** | F-33 headers and error handling | F-28 prototype pollution and sockets · F-30 seed data | F-34 package replacements |

---

## 4. Top 5 immediate actions

1. Contain the deployment. Run this app only on an isolated network with no real data. Do not apply the Terraform in `terraform/` or `infrastructure/terraform/` as a real deployment: it publishes an app with open SQL injection and `eval` to the internet over HTTP. If it must be deployed, add the HTTP-to-HTTPS redirect and restrict the ALB ingress first (F-20, F-21).
2. Remove and rotate embedded secrets. Delete the RSA key from `networking.tf` in both folders, move the JWT key, HMAC secret and cookie secret out of source, rotate them, and stop serving `/encryptionkeys` (F-02, F-05, F-06). Add the missing `.gitignore` patterns (F-31).
3. Close the code-execution and injection paths. Remove `eval` in `routes/userProfile.ts:65`, parameterise the SQL at `routes/login.ts:34` and `routes/search.ts:23`, fix the NoSQL review queries, and drop `notevil` and `vm` evaluation (F-01, F-03, F-07, F-11).
4. Patch the critical dependencies. Upgrade `multer` to 2.x, add `overrides` for `handlebars@^4.7.10` and `proxy-addr@^2.0.8`, and rebuild on a newer distroless base. Plan the replacement of `download`/`decompress` (F-04a) and decide how to handle `marsdb` (F-04b). Leave the deliberate challenge pins (`express-jwt`, `jsonwebtoken`, `sanitize-html`) alone only if the app stays isolated.
5. Restore access control and shrink the exposed surface. Re-enable the guard at `server.ts:389`, add ownership checks to baskets and orders, remove or authenticate `/ftp`, `/support/logs`, `/metrics` and `application-configuration`, set cookie flags, and restrict CORS (F-12, F-13, F-16, F-17).

---

## 5. Coverage and limitations

### What was done

Code review of routes, middleware and libraries. A repository-wide secret search, including 23,860 commits of git history searched for deleted sensitive files and key patterns. Manifest and registry analysis (32 `npm view` calls). Review of Terraform, Dockerfiles, compose, Vagrant, GitHub workflows and web-app headers, cookies, CORS and rate limiting. Key line references were spot-checked against the source, including the SQL injection, `eval`, key, CORS, cookie-secret, rate-limit, Dockerfile and Terraform lines.

### What was not done

- DAST. No running application was tested, so header and cookie behaviour comes from the code, not live responses.
- Snyk Secrets. The scan is disabled for the org (HTTP 403), so secret detection used pattern searches only. A tool-based full-history scan (for example gitleaks) was not run.
- Fresh vulnerability cross-check. Counts come from the Snyk scans of 2026-10-11 (`report_scan_2.md`), and a critical-only dependency re-scan on 2026-10-13 returned the same five issues. `npm audit` was not run and reachability was not assessed.
- Frontend dependencies. The 13 frontend issues were not identified by package, and `frontend/node_modules` was not audited separately.

### Open items to verify

- `pr-compliance.yml`: whether the `pull_request_target` job checks out or runs PR code (F-25).
- `ftp/incident-support.kdbx`: contents of the KeePass database.
- `mongodb/secrets.js`: a file deleted in git history, contents unknown.
- Commit `ea9462f3d`: one `AKIA` pattern match, probably an embedded image, not opened.
- `infrastructure/nginx.conf`: referenced by compose but absent from the repo.

---

## Appendix A: architecture and trust boundaries

Stack. Node 22 to 26, TypeScript, Express 4.22 (`server.ts`, 61 route files), Sequelize on SQLite, an in-memory Mongo-like store (`marsdb`) for reviews, `finale-rest` auto-generated CRUD, Angular 22 frontend, socket.io 3.1, JWT RS256 with MD5 password hashing, an LLM chatbot, Terraform on AWS (ALB, ECS Fargate, EFS), Docker, Vagrant.

Middleware order. `cors()` (all origins), `helmet` (only `noSniff` and `frameguard`), body parsers with manual JSON parsing, static and file servers, upload handlers, JWT middleware and per-path guards, `finale` CRUD, custom `/rest/*` routes, then the Angular client.

Data flow.
```
Browser (Angular) --HTTP/JSON--> Express (server.ts)
   |  socket.io                   |-- cors(*) -> helmet(partial) -> body parsing
   |                              |-- JWT middleware -> per-route guards (inconsistent)
   v                              v
 login   -> routes/login.ts:34    -> raw SQL  -> SQLite
 search  -> routes/search.ts:23   -> raw SQL  -> SQLite -> JSON
 reviews -> routes/*Reviews.ts    -> $where / _id operator -> Mongo-like store
 /api/*  -> finale-rest           -> Sequelize -> SQLite (mass assignment, plain card numbers)
 upload  -> routes/fileUpload.ts  -> zip write / XML (XXE) / YAML (vm)
 image URL -> profileImageUrlUpload.ts:24 -> fetch(any URL) -> disk -> DB
 profile -> routes/userProfile.ts:65 -> eval() -> pug -> HTML
 B2B     -> routes/b2bOrder.ts    -> notevil in vm
 static  -> /ftp, /encryptionkeys, /support/logs, /metrics (no auth)
```

Trust boundaries.
1. Internet to Express: no TLS in the app, CORS `*`, JWT in header or cookie.
2. Anonymous to customer to admin: guards applied per path, no deny-by-default, role taken from the client at registration.
3. Express to SQLite and to the Mongo-like store: raw SQL and `$where` strings.
4. Express to the filesystem: key, log, ftp and upload directories, several served publicly.
5. Express to the outbound network: unrestricted `fetch()` and an LLM API call.
6. Express to `vm` and `eval` sandboxes: not security boundaries.
7. Browser to socket.io: origin-restricted but unauthenticated events.

## Appendix B: key entry points

| Path | Method | Auth | Risk |
|---|---|---|---|
| `/rest/user/login` | POST | no | SQL injection (F-01) |
| `/rest/products/search` | GET | no | SQL injection (F-01) |
| `/rest/products/:id/reviews` | GET, PUT | no | NoSQL injection (F-07) |
| `/api/Users` | POST | no | Mass assignment of `role` (F-12) |
| `/api/Products/:id` | PUT | no (guard commented out) | Unauthorised writes (F-12) |
| `/api/Cards` | POST | partial | Plain card numbers (F-26) |
| `/rest/basket/:id` | GET | yes, no ownership check | IDOR (F-12) |
| `/file-upload` | POST | no | Zip slip, XXE, YAML (F-08, F-09) |
| `/profile/image/url` | POST | cookie token | SSRF (F-10) |
| `/profile` | GET, POST | cookie token | `eval` RCE, XSS (F-03, F-15) |
| `/b2b/v2/orders` | POST | JWT | `notevil` in `vm` (F-11) |
| `/redirect` | GET | no | Open redirect (F-27) |
| `/ftp`, `/encryptionkeys`, `/support/logs` | GET | no | File disclosure (F-13) |
| `/metrics`, `/rest/admin/application-configuration` | GET | no | Information disclosure (F-13) |
| `/rest/user/change-password` | GET | manual token | Credentials in URL (F-29) |
| `/rest/chat` | POST | no | Prompt injection (F-33) |
| Socket.IO events | WS | no | Unauthenticated events (F-28) |

## Appendix C: secrets inventory (redacted)

| Location | Type | Notes |
|---|---|---|
| `lib/insecurity.ts:21` | RSA private key (`-----BEGIN RSA PRIVATE KEY-----`, `MIIC...`) | Signs JWTs, also an HMAC key |
| `lib/insecurity.ts:42` | HMAC-SHA256 secret (`pa4q...tw...`) | Password hashing |
| `server.ts:308` | Cookie secret `kekse` | Weak and hardcoded |
| `terraform/networking.tf:171`, `infrastructure/terraform/networking.tf:171` | RSA private key (same `MIIC...` prefix) | Embedded in `aws_iam_server_certificate` |
| `encryptionkeys/jwt.pub` | RSA public key | Not secret, enables key-confusion challenges |
| `encryptionkeys/premium.key` | Premium key (50 bytes) | Premium paywall challenge |
| `ctf.key` | CTF HMAC key (30 bytes) | Default for flag HMAC |
| `data/static/users.yml` | 11 seeded plaintext passwords and one TOTP secret | Seed data |
| `ftp/incident-support.kdbx` | KeePass database | Contents not inspected |
| Test fixtures (`test/`, `*.spec.ts`) | Embedded JWTs and credentials | Mostly forged or expired tokens |
| `.github/workflows/*.yml` | Secrets referenced as `${{ secrets.* }}` | Correct practice, none hardcoded |

No AWS access key pattern, URL with embedded credentials or tracked `.env` file was found in tracked files.

## Appendix D: dependency upgrade plan

Vulnerability data comes from the Snyk scans. Maintenance dates come from `npm view`.

| Order | Change | Clears | Breaking? | Test |
|---|---|---|---|---|
| 1 | `overrides` for `handlebars@^4.7.10`, `proxy-addr@^2.0.8`. Rebuild on a newer distroless base. | 2 critical, 1 critical, OS-layer `zlib` high | No | Views render, image starts |
| 2 | `multer` to 2.x (2.3.0 per Snyk, 2.4.0 is current) | 12 issues incl. 1 critical | Major | Uploads, size and type challenges, oversize handling |
| 3 | `sqlite3` to 6.0.1 | 12 `tar` issues | Major | Native build on Node 22, 24, 26; DB seeding |
| 4 | `socket.io` and `socket.io-client` to 4.8.x (root and frontend) | 9 issues plus frontend high issues | Major | WebSocket events, frontend build |
| 5 | `i18n`, `pdfkit`, `file-type` (ESM), `js-yaml` 4, `@cyclonedx/cyclonedx-npm`, `express` patch | About 8 issues | Mixed | Language switching, PDF, upload type detection, YAML loading, SBOM |
| 6 | Run `npm audit` in `frontend/` and upgrade `ethers` | 13 frontend issues | Mixed | Frontend build and tests |
| 7 | Replace `download` and `decompress` with `fetch` and a maintained extractor | 1 critical plus 5 `decompress` issues | Code change in `lib/utils.ts` | Startup asset download |
| 8 | Challenge pins (`express-jwt`, `jsonwebtoken`, `sanitize-html`, `notevil`, `marsdb`): upgrade only if the challenges are dropped. Otherwise isolate and record the reasons in a `.snyk` policy with expiry dates. | Remaining high issues | Breaks challenges | Challenge tests |
