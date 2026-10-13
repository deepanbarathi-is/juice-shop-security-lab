# Threat Model: OWASP Juice Shop v20.2.0

> Juice Shop is a deliberately insecure training application. Most findings below are intentional challenge vulnerabilities. This model treats it as if it were a real production shop. Do not deploy it that way.

## System Overview

A single-process Node.js/Express (TypeScript) e-commerce app with an Angular SPA frontend.

**Components**
- Angular SPA (`frontend/`), served as static files by Express
- Express server (`server.ts`) with `/rest/*`, `/api/*` (finale-rest auto-generated CRUD), `/b2b/v2`, `/profile`, `/redirect`, `/metrics`
- SQLite via Sequelize (`models/`), seeded by `data/datacreator.ts`
- MarsDB (in-memory Mongo-like store) for product reviews and orders
- Filesystem exposures: `/ftp`, `/encryptionkeys`, `/support/logs`, `/infrastructure`, `uploads/`
- Outbound integrations: profile image URL fetch, Web3/Ethereum listeners, chatbot, webhook (`lib/webhook.ts`)

**Actors**
- Anonymous visitor, Customer, Deluxe customer, Accounting role, Admin, B2B client, Attacker (any of the above)

**Trust boundaries**
- TB1: Internet to Express (all input is untrusted)
- TB2: Express to datastores (SQLite, MarsDB, filesystem)
- TB3: Express to outbound services (URL fetch, blockchain RPC, webhook)
- TB4: Unauthenticated to authenticated (JWT) to privileged roles (admin, accounting)

## Architecture Diagram

```
                         (TB1: Internet / Untrusted)
 +-----------+   +-----------+   +-----------+   +----------+
 | Anonymous |   | Customer  |   | Accounting|   | B2B      |
 | visitor   |   | / Deluxe  |   | / Admin   |   | client   |
 +-----+-----+   +-----+-----+   +-----+-----+   +----+-----+
       |  HTTP(S)      |  JWT          |  JWT          | JWT
       v               v               v               v
 ======================= TB1 ================================
 +----------------------------------------------------------+
 |  Angular SPA (browser)  <-- static assets from Express   |
 +------------------------------+---------------------------+
                                | REST/JSON, multipart, XML/YAML
 =========================== TB4 (authn/authz) ==============
 +------------------------------v---------------------------+
 |                  Express Server (Node.js)                |
 |  +-----------+ +------------+ +-----------+ +---------+  |
 |  | Auth/JWT  | | REST+API   | | Upload    | | Static/ |  |
 |  | login,2FA | | (finale)   | | zip/xml/  | | dir     |  |
 |  | reset pw  | | basket,    | | yaml/img  | | listing |  |
 |  |           | | orders,    | | URL fetch | | /ftp    |  |
 |  |           | | wallet     | |           | | /logs   |  |
 |  +-----------+ +------------+ +-----------+ +---------+  |
 |  +-----------+ +------------+ +-----------+ +---------+  |
 |  | B2B order | | Profile    | | Redirect  | | /metrics|  |
 |  | vm sandbox| | (eval tmpl)| | /redirect | |Prometheus| |
 |  +-----------+ +------------+ +-----------+ +---------+  |
 +-----+------------------+--------------------+------------+
 ===== TB2 ==============|=========== TB3 =====|=============
       |                  |                     |
 +-----v-----+     +------v------+      +-------v----------+
 | SQLite    |     | MarsDB      |      | Outbound: image  |
 | Users,    |     | reviews,    |      | URL fetch, web3  |
 | Baskets,  |     | orders      |      | RPC, webhook     |
 | Cards...  |     |             |      +------------------+
 +-----------+     +-------------+
 +-----------------------------------+
 | Filesystem: ftp/, encryptionkeys/,|
 | logs/, uploads/, config/*.yml     |
 +-----------------------------------+
```

## Threat Mapping

```
 Anonymous/Customer/Admin/B2B  -------- S (stolen/forged JWT, weak reset, header spoof)
        |                                R (no audit trail for admin actions)
        v
 +--------------------- Angular SPA ----------------------+
 |  T/I: DOM + stored XSS, tokens in localStorage/cookie  |
 +----------------------------+---------------------------+
                              |
 ============================ TB1 / TB4 ==================
                              v
 +---------------------- Express Server -----------------+
 |  Auth/JWT   : S  T  R  E   (md5 pw, hardcoded RSA key, |
 |                             alg confusion, weak reset) |
 |  REST/API   : T  I  E  D   (SQLi, IDOR, mass-assign,   |
 |                             missing authz on routes)   |
 |  Upload     : T  I  D  E   (XXE, YAML bomb, zip slip,  |
 |                             SSRF via image URL)        |
 |  Static/dir : I            (/ftp, /encryptionkeys,     |
 |                             /support/logs, /metrics)   |
 |  B2B vm     : E  D         (sandbox escape, RCE)       |
 |  Profile    : E  T         (eval of username template) |
 |  Redirect   : S  T         (allowlist uses includes()) |
 |  CORS *     : S  I         (any origin)                |
 +-----+-----------------+-----------------+--------------+
       |                 |                 |
       v                 v                 v
  SQLite: T I E      MarsDB: T I      Filesystem: I T
  (SQLi dump,        (NoSQL op        (key/log/backup
   hash crack)        injection)       disclosure)
```

## Threat Table

| ID | STRIDE | Component | Threat | Impact | Likelihood | Mitigation |
|----|--------|-----------|--------|--------|------------|------------|
| T-01 | S | `routes/login.ts` | SQL injection in login query (`email = '${req.body.email}'`) lets an attacker log in as any user, including admin, without a password | Critical: full account takeover | High | Parameterized queries or ORM finders; reject non-string input |
| T-02 | S | `lib/insecurity.ts` JWT | RSA private key hardcoded in source; anyone with the repo can forge valid tokens; verify path accepts unsigned or alg-confused tokens | Critical: forge any identity or role | High | Load key from a secret store; pin `algorithms: ['RS256']`; rotate key |
| T-03 | S | Password storage | Passwords hashed with unsalted MD5 (`security.hash`) | High: offline cracking after any DB leak | High | argon2id or bcrypt with per-user salt |
| T-04 | S | Password reset / security questions | Guessable security answers; rate limit keyed on spoofable `X-Forwarded-For` | High: account takeover | High | Signed one-time email reset tokens; rate limit on real client IP and account |
| T-05 | S | `/redirect` (`isRedirectAllowed`) | Allowlist uses `url.includes(allowed)`, so `evil.com/?https://github.com/juice-shop` passes | Medium: phishing and open redirect | High | Exact origin match after URL parsing |
| T-06 | S | CORS | `cors()` with no options allows every origin | Medium: cross-site API abuse | Medium | Restrict to known origins; no credentials with `*` |
| T-07 | T | `routes/search.ts` | SQL injection in product search; UNION query dumps the Users table (emails and MD5 hashes) | Critical: data breach | High | Parameterized queries |
| T-08 | T | `/api/Products` and `/api/*` (finale) | Product PUT unprotected (auth commented out); mass assignment lets users set `role`, `id`, `deluxeToken` at registration | High: privilege change, data corruption | High | Per-route authz; allowlist writable fields |
| T-09 | T | Reviews, feedback, profile | Stored and reflected XSS; `helmet.xssFilter` disabled; no output encoding or CSP | High: session hijack, defacement | High | Output encoding, sanitize input, strict CSP, HttpOnly cookies |
| T-10 | T | Basket and wallet routes | Business logic abuse: negative quantities, basket ID tampering, coupon reuse, wallet top-up without payment | Medium: financial fraud | Medium | Server-side validation; bind basket and order to session user |
| T-11 | T | `/file-upload` (zip) | Zip slip writes outside the upload directory (`absolutePath.includes(...)` check) | High: arbitrary file write | Medium | Normalize paths, `startsWith` the base dir, size and entry limits |
| T-12 | R | Logging (`morgan`, `/support/logs`) | No audit log of admin, order or privacy-request actions; logs are tamperable and publicly listed; `X-Forwarded-For` trusted for IP | Medium: no forensics, denial of actions | High | Append-only central audit log; protect log access; trust only a known proxy |
| T-13 | R | `saveLoginIp` | Client IP taken from spoofable header | Low: wrong attribution | High | Use the socket address behind a trusted proxy |
| T-14 | I | `/ftp`, `/encryptionkeys`, `/support/logs`, `/infrastructure` | Directory listing exposes backups (`.bak`), keys, access logs, and `package.json.bak`; poison-null-byte bypasses the extension filter | High: secret and IP disclosure | High | Remove the routes; deny by default; never serve the app tree |
| T-15 | I | `/metrics` | Prometheus metrics public | Low: reconnaissance | High | Auth or network-restrict |
| T-16 | I | IDOR on `/rest/basket/:id`, `/api/Users`, `/rest/track-order/:id`, `/api/Cards`, data export | Authenticated user reads other users' baskets, orders, and PII | High: PII leak | High | Ownership check on every object access |
| T-17 | I | `/rest/user/authentication-details`, `/api/Users` | Password hashes and tokens returned in API responses | High | High | DTO allowlist; never return hashes |
| T-18 | I | XXE in `/file-upload` (XML) and `/b2b/v2` | External entity file read | High: local file read | Medium | Disable DTD and entity expansion |
| T-19 | I | `profileImageUrlUpload` | SSRF: server fetches any user-supplied URL | High: internal network and metadata access | Medium | Allowlist hosts; block private ranges; no redirects |
| T-20 | I | Frontend token storage | JWT in localStorage plus cookie readable by script | Medium: token theft via XSS | Medium | HttpOnly, Secure, SameSite cookies |
| T-21 | I | Error handling | Verbose stack traces returned to clients | Low: info leak | High | Generic errors in production |
| T-22 | D | `/file-upload` YAML and XML | YAML and XML bombs; limited only by a 2s vm timeout | Medium: CPU and memory exhaustion | Medium | Parser limits; safe schema; run in a worker |
| T-23 | D | `/b2b/v2/orders` | `notevil` in `vm` can be sent infinite loops or ReDoS | Medium | Medium | Remove eval; schema validation |
| T-24 | D | Global | Only the reset-password route has a rate limit; login, search and registration have none; single process | Medium: brute force and service exhaustion | High | Rate limit and lockout; WAF; scale out |
| T-25 | E | `/b2b/v2/orders` | Sandbox escape of `vm` with `notevil` gives RCE | Critical | Medium | Never evaluate user code; use JSON schema |
| T-26 | E | `routes/userProfile.ts` | `eval()` on a username template (`#{...}`) gives server-side RCE | Critical | High | Remove `eval`; use a safe template engine |
| T-27 | E | Registration and role handling | `role: admin` accepted at `POST /api/Users`; JWT carries the role claim that is trusted | Critical: admin access | High | Server-assigned roles only; re-check role from the DB |
| T-28 | E | `isAccounting()` / IP filter | Placeholder IP allowlist (`123.456.789`) is ineffective; accounting endpoints guarded by token role alone | Medium | Medium | Real RBAC; verify role server-side |
| T-29 | E | Supply chain and config | Known vulnerable dependencies; `config/unsafe.yml`; Docker image runs app and data together | Medium | Medium | `npm audit`, SCA in CI, non-root distroless image |
| T-30 | T | Profile update CSRF | CSRF check based on `includes()` of origin/referer; no CSRF token; cookies not SameSite | Medium | Medium | CSRF tokens or SameSite=strict; exact origin match |

## Key Risks

1. **Injection to full compromise.** SQLi in login (T-01) and search (T-07) gives authentication bypass and a full user/hash dump. Unsalted MD5 (T-03) makes the stolen hashes immediately usable.
2. **Server-side code execution.** `eval` in the profile template (T-26) and `vm` plus `notevil` in B2B orders (T-25) give RCE. That means access to the key files, the DB and the host.
3. **Broken identity and token trust.** A hardcoded JWT private key (T-02), an accepted `role` at registration (T-27) and a weak reset flow (T-04) let an attacker become anyone, including admin.
4. **Broken access control and IDOR.** Missing or inconsistent authorization on `/api/*` and `/rest/*` (T-08, T-16, T-17) exposes other users' baskets, cards, orders and PII.
5. **Secret and file disclosure.** Public `/ftp`, `/encryptionkeys`, `/support/logs` (T-14) leak keys, backups and logs. XXE (T-18) and SSRF (T-19) extend this to local files and the internal network.

## Recommended Controls

- **Input handling:** parameterized queries everywhere; schema validation (zod/ajv) on all bodies; allowlist writable model fields; remove every `eval` and user-code `vm`.
- **AuthN/AuthZ:** argon2id for passwords; keys from a secrets manager with rotation; pin the JWT algorithm; assign roles server-side only; ownership checks on every object ID; deny by default on `/api/*`.
- **Session and browser:** HttpOnly, Secure, SameSite cookies instead of localStorage; strict CSP; re-enable output encoding; CSRF tokens; restrictive CORS.
- **File and network:** remove directory-listing routes and serve only intended assets; fix zip-slip with normalized path checks; disable XML entities; SSRF allowlist and private-range block on URL fetch; exact-match redirect allowlist.
- **Resilience:** rate limiting and lockout on login, reset, search and registration; request size and parser limits; run untrusted-file parsing in isolated workers.
- **Detection:** append-only audit logging of auth, admin, order and privacy events; trust proxy headers only from known proxies; protect `/metrics`; alert on anomalies.
- **Supply chain:** `npm audit`/SCA and secret scanning in CI; non-root minimal container; separate config for production (never `unsafe.yml`).
