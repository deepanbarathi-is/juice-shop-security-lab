# Threat Model: OWASP Juice Shop v20.2.0

> Juice Shop is a deliberately insecure training application. Most threats below are intentional challenge vulnerabilities. This model treats it as if it were a real production shop. Do not deploy it that way.

## System Overview

A single-process Node.js/Express (TypeScript) e-commerce app with an Angular SPA frontend.

**Components**
- Angular SPA (`frontend/`), served as static files by Express
- Express server (`server.ts`) exposing `/rest/*`, `/api/*` (auto-generated CRUD via `finale-rest`, `server.ts:500`), `/b2b/v2`, `/profile`, `/redirect`, `/metrics`, `/file-upload`
- SQLite database via Sequelize (`models/index.ts:41`, file `data/juiceshop.sqlite`)
- Auth module `lib/insecurity.ts` (JWT RS256, MD5 hashing, HMAC)
- File stores served over HTTP: `/ftp`, `/encryptionkeys`, `/support/logs`, uploads directory
- WebSocket channel (`lib/startup/registerWebsocketEvents`, `server.ts:770`)
- Outbound HTTP: profile image URL fetch (`routes/profileImageUrlUpload.ts:24`)

**Actors**
- Anonymous visitor, authenticated customer, accounting/admin user, B2B API client, external attacker, Prometheus scraper.

**Trust boundaries**
- TB1: Internet to Express (no TLS configured in the app; `server.ts` has no https setup)
- TB2: Express to SQLite (in-process file access)
- TB3: Express to filesystem (keys, logs, ftp, uploads)
- TB4: Express to outbound network (SSRF surface)
- TB5: Anonymous to authenticated to admin (JWT-based)

## Architecture Diagrams

### 1. Component Diagram

```
 +----------+  +-----------+  +-----------+  +-------------+
 | Anonymous|  | Customer  |  | Admin /   |  | B2B client  |
 | visitor  |  | (JWT)     |  | Accounting|  | (/b2b/v2)   |
 +----+-----+  +-----+-----+  +-----+-----+  +------+------+
      |              |              |               |
      +--------------+------+-------+---------------+
                            |
                            v
      +---------------------------------------------------+
      |             Express server (server.ts)            |
      |                                                   |
      |  +------------+  +--------------+  +-----------+  |
      |  | Angular SPA|  | REST routes  |  | finale    |  |
      |  | (static)   |  | /rest/*      |  | /api/*    |  |
      |  +------------+  +--------------+  +-----------+  |
      |                                                   |
      |  +---------------------------------------------+  |
      |  | lib/insecurity.ts  (JWT, MD5, HMAC)         |  |
      |  +---------------------------------------------+  |
      |                                                   |
      |  +-----------+  +-----------+  +--------------+   |
      |  | Upload    |  | WebSocket |  | /metrics     |   |
      |  | handlers  |  | events    |  | /redirect    |   |
      |  +-----------+  +-----------+  +--------------+   |
      +------+----------------+-----------------+---------+
             |                |                 |
             v                v                 v
      +-------------+  +--------------+  +----------------+
      | SQLite DB   |  | Filesystem   |  | Outbound fetch |
      | users,cards |  | /ftp         |  | (profile image |
      | baskets     |  | /encryption  |  |  URL)          |
      +-------------+  | keys, logs,  |  +----------------+
                       | uploads      |
                       +--------------+
```

### 2. Data Flow Diagram

```
 (1) Login
     Client --[email, password]--> /rest/user/login --[SQL]--> SQLite
     Client <--[JWT]-------------- /rest/user/login

 (2) Authenticated request
     Client --[JWT in header/cookie]--> isAuthorized() --> route handler

 (3) Card data
     Client --[card number, expiry]--> /api/Cards --> SQLite (plain integer)
     Client <--[masked PAN]----------- /rest/payment

 (4) Uploads
     Client --[xml/yaml/zip/image]--> /file-upload, /profile/image/*
            --> memory or disk (uploads dir)

 (5) Image URL
     Client --[imageUrl]--> /profile/image/url --[server-side fetch]--> any URL

 (6) Static file access
     Client <--[files]-- /ftp, /encryptionkeys, /support/logs

 (7) Metrics
     Prometheus --> /metrics (no auth)
```

### 3. Trust Boundary Diagram

```
  +------------------------ UNTRUSTED: Internet ------------------------+
  |   Anonymous visitor        Attacker        B2B client               |
  +----------------------------------+---------------------------------+
                                     |
 ====================== TB1: Internet -> Express (no TLS in app) ========
                                     |
  +----------------------------------v---------------------------------+
  |  SEMI-TRUSTED: Express server                                       |
  |                                                                     |
  |   +-------- TB5: JWT boundary -------------------------------+      |
  |   | Anonymous routes  ->  Customer routes  ->  Admin routes  |      |
  |   +-----------------------------------------------------------+     |
  +--------+------------------------+------------------------+---------+
           |                        |                        |
 ==== TB2: app -> DB ====  ==== TB3: app -> files ====  ==== TB4: app -> network ====
           |                        |                        |
   +-------v------+        +--------v--------+       +-------v--------+
   | TRUSTED      |        | TRUSTED         |       | UNTRUSTED      |
   | SQLite DB    |        | keys, logs, ftp |       | external hosts |
   +--------------+        +-----------------+       | internal svc   |
                                                     +----------------+
```

## Threat Mapping

```
 +----------+  S: forged JWT (signing key is public)
 | Clients  |  S: SQLi login bypass
 |          |  I: no TLS, traffic sniffing
 +----+-----+  D: unthrottled endpoints
      |
      v
 +------------------+                          +------------------+
 | /rest, /api      |  T: SQLi, mass assign    | SQLite DB        |
 | (finale CRUD)    |  E: IDOR, admin routes   | I: MD5 pw hashes |
 | S T R I D E      |  R: no auth-event logs   | I: plaintext PAN |
 +--------+---------+------------------------->| T: SQLi writes   |
          |                                    +------------------+
          |
          +---------------------------------+
          |                                 |
          v                                 v
 +------------------+              +--------------------+
 | Upload handlers  |              | Filesystem         |
 | T: XXE, zip slip |              | I: /encryptionkeys |
 | D: large payload |              | I: /support/logs   |
 | E: RCE via input |              | I: /ftp backups    |
 +------------------+              | T: upload overwrite|
                                   +--------------------+
 +------------------+              +--------------------+
 | Outbound fetch   |              | /redirect          |
 | I: SSRF          |              | S: open redirect   |
 +------------------+              +--------------------+
```

## Threat Table

| ID | STRIDE | Component | Threat | Impact | Likelihood | Mitigation |
|---|---|---|---|---|---|---|
| T-01 | S | `/rest/user/login` | SQL injection in login query (`routes/login.ts:34`) lets an attacker log in as any user, including admin, with no password. | Critical | High | Parameterised queries; generic login errors. |
| T-02 | S | `lib/insecurity.ts` | JWT RSA private key hardcoded (`:21`) and `/encryptionkeys` is browsable (`server.ts:296`); attacker forges admin tokens. | Critical | High | Load keys from a secrets manager; remove directory serving; rotate keys. |
| T-03 | S | Token handling | HMAC secret hardcoded (`lib/insecurity.ts:42`); cookie secret `'kekse'` (`server.ts:308`). | High | High | Move secrets to config; rotate. |
| T-04 | T | `/rest/products/search` | SQL injection (`routes/search.ts:23`) allows UNION extraction of the Users table and schema. | Critical | High | Parameterise; least-privilege DB access. |
| T-05 | T | `/api/*` (finale) | Auto-generated CRUD may allow mass assignment and writes to unprotected resources (e.g. `PUT /api/Products/:id` guard commented out, `server.ts:389`). | High | Medium | Explicit field allow-lists; apply `isAuthorized` and role checks. |
| T-06 | T | `/file-upload` | Uploaded XML, YAML and zip files are parsed server-side (YAML in a VM, `routes/fileUpload.ts:109`); crafted files may trigger XXE or zip path traversal. Not verified beyond the YAML handling. | High | Medium | Disable DTD/entities; safe YAML schema; validate zip entry paths. |
| T-07 | R | Auth and admin routes | No auth-event logging in login (`routes/login.ts`); logger is console-only (`lib/logger.ts:10`). | Medium | High | Log auth, privilege and data-change events to a protected central store. |
| T-08 | R | Access logs | Logs are downloadable by anyone (`server.ts:300-302`), so attackers can read or learn from them. | Medium | High | Restrict access; do not serve logs over HTTP. |
| T-09 | I | SQLite DB | Passwords stored as unsalted MD5 (`lib/insecurity.ts:41`); card numbers stored as plain integers (`models/card.ts:38`). | Critical | High | argon2id/bcrypt; stop storing PAN; encrypt DB at rest. |
| T-10 | I | Static file dirs | `/ftp`, `/encryptionkeys`, `/support/logs`, `/metrics` publicly listable (`server.ts:288,296,300,695`). | High | High | Remove or authenticate; bind `/metrics` to an internal interface. |
| T-11 | I | Transport | No TLS or HSTS configured in app; tokens and credentials travel in clear unless a proxy terminates TLS. | High | Medium | TLS 1.2+ at app or proxy; `helmet.hsts()`. |
| T-12 | I | Profile image URL | Server fetches a user-supplied URL (`routes/profileImageUrlUpload.ts:24`): SSRF to internal services or cloud metadata. | High | Medium | Allow-list hosts; block private ranges; use a fetch proxy. |
| T-13 | D | Public endpoints | Rate limits cover only a few routes (`server.ts:362,478-491`); search and upload are unthrottled; memory upload capped at 200 KB (`server.ts:713`). | Medium | High | Global rate limiting; request-size and time limits. |
| T-14 | D | `b2bOrder` / captcha | `vm` + `notevil` evaluation (`routes/b2bOrder.ts:23`) and `eval` in captcha (`routes/captcha.ts:22`) allow CPU exhaustion or sandbox escape. | High | Medium | Remove eval; strict schema validation. |
| T-15 | E | `/redirect` | Substring allow-list (`lib/insecurity.ts:136`) enables open redirect for phishing and token theft. | Medium | High | Exact-match allow-list of full URLs. |
| T-16 | E | `routes/userProfile.ts` | `eval` on user-controlled profile content (`:65`) allows server-side code execution. | Critical | Medium | Remove `eval`; use a template engine with escaping. |
| T-17 | E | Role checks | Role and `isAccounting` checks are inconsistent across routes; IDOR on baskets and orders is possible. | High | Medium | Centralised authorisation; ownership checks on every object access. |
| T-18 | T | Browser / SPA | Stored and reflected XSS (XSS filter intentionally off, `server.ts:188`; no CSP) lets attackers steal tokens from non-httpOnly cookies (`lib/insecurity.ts:192`). | High | High | CSP; output encoding; httpOnly, secure, sameSite cookies. |

## Key Risks

1. **Authentication collapse (T-01, T-02, T-03):** SQL injection plus a publicly reachable signing key means anyone can become any user.
2. **Bulk data theft (T-04, T-09, T-10):** UNION injection, MD5 hashes and plaintext card numbers make a full database dump trivial and reversible.
3. **Remote code execution (T-16, T-14):** `eval` and VM-based evaluation of user input could give server-level access.
4. **Unprotected operational endpoints (T-08, T-10):** keys, logs, backups and metrics are available without authentication.
5. **Pivoting via SSRF and uploads (T-06, T-12):** server-side fetch and XML/YAML/zip parsers extend the attack to internal systems.

## Recommended Controls

- **Input handling:** parameterised queries everywhere; remove all `eval` and `vm` evaluation of user data; schema-validate request bodies.
- **Secrets and crypto:** move all keys and secrets out of source; rotate them; replace MD5 with argon2id; stop storing card numbers.
- **Authentication and access:** enforce authorisation on every state-changing route; add ownership checks; require MFA for admin; set cookie flags.
- **Exposure reduction:** remove `/encryptionkeys`, `/ftp`, `/support/logs` and public `/metrics`; restrict `/rest/admin/*`.
- **Transport and headers:** TLS with HSTS; restrict CORS to known origins; enable CSP.
- **Resilience:** global rate limiting, request-size limits and timeouts; allow-list for outbound fetch and redirects.
- **Detection:** log authentication and privilege events to a protected central store; alert on repeated failures and anomalous admin activity.
- **Training use:** run only in isolated, non-production environments and never load real data into it.
