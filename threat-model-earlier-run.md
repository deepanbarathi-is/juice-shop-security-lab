    # Threat Model: OWASP Juice Shop

## System Overview

OWASP Juice Shop is a single-process Node.js/Express monolith (`server.ts`, `app.ts`) serving:
- A compiled Angular SPA (`frontend/`) as static assets, plus server-rendered views (`views/`) for a few flows.
- A REST API (`routes/*.ts`, 61 route modules) covering auth, catalog/search, basket/checkout, payments, file upload/serving, user profile, 2FA, admin, and CTF challenge-scoring endpoints.
- A local SQLite database (`sequelize` ORM, `models/*.ts`) holding users, products, baskets, orders, cards, addresses, feedback, security Q&A.
- A local filesystem used as a second data store: `uploads/`, `ftp/` (static docs served back to users), `encryptionkeys/` (JWT public key), and `i18n/`.
- Stateless-looking but actually semi-stateful auth: RS256 JWTs signed server-side, but authorization decisions are also backed by an in-memory `authenticatedUsers` token map (`lib/insecurity.ts`).

**Actors**
- Anonymous visitor (browses catalog, registers, resets password)
- Registered customer / deluxe customer (basket, checkout, payment cards, 2FA)
- Accounting role (`isAccounting()` gate)
- Admin role (user/product management, CTF scoreboard control)
- Node.js server process itself (trusted, has filesystem + DB access)
- Underlying OS/filesystem and SQLite file (`data/*.sqlite` via Sequelize)

**Trust boundaries**
1. Internet ↔ Express server (all `/rest/*`, `/api/*`, `/socket.io`, static file routes)
2. Authenticated-request boundary — JWT-bearing request vs. anonymous request
3. Role boundary — customer vs. deluxe vs. accounting vs. admin (enforced only where explicitly checked)
4. Server process ↔ filesystem (`uploads/`, `ftp/`, `encryptionkeys/`)
5. Server process ↔ SQLite database (raw SQL is built by string concatenation in places — see below)
6. Server ↔ third-party redirect targets / CDN-fetched frontend assets

## Architecture Diagram

```
                         (1) Internet boundary
   ┌─────────────┐   HTTPS/HTTP    ┌──────────────────────────────────────────┐
   │   Browser    │───────────────▶│              Express App (Node)           │
   │ (Angular SPA)│◀───────────────│  server.ts / app.ts                       │
   └─────────────┘   JSON / HTML   │  ┌────────────────────────────────────┐  │
                                    │  │ Middleware: helmet(partial), cors()│  │
                                    │  │ (wildcard), cookieParser('kekse'), │  │
                                    │  │ express-jwt (isAuthorized),        │  │
                                    │  │ rateLimit (only 2FA + reset-pwd)   │  │
                                    │  └────────────────────────────────────┘  │
                                    │              │           │               │
                    (2)(3) Auth/role boundary      │           │               │
                                    │        ┌─────▼───┐  ┌────▼─────┐         │
                                    │        │ Route    │  │  Route   │         │
                                    │        │ handlers │  │ handlers │  ...    │
                                    │        │ (61 mods)│  │ (admin)  │         │
                                    │        └─────┬───┘  └────┬─────┘         │
                                    │   (5) DB boundary        │ (4) FS boundary│
                                    │   ┌──────────▼───┐  ┌────▼────────────┐  │
                                    │   │  Sequelize    │  │ uploads/        │  │
                                    │   │  → SQLite DB  │  │ ftp/            │  │
                                    │   │ (raw SQL in   │  │ encryptionkeys/ │  │
                                    │   │  search/login)│  │ (jwt.pub)       │  │
                                    │   └───────────────┘  └─────────────────┘  │
                                    │                                            │
                                    │   ┌────────────────────────────────────┐  │
                                    │   │ In-memory authenticatedUsers map    │  │
                                    │   │ (token → user, tracks basket id)    │  │
                                    │   └────────────────────────────────────┘  │
                                    └──────────────────────────┬─────────────────┘
                                                (6) Egress boundary
                                                                │
                                                     ┌──────────▼──────────┐
                                                     │ External redirect    │
                                                     │ allowlist (substring │
                                                     │ match, not exact)    │
                                                     └──────────────────────┘
```

## Threat Mapping

STRIDE letters overlaid on the components/flows they affect, each backed by concrete code evidence:

```
   ┌─────────────┐  S,I         ┌──────────────────────────────────────────┐
   │   Browser    │◀────────────│  Express App                               │
   └─────────────┘              │                                            │
                                  │  Middleware layer:                        │
                                  │   T,S  cors() wildcard  (server.ts:181-183)│
                                  │   S    cookie secret 'kekse' (server.ts:308)│
                                  │   D    login has NO rate limit             │
                                  │        (only reset-pwd/2FA do, :362,478-491)│
                                  │                                            │
                    S,E ─────────┤        ┌─────────┐   T,I  ┌──────────┐    │
                                  │        │ /login   │──────▶│ /basket/ │    │
                                  │        │ SQLi     │        │ :id BOLA │    │
                                  │        │(login.ts:33)      │(basket.ts:20)│
                                  │        └─────────┘        └──────────┘    │
                                  │   I ┌──────────────┐                       │
                                  │     │ /rest/products│  T,I  DB boundary    │
                                  │     │ /search SQLi  │──────▶┌─────────────┐│
                                  │     │(search.ts:22) │       │ raw string- ││
                                  │     └──────────────┘       │ built SQL   ││
                                  │                              └─────────────┘│
                                  │   T,I ┌────────────────────┐  FS boundary  │
                                  │       │ fileUpload.ts:      │──────▶┌─────┐│
                                  │       │ zip-slip extraction │       │uploads│
                                  │       │ (:32), XXE (:76-91),│       │  /   │
                                  │       │ YAML vm sandbox     │       └─────┘│
                                  │       │ escape (:104-124)   │               │
                                  │       └────────────────────┘               │
                                  │   T ┌───────────────────────┐              │
                                  │     │ fileServer.ts: null-byte│──────▶ ftp/ │
                                  │     │ poisoning, path reveal  │              │
                                  │     │ (:21-38)                │              │
                                  │     └───────────────────────┘              │
                                  │   R,E ┌──────────────────────┐             │
                                  │       │ insecurity.ts:               │     │
                                  │       │ hardcoded RSA private key (21)│    │
                                  │       │ hardcoded HMAC key (42),     │     │
                                  │       │ MD5 password hash (41)       │     │
                                  │       └──────────────────────┘             │
                                  │   I ┌────────────────────┐                 │
                                  │     │ models/card.ts:     │                 │
                                  │     │ full PAN stored     │                 │
                                  │     │ in plaintext (:20)  │                 │
                                  │     └────────────────────┘                 │
                                  └──────────────────────────┬─────────────────┘
                                                 T,S           │
                                                     ┌──────────▼──────────┐
                                                     │ redirectAllowlist:   │
                                                     │ substring match, not │
                                                     │ exact (insecurity.ts:│
                                                     │ 133-139) → open      │
                                                     │ redirect             │
                                                     └──────────────────────┘

Legend: S=Spoofing T=Tampering R=Repudiation I=Information Disclosure D=DoS E=Elevation of Privilege
```

## Threat Table

| ID | STRIDE | Component | Threat | Impact | Likelihood | Mitigation |
|----|--------|-----------|--------|--------|------------|------------|
| T1 | E, T | `routes/login.ts:33` | Login query builds SQL by string-concatenating `req.body.email`/password hash; `' OR 1=1--` bypasses auth as any user (incl. admin) | Full account takeover, admin compromise | High (classic, unauthenticated, no WAF) | Use parameterized queries (`sequelize.query` with `replacements`/bind params) everywhere; never concatenate user input into SQL |
| T2 | I | `routes/search.ts:22` | Product search builds SQL via template-string concatenation of `q` param; enables UNION-based extraction of arbitrary tables (users, cards) | Full DB exfiltration (emails, password hashes, card numbers) | High | Parameterize the query; add input allowlisting as defense-in-depth |
| T3 | T, I | `routes/basket.ts:12-25` | `retrieveBasket` fetches any basket by `:id` from the URL with no ownership check before returning it (ownership check exists only as a challenge-scoring side effect, not an access-control gate) | Any authenticated user can read/tamper with another user's basket (IDOR/BOLA) | High | Enforce `basket.UserId === authenticatedUser.id` (or JWT `bid`) server-side before returning data, not just for challenge bookkeeping |
| T4 | S, R, E | `lib/insecurity.ts:20-21,42,150` | RSA private signing key and an HMAC key (`pa4q...tw... (redacted)`) are hardcoded in source; `deluxeToken` derived from a static, source-visible key | Anyone with source/repo access can forge valid JWTs for any user/role, forge deluxe tokens, and mint valid session tokens without ever authenticating | High (keys are public in a public repo) | Load signing keys from a secret store / env var, generate per-deployment, rotate regularly; never commit private keys |
| T5 | I | `lib/insecurity.ts:41` | Passwords hashed with unsalted MD5 (`hash()`) | Trivial rainbow-table/GPU cracking of any leaked password hash | High if DB is ever exfiltrated (see T2) | Use bcrypt/argon2 with per-user salt and adequate work factor |
| T6 | I | `models/card.ts:18-20` | Full card number (`cardNum`) stored as a plain integer with no encryption, tokenization, or truncation | PCI-scope data exposed in full on any DB read/leak (compounds T2) | High | Store only last 4 digits + a tokenized reference from a PCI-compliant processor; never persist full PAN |
| T7 | T | `routes/fileUpload.ts:27-35` | `extractZipBuffer` writes each zip entry to `uploads/complaints/<entry.path>` and only checks that the *resolved* path starts with `path.resolve('.')` (the whole project root, not the upload dir) — classic zip-slip; a crafted `../../` entry can still land inside the project tree | Arbitrary file write within the app's working directory (e.g., overwrite config or drop a webshell-adjacent file) | Medium (requires reaching the file-write challenge/upload path) | Validate resolved path is inside `path.resolve('uploads/complaints')` specifically, reject entries with `..` segments, extract to a temp dir with an allowlist |
| T8 | D, I | `routes/fileUpload.ts:76-124` | XML upload parses attacker XML (`parseXmlString`) and YAML upload runs `vm.runInContext(... yaml.load(data) ...)` — both are known vectors for XXE-based file disclosure and YAML/VM-based DoS (billion-laughs / long-running scripts), acknowledged in-code as causing crashes | Local file disclosure (`/etc/passwd`), server hang/crash | Medium (feature is nominally "deprecated" but still reachable) | Disable external entity resolution in the XML parser; avoid `vm` for untrusted YAML, use a hardened parser with depth/alias limits and no code execution context |
| T9 | T, I | `routes/fileServer.ts:21-45` | File serving accepts a null-byte-poisoned filename (`cutOffPoisonNullByte`) and only checks the file *ends with* `.md`/`.pdf`; combined with `path.resolve('ftp/', file)` this allows serving unlisted files (e.g. backup files, easter eggs) once the extension check is defeated | Disclosure of files not meant to be public (backups, internal docs) | Medium | Serve from a strict allowlist of filenames generated server-side, not from user-controlled path segments; drop null-byte handling entirely (reject the request) |
| T10 | S | `lib/insecurity.ts:133-139` (`isRedirectAllowed`) | Redirect target validated with `url.includes(allowedUrl)`, a substring check, not an exact/prefix match against a parsed URL — `https://evil.com/?x=https://github.com/juice-shop/juice-shop` passes | Open redirect usable for phishing, OAuth token theft | Medium | Parse the URL and compare the full origin (scheme+host) against an allowlist, not substring containment |
| T11 | S, D | `routes/login.ts` (whole handler) + `server.ts` rate-limit config | No `rateLimit` middleware is applied to `/rest/user/login` (only `/rest/user/reset-password` and the 2FA endpoints have one) | Unlimited online credential-stuffing / brute-force against every account | High | Add `express-rate-limit` (and ideally progressive backoff / captcha) to the login endpoint |
| T12 | S | `server.ts:181-183` | `app.use(cors())` with no options allows any origin to make credentialed cross-origin requests to the API | Any malicious site can call the API using a victim's session, widening the impact of XSS/CSRF-style attacks | Medium | Restrict `origin` to the deployment's own frontend origin(s); do not reflect `*`/all origins, especially alongside cookie-based auth |
| T13 | S | `server.ts:308` | `cookieParser('kekse')` uses a hardcoded, publicly-known signing secret for signed cookies | Forged/tampered signed cookies accepted as valid | Medium | Load the cookie secret from environment/secret manager, unique per deployment |
| T14 | R | Across routes (e.g. `routes/order.ts`, `payment.ts`) | No structured audit/security-event logging observed for sensitive actions (role changes, payment, admin actions) beyond generic app logging | Difficult to detect or investigate abuse after the fact | Medium | Add tamper-evident audit logging for auth, role changes, payments, and admin actions, shipped to a separate log sink |

## Key Risks

1. **Two independent, unauthenticated SQL-injection paths (T1 login bypass, T2 search UNION)** are the single biggest risk — either one alone yields full database compromise, and T1 additionally grants direct admin access without needing the DB dump.
2. **Hardcoded cryptographic material committed to source (T4, T5, T13)** means the "keys to the kingdom" (JWT signing key, HMAC key, cookie secret) are public to anyone who can read the repository — this alone defeats the authentication and integrity guarantees of the entire session/token system, independent of any application bug.
3. **Plaintext payment card storage (T6)** combined with the SQLi paths turns any DB read primitive into a full PCI-data breach, not just a "just usernames and emails" leak.
4. **Broken object-level authorization on baskets (T3)** is a textbook IDOR/BOLA that lets any logged-in user pivot into other customers' cart/order data.
5. **No brute-force protection on login (T11) combined with weak/no CORS restriction (T12)** substantially lowers the bar for credential-stuffing and session-riding attacks even without exploiting T1/T2.

## Recommended Controls

- Replace all string-concatenated SQL (`login.ts`, `search.ts`, and any other `sequelize.query(`...${x}...`)` call) with parameterized queries or Sequelize model methods — highest priority, addresses T1/T2.
- Move every hardcoded secret (RSA private key, HMAC key, cookie secret) out of source into environment variables / a secrets manager, generated uniquely per deployment; rotate immediately given current keys are public — addresses T4, T5 (indirectly), T13.
- Enforce object ownership checks server-side (not just for challenge scoring) on `basket`, `order`, `address`, and `card` lookups keyed by `:id` — addresses T3.
- Tokenize or truncate stored card data; never persist a full PAN — addresses T6.
- Add `express-rate-limit` to `/rest/user/login` and other unauthenticated, high-value endpoints — addresses T11.
- Scope `cors()` to explicit allowed origins instead of the default allow-all — addresses T12.
- Harden file handling: fix the zip-slip path check to resolve against the upload subdirectory (not project root), disable XXE in the XML parser, remove `vm`-based YAML evaluation, and drop null-byte filename handling in favor of exact allowlisted filenames — addresses T7, T8, T9.
- Fix `isRedirectAllowed` to do full-URL/origin comparison instead of substring `includes()` — addresses T10.
- Replace MD5 password hashing with bcrypt/argon2 plus per-user salt — addresses T5.
- Add centralized security-relevant audit logging (auth events, role/privilege changes, payment actions) — addresses T14.

*Note: this application is OWASP Juice Shop, an intentionally vulnerable training/CTF platform — nearly every threat above is a deliberately implanted "challenge," not an accidental defect. This model documents them as if for a production hardening exercise, per the request.*
