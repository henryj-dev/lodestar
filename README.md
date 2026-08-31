<div align="center">

<h1>lodestar</h1>

### **An open-source identity provider that runs on Cloudflare Workers.**

OIDC, SAML 2.0, WebAuthn/Passkey, TOTP 2FA and LDAP, with multi-tenant organization
management. It ships as one SvelteKit application; the database dialect and the
deployment target are chosen at build time.

<br/>

[![ci](https://github.com/henryj-dev/lodestar/actions/workflows/ci.yml/badge.svg)](https://github.com/henryj-dev/lodestar/actions/workflows/ci.yml)
[![codeql](https://github.com/henryj-dev/lodestar/actions/workflows/codeql.yml/badge.svg)](https://github.com/henryj-dev/lodestar/actions/workflows/codeql.yml)

<br/>

![bun](https://img.shields.io/badge/Bun-1.x-000000?logo=bun&logoColor=white)
![typescript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)
![cloudflare workers](https://img.shields.io/badge/Cloudflare-Workers%20%C2%B7%20Node-F38020?logo=cloudflare&logoColor=white)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<br/>

> _A lodestar is the star you steer by — the fixed point everything else takes its
> bearing from._

English · [한국어](README.ko.md)

</div>

---

## Contents

- [The problem](#the-problem)
- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [How it fits together](#how-it-fits-together)
- [Configuration](#configuration)
- [HTTP API](#http-api)
- [Operations](#operations)
- [Development](#development)
- [Security notes](#security-notes)
- [Status & limitations](#status--limitations)
- [License](#license)

---

## The problem

An identity provider ends up holding two different things: who somebody is in the organization,
and what they are allowed to do in each service. It is tempting to let one answer both — the org
chart is already there, it is already a list, and a list of groups looks a lot like a set of
permissions.

It is not one. Authorize on group membership and moving teams moves a security boundary, a
reorganization reassigns permissions, and the person who edits the org chart becomes the person
who grants access.

Lodestar keeps the two apart deliberately. `groups` and the `organization` claims describe the
reporting structure and are meant for display. `roles` and `entitlements` are assigned per user
per service and are the only claims meant for authorization — issued regardless of scope wherever
a service assignment exists, and pushed to the relying party as a Security Event Token when an
administrator changes them. A SAML SP sees organization attributes only when it has been granted
them by name.

---

## What it does

| Feature                   |                                                                                                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **OIDC**                  | Authorization Code + PKCE, refresh tokens (rotation and reuse detection), UserInfo, JWKS, introspection, revocation, end-session                                               |
| **SAML 2.0**              | SP-initiated SSO (HTTP-Redirect and HTTP-POST bindings), assertion signing and encryption, `ForceAuthn`, `IsPassive`, `RequestedAuthnContext`, SLO                             |
| **ACR / AMR**             | ACR decided from how the session authenticated — carried in the SAML assertion and the OIDC ID token                                                                           |
| **Re-auth policy**        | Per client and per SP: require an MFA-level session, and choose whether re-authentication takes the password again or just an OTP on the live session                          |
| **WebAuthn / Passkey**    | Passkey registration and authentication, single-use challenges held in the database, tenant isolation                                                                          |
| **TOTP 2FA**              | Compatible with Google Authenticator and the like, with backup codes                                                                                                           |
| **LDAP**                  | LDAP authentication and JIT user provisioning, providers configured from the admin UI                                                                                          |
| **Account self-service**  | Profile, email change, password reset and recovery, MFA enrollment, passkey add and remove, active session listing and revocation, account deletion with a 30-day grace period |
| **Service authorization** | Per-service (RP) `roles` assignment and `entitlements` grants — issued as OIDC claims, with a SET notification to the RP on change                                             |
| **Service API tokens**    | Scope-limited bearer tokens issued and revoked per caller from the admin console                                                                                               |
| **Organization**          | Department → team → part hierarchy, grades and titles, multiple memberships                                                                                                    |
| **Multi-tenant**          | Users, clients and keys are managed independently per tenant                                                                                                                   |
| **Admin UI**              | CRUD for users, organization (departments, teams, parts, grades), OIDC clients, SAML SPs, LDAP providers, signing keys, service tokens, login skins and audit logs             |
| **Custom login skins**    | Per-client HTML and CSS for 10 auth screens (login, signup, MFA, logout …), sanitized server-side, cached in R2 or S3-compatible storage                                       |
| **Audit log**             | Logins, SSO and token issuance recorded automatically, each row carrying an integrity MAC, browsable from the admin UI                                                         |
| **i18n**                  | Message-catalog internationalization — Korean and English (`ko` / `en`)                                                                                                        |

### ACR / AMR mapping

ACR is derived from how the session authenticated (AMR) and carried into both the SAML
assertion and the OIDC ID token.

| Authentication         | AMR           | ACR                                                                 |
| ---------------------- | ------------- | ------------------------------------------------------------------- |
| Password only          | `pwd`         | `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` |
| Password + TOTP        | `pwd`, `totp` | `https://refeds.org/profile/mfa`                                    |
| Password + backup code | `pwd`, `swk`  | `https://refeds.org/profile/mfa`                                    |
| WebAuthn / Passkey     | `hwk`         | `https://refeds.org/profile/mfa`                                    |

When a SAML SP demands a particular ACR through `RequestedAuthnContext` and the session's
ACR does not meet it, re-authentication is forced. If it cannot be met at all — no MFA
enrolled, for instance — a `NoAuthnContext` error is returned to the ACS URL.

The admin console requires an MFA-level session of its own. An administrator whose session
is password-only is sent through an OTP step-up before `/admin` opens.

### Re-authentication policy — per client and per SP

Two settings on each OIDC client and SAML SP, on different axes. `require_mfa` decides
**what is demanded**; `reauth_policy` decides **what satisfies it**.

| Setting         | Default | Means                                                                            |
| --------------- | ------- | -------------------------------------------------------------------------------- |
| `require_mfa`   | off     | SSO to this service needs an MFA-level session (ACR `refeds/mfa`)                |
| `reauth_policy` | `full`  | `full` = re-authenticate from the password; `mfa_only` = OTP on the live session |

`require_mfa` is not the same as an RP sending `prompt=login`. `prompt=login` demands
re-authentication even when the session is already MFA, so moving between apps in the same
family throws up a login screen every time. `require_mfa` asks **only when the session falls
short**, so return visits after one OTP pass straight through. On SAML it is enforced by the
IdP even when the SP sends no `RequestedAuthnContext`, on both the SP-initiated and the
IdP-initiated path.

`reauth_policy=mfa_only` keeps the session and takes only an OTP, then raises that session's
AMR/ACR in place — the session row, its `sid` and the session cookie all survive, so other
RPs already signed in through it stay mapped. It applies to `require_mfa` shortfalls,
`prompt=login`, `max_age` expiry, `RequestedAuthnContext` shortfalls and `ForceAuthn`.

> [!WARNING]
> `mfa_only` gives up the guarantee that the password was reconfirmed recently — it reuses the
> first-factor proof already in the session. It relaxes what `prompt=login` asks for, and for
> SAML it relaxes `ForceAuthn`, which the spec (SAML Core 3.4.1.1) defines as establishing
> authentication freshly rather than relying on an existing session. That is why the default is
> `full` and this is opt-in per service. Enable it between services that trust each other.

An `id_token_hint` whose `sub` does not match the session is a request to **switch accounts**,
which an OTP cannot satisfy. That always forces a full login regardless of this setting.

### Per-SP attribute filtering

Each SP can carry an `allowedAttributes` list controlling what the assertion may include.
With none set, only `email`, `username` and `displayName` are sent. Organization attributes
(`department`, `team`, `jobTitle`, `position`) are included only when the SP allows them
explicitly.

---

## Quick start

You need [Bun](https://bun.sh) 1.x, a [Cloudflare account](https://dash.cloudflare.com)
with D1, R2 and Workers enabled, and the Wrangler CLI (`bun add -g wrangler`).

```bash
git clone https://github.com/henryj-dev/lodestar.git
cd lodestar
bun install
bun run setup
```

`bun run setup` walks through the steps below interactively. The database dialect comes from
`--dialect` (`d1` — the default — `postgres`, `mysql` or `sqlite`) or from `DB_DIALECT`, and
steps 3 to 5 branch on it:

1. **Configuration files** — `wrangler.example.jsonc` → `wrangler.jsonc`, `.env.example` → `.env`
2. **Dialect** — `--dialect` > `DB_DIALECT` env > `.env` > prompt
3. **Database**
    - `d1`: after checking the wrangler login, create a new D1 database or pick an existing one
      (a preview database is optional); the database and account ids are written into
      `wrangler.jsonc` and `.env`
    - `postgres` / `mysql` / `sqlite`: enter `DATABASE_URL` or reuse the existing value. For
      postgres and mysql, giving a Hyperdrive configuration id sets the `HYPERDRIVE` binding in
      `wrangler.jsonc` automatically
4. **Migrations** — run the dialect's `db:generate*` and apply the schema (for D1 this includes
   detecting and handling conflicting tables)
5. **First administrator** — organization name, administrator account and issuer URL, seeded into
   the database (a password is generated if none is given)
6. **Signing key** — `IDP_SIGNING_KEY_SECRET` generated or entered, then saved to `.env`

```bash
# for example, setting up on PostgreSQL
bun run setup -- --dialect postgres --database-url "postgres://user:pass@host:5432/db" --hyperdrive-id <id>
```

> [!NOTE]
> The R2 bucket (`lodestar-skin-cache`) is only needed for custom login skins. Without that
> feature you can comment out `r2_buckets` in `wrangler.jsonc`.

Then start the development server:

```bash
bun run dev
```

---

## How it fits together

### Stack

- **Runtime**: Cloudflare Workers by default (`nodejs_als`, `nodejs_compat`), or a plain Node
  server (`adapter-node`, `BUILD_TARGET=node`) — see
  [deployment target](#deployment-target-cloudflare-workers-or-plain-node)
- **Framework**: SvelteKit 2 + Svelte 5 (runes), `@sveltejs/adapter-cloudflare`
- **Database**: one of Cloudflare D1 (SQLite), libSQL (SQLite), PostgreSQL or MySQL, through
  Drizzle ORM. PostgreSQL and MySQL reach the server over Hyperdrive, Workers VPC, or a direct
  `DATABASE_URL` — see [choosing a database dialect](#choosing-a-database-dialect)
- **Object storage**: Cloudflare R2 or anything S3-compatible (AWS S3, MinIO) for the login-skin cache
- **Styling**: Tailwind CSS 4
- **Crypto**: Web Crypto API (RSA/EC signing, HKDF derivation, AES-256-GCM), `node:crypto` scrypt
  for password hashing, `@simplewebauthn/*`, `xmldsigjs`
- **Language and tooling**: TypeScript, Bun, ESLint, Prettier

### Source tree

```text
src/
├── hooks.server.ts        # session restore, security headers, CSRF origin check, tenant context
├── app.html
├── routes/
│   ├── +error.svelte      # root error page (404 / 403 / 503 …)
│   ├── (auth)/            # login, signup, logout, mfa, find-id, find-password,
│   │                      #   reset-password, verify-email, accept-invite
│   ├── account/           # profile, mfa, passkeys, sessions, danger-zone,
│   │                      #   confirm-email-change (account self-service)
│   ├── admin/             # admin UI (users, departments, teams, parts, positions,
│   │                      #   oidc-clients, saml-sps, ldap-providers, signing-keys,
│   │                      #   service-tokens, skins, audit, login)
│   ├── oidc/              # authorize, token, userinfo, jwks, end-session,
│   │                      #   introspect, revoke
│   ├── saml/              # sso, slo, metadata
│   ├── .well-known/       # openid-configuration (discovery)
│   └── api/               # health, webauthn/*, totp/*, users/lookup, skin-scripts/*
└── lib/
    ├── components/        # shared Svelte components
    ├── i18n/              # message catalogs (ko.json, en.json)
    ├── assets/
    └── server/
        ├── auth/          # session, password (scrypt), mfa, totp, webauthn, guards,
        │                  #   csrf, redirect, invite, email-verification, email-change,
        │                  #   trusted-device, service-token, breach-check, bootstrap
        ├── oidc/          # client, grant, pkce, refresh, claims, logout, role-change
        ├── saml/          # sp, metadata, parse-authn-request, response, slo,
        │                  #   verify-xml-signature, encrypt, cert-validity
        ├── ldap/          # auth, client, provision
        ├── access/        # service role and entitlement decisions
        ├── admin/         # admin CRUD factory, Zod schemas, user actions
        ├── crypto/        # signing-key management, JWT issuance, key rotation, HKDF
        ├── audit/         # audit event recording (per-row integrity MAC)
        ├── org/           # organization membership lookup
        ├── ratelimit/     # rate limiting for authentication endpoints (storage abstracted)
        ├── skin/          # custom login skins (resolver, sanitize, storage)
        └── db/            # Drizzle per-dialect schema, drivers, GC

drizzle/                   # migration SQL (drizzle-kit generate output, one directory per dialect)
test/                      # vitest unit and integration tests
docs/                      # operations manual, design and audit documents
scripts/setup.ts           # interactive first-run setup
```

---

## Configuration

### Environment variables

[`.env.example`](.env.example) carries the full list with detailed comments. These are the ones
in regular use.

| Variable                            | Required    |                                                                                                                                                                           |
| ----------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IDP_ISSUER_URL`                    | ✅          | OIDC/SAML issuer URL, matching the deployed domain. **Required in production** — without it requests fail closed with a 503. Only in dev does the request origin stand in |
| `IDP_SIGNING_KEY_SECRET`            | ✅          | KEK encrypting the signing keys (a Secret in production). **Required in production** — without it requests fail fast                                                      |
| `IDP_SIGNING_KEY_SECRET_PREVIOUS`   | optional    | Set alongside the current value only while **rotating the master secret**; decryption falls back current → previous ([rotation procedure](docs/SECRET_ROTATION.md))       |
| `BUILD_TARGET`                      | optional    | `cloudflare` (default) or `node` — which adapter to build. Read **at build time**                                                                                         |
| `DB_DIALECT`                        | optional    | `d1` (default), `sqlite`, `postgres` or `mysql`. Read **at build, typecheck and migration-generation time as well**                                                       |
| `DATABASE_URL`                      | conditional | Connection string for postgres, mysql or sqlite. On Cloudflare a `HYPERDRIVE` binding takes precedence                                                                    |
| `DATABASE_AUTH_TOKEN`               | optional    | Auth token for remote libSQL such as Turso (only with `sqlite` against a remote)                                                                                          |
| `DISPATCHER_SERVICE_TOKEN`          | optional    | Legacy **all-scope** bearer token for the service API. Prefer per-caller tokens from the admin console. With neither this nor an issued token, those APIs answer 503      |
| `IDP_DEFAULT_TENANT_NAME`           | optional    | Default tenant name (default `My Organization`)                                                                                                                           |
| `IDP_TENANT_BASE_DOMAIN`            | optional    | Base domain for `<tenant-slug>.<base-domain>` routing. Explicit `/t/<tenant-slug>/…` paths also work                                                                      |
| `IDP_TENANT_ISSUER_MODE`            | optional    | `shared` (default), `host` or `path` — per-tenant OIDC/SAML issuer strategy                                                                                               |
| `RATELIMIT_STORE`                   | optional    | `auto` (default), `memory`, `db` or `redis` — use `db` or `redis` for multi-instance Node                                                                                 |
| `RATELIMIT_REDIS_URL` / `_TOKEN`    | conditional | Upstash-compatible Redis REST credentials, needed when `RATELIMIT_STORE=redis`                                                                                            |
| `APP_INSTANCE_COUNT`                | optional    | Node instance count, used to warn when memory rate limiting is chosen for more than one                                                                                   |
| `IDP_ENFORCE_SP_CERT_VALIDITY`      | optional    | Enforce SAML SP certificate validity periods. **On by default** — only `"false"` relaxes it                                                                               |
| `PASSWORD_BREACH_CHECK`             | optional    | Screen against breached passwords (HIBP k-anonymity). Off by default; API errors fail open                                                                                |
| `SMTP_HOSTNAME` and other `SMTP_*`  | optional    | Outbound mail (password recovery, invitations, email verification, security notices). Unset means those mails are skipped                                                 |
| `S3_ENDPOINT` and other `S3_*`      | optional    | S3-compatible storage for the skin cache, used when there is no R2 binding                                                                                                |
| `CLOUDFLARE_ACCOUNT_ID`             | optional    | Cloudflare account id (used by the migration scripts)                                                                                                                     |
| `CLOUDFLARE_D1_DATABASE_ID`         | optional    | D1 database id (used by the migration scripts)                                                                                                                            |
| `CLOUDFLARE_D1_PREVIEW_DATABASE_ID` | optional    | Preview D1 database id                                                                                                                                                    |
| `CLOUDFLARE_D1_TOKEN`               | optional    | D1 API token (used by `db:migrate`)                                                                                                                                       |

LDAP identity/user tenant consistency can be checked once before deploying with
`bun run db:check-tenant-consistency`; the runtime GC also emits structured warnings periodically.

> [!NOTE]
> `bun run setup` creates the first administrator. For a manual or CI seed, set
> `IDP_BOOTSTRAP_ADMIN_USERNAME` / `IDP_BOOTSTRAP_ADMIN_EMAIL` / `IDP_BOOTSTRAP_ADMIN_PASSWORD`
> (and optionally `IDP_BOOTSTRAP_ADMIN_NAME`) and run `bun run db:seed` (or the per-dialect
> `db:seed:pg` and friends). In non-interactive environments `SEED_RESET=0|1` decides whether to
> reset first.

### Cloudflare bindings (`wrangler.jsonc`)

| Binding      | Kind       |                                                                         |
| ------------ | ---------- | ----------------------------------------------------------------------- |
| `DB`         | D1         | Main database, when `DB_DIALECT=d1`                                     |
| `HYPERDRIVE` | Hyperdrive | PostgreSQL/MySQL connection, when `DB_DIALECT` is `postgres` or `mysql` |
| `SKIN_CACHE` | R2         | Custom login-skin cache                                                 |
| `ASSETS`     | static     | SvelteKit build output (`.svelte-kit/cloudflare`)                       |

### Choosing a database dialect

D1 (SQLite), libSQL (SQLite), PostgreSQL and MySQL are all supported, and **exactly one is used
per deployment**. D1 is the convenient choice but its latency is comparatively high; where that
matters, reach PostgreSQL or MySQL through Cloudflare Hyperdrive or connect to your own database
directly.

The dialect is chosen with `DB_DIALECT` (`d1` by default, or `sqlite`, `postgres`, `mysql`). That
value is read **not only at runtime but at build, typecheck and migration-generation time**, where
it decides the schema and the driver.

| Dialect    | Driver           | Connects to                                                 |
| ---------- | ---------------- | ----------------------------------------------------------- |
| `d1`       | `drizzle-orm/d1` | Cloudflare D1 (a Workers-only binding)                      |
| `sqlite`   | libSQL           | A local file (`file:`) or Turso, for plain Node and similar |
| `postgres` | postgres-js      | Hyperdrive, or `DATABASE_URL` directly                      |
| `mysql`    | mysql2           | Hyperdrive, or `DATABASE_URL` directly                      |

```bash
# build and deploy on PostgreSQL
DB_DIALECT=postgres bun run build
DB_DIALECT=postgres bun run deploy   # or wrangler deploy

# build and deploy on MySQL
DB_DIALECT=mysql bun run build

# run on plain Node against a local SQLite file (libSQL)
BUILD_TARGET=node DB_DIALECT=sqlite DATABASE_URL="file:./lodestar.db" bun run build && node build
```

How it works:

- Schemas are kept per dialect: `schema.sqlite.ts` (shared by d1 and sqlite), `schema.pg.ts` and
  `schema.mysql.ts`. All three keep the same table, column and index names and the same inferred
  JS types, and the `schema.ts` barrel resolves to whichever matches `DB_DIALECT`.
- `getDb()` in `src/lib/server/db/index.ts` picks the driver for the dialect (d1, libSQL,
  postgres-js or mysql2). Only the active dialect's driver is bundled.
- **Connection-string precedence**: `sqlite` reads `DATABASE_URL` or `SQLITE_URL` (without a
  `file:` scheme it is taken as a local path). `postgres` and `mysql` read the `HYPERDRIVE`
  binding first on Cloudflare, then `DATABASE_URL` (var or secret); on plain Node, `DATABASE_URL`.
- **Private-network Postgres/MySQL — Workers VPC**: declaring a **`VPC`** binding through
  `vpc_networks` in `wrangler.jsonc` (the name is fixed — the code reads `platform.env.VPC`) sends
  the driver's TCP connection out through a Cloudflare Tunnel to a private address. Inject the
  credentials as a **secret** `DATABASE_URL` in that case, and the private database is never
  publicly exposed.

```bash
# (Cloudflare) create the Hyperdrive configuration — the binding must be named HYPERDRIVE
wrangler hyperdrive create lodestar-pg    --connection-string="postgres://user:pass@host:5432/db"
wrangler hyperdrive create lodestar-mysql --connection-string="mysql://user:pass@host:3306/db"
```

Put the id it prints into `hyperdrive[].id` in `wrangler.jsonc` and uncomment the entry — or let
`bun run setup -- --dialect postgres --hyperdrive-id <id>` do it. To connect directly instead, set
`DATABASE_URL` as a var or secret. Then apply the schema and seed:

```bash
bun run db:generate:pg && bun run db:migrate:pg
bun run db:seed:pg
```

### Deployment target: Cloudflare Workers or plain Node

`BUILD_TARGET` (`cloudflare` by default, or `node`) switches the adapter. `node` builds through
`@sveltejs/adapter-node` and runs as a plain Node server with no Cloudflare involved. Node has no
`platform` bindings, so it uses **PostgreSQL, MySQL or sqlite (libSQL)** — D1 is Workers-only —
reading the connection from `DATABASE_URL` and the settings from `process.env`.

```bash
# build and run on PostgreSQL under plain Node
export BUILD_TARGET=node DB_DIALECT=postgres
export DATABASE_URL="postgres://user:pass@host:5432/db"
# other settings come from the environment too: IDP_SIGNING_KEY_SECRET, IDP_ISSUER_URL, …
bun run build
node build            # adapter-node output, PORT=3000 by default
```

> [!NOTE]
> MySQL supports neither `UPDATE … RETURNING` nor partial unique indexes. The logic that needs
> them — consuming authorization codes and WebAuthn challenges, signing-key rotation, rate-limit
> upserts — branches per dialect and reaches the same result on MySQL through `affectedRows`
> checks, re-reads and transactions.

### Skin cache storage: R2 or S3-compatible

The custom login-skin cache picks its storage in this order. With neither configured there is no
cache and the origin is fetched every time, which works.

1. A **Cloudflare R2 binding** (`SKIN_CACHE`), if present.
2. Otherwise **S3-compatible settings** (`S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`,
   `S3_SECRET_ACCESS_KEY`).

R2 is itself S3-compatible, so AWS S3, MinIO and Ceph all work — as does R2's own S3 endpoint.
Signing is done with `aws4fetch` and works on both Workers and Node. Path-style versus
virtual-host addressing is controlled by `S3_FORCE_PATH_STYLE` (`true` by default, which is what
MinIO and R2 want). See [`.env.example`](.env.example) for the full set.

---

## HTTP API

### OIDC — discovery at `/.well-known/openid-configuration`

| Path                                |                                                                                                                                    |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `/.well-known/openid-configuration` | OIDC discovery document                                                                                                            |
| `/oidc/authorize`                   | Authentication request (Authorization Code + PKCE). Handles `prompt` (`none`/`login`), `max_age`, `id_token_hint` and `login_hint` |
| `/oidc/token`                       | Token exchange (authorization code, refresh token)                                                                                 |
| `/oidc/userinfo`                    | UserInfo endpoint                                                                                                                  |
| `/oidc/introspect`                  | Token introspection (RFC 7662)                                                                                                     |
| `/oidc/revoke`                      | Token revocation (RFC 7009)                                                                                                        |
| `/oidc/jwks`                        | JSON Web Key Set                                                                                                                   |
| `/oidc/end-session`                 | RP-initiated logout ([implementation notes](docs/oidc-rp-initiated-logout.md))                                                     |

#### Issued claims — `groups` and `roles` are not for the same thing

| Claim                   | Means                                              | Use for                          |
| ----------------------- | -------------------------------------------------- | -------------------------------- |
| `groups`                | Organizational membership (department, team, part) | **Display. Never authorization** |
| `organization` family   | Organization detail (department, grade, title)     | **Display**                      |
| `roles` · `roles_label` | Service role (assigned per user per service)       | **Authorization**                |
| `entitlements`          | Service permissions (an axis orthogonal to role)   | **Authorization**                |

> [!WARNING]
> **Do not authorize on `groups`.** The name reads like an authorization claim and the value is a
> list, so it looks like a permission set — but what it actually holds is **your reporting
> structure**. Authorize on it and moving teams moves a security boundary, a reorganization
> reassigns permissions, and you can no longer separate the person who edits the org chart from
> the person who grants access. Use `roles` and `entitlements` for service authorization.

`roles` is **one per user per service** — it is an array, but a schema constraint keeps it to a
single element. `entitlements` attaches multiple permission keys to that same assignment and is
not bounded that way. `groups` and `organization` are issued only when their scope is requested;
`roles` and `entitlements` are issued whenever a service assignment exists, regardless of scope
(and the key is omitted entirely when there is no value). See the
[administrator guide](docs/ADMIN_GUIDE.md) for how roles and entitlements are defined and assigned.

When an administrator changes a role or entitlement and the client has a `role_change_uri`
registered, a **Security Event Token (SET)** is POSTed to that URI. The RP refreshes the
permissions without dropping the session, so the change takes effect on the next request with no
re-login. It is fire-and-forget with no retry — the RP must discard a late-arriving snapshot using
the `txn` ordering marker. The contract is documented at the top of
`src/lib/server/oidc/role-change.ts`.

SAML carries the same values, as an **`Entitlements` attribute** on the assertion — a list, so
several `<saml:AttributeValue>` inside one `<saml:Attribute>`. As with `Role` and `RoleLabel`,
the SP's `allowedAttributes` must name `Entitlements` for it to actually be sent.

The `sub` claim equals `users.id`, and can be used directly as the `userId` in the
[service-to-service TOTP API](#service-to-service-totp-api) below.

### SAML 2.0

| Path             |                                           |
| ---------------- | ----------------------------------------- |
| `/saml/metadata` | IdP metadata XML                          |
| `/saml/sso`      | SP-initiated SSO (handles `AuthnRequest`) |
| `/saml/slo`      | Single logout, including chained SLO      |

### WebAuthn and other APIs

| Path                                 |                                                                 |
| ------------------------------------ | --------------------------------------------------------------- |
| `/api/health`                        | Health check — liveness plus a shallow database readiness probe |
| `/api/webauthn/register/options`     | Issue a passkey registration challenge                          |
| `/api/webauthn/register/verify`      | Verify the registration attestation                             |
| `/api/webauthn/authenticate/options` | Issue an authentication challenge                               |
| `/api/webauthn/authenticate/verify`  | Verify the authentication assertion                             |
| `/api/skin-scripts/*`                | Per-client custom skin scripts                                  |

### Service-to-service TOTP API

For a trusted service to enroll or verify TOTP on a user's behalf. Every request needs an
`Authorization: Bearer <service token>` header.

Issue tokens per caller from **the admin console → service tokens** (`/admin/service-tokens`) and
grant only the scopes that caller needs. The plaintext is shown once at issuance; only a hash is
stored.

| Scope          | Opens                                                |
| -------------- | ---------------------------------------------------- |
| `totp.verify`  | `/api/totp/verify`                                   |
| `totp.status`  | `/api/totp/status`                                   |
| `totp.enroll`  | `/api/totp/enroll/init` · `/api/totp/enroll/confirm` |
| `users.lookup` | `/api/users/lookup`                                  |

> [!NOTE]
> `DISPATCHER_SERVICE_TOKEN` is a legacy path holding **every scope**. It remains so existing
> callers keep working; remove it once they have all moved to issued tokens.

| Path                       | Method |                                                                        |
| -------------------------- | ------ | ---------------------------------------------------------------------- |
| `/api/totp/enroll/init`    | POST   | `{userId}` → `{secret, otpAuthUri, username}` (stateless)              |
| `/api/totp/enroll/confirm` | POST   | `{userId, secret, code}` → verify, persist, and return `{backupCodes}` |
| `/api/totp/verify`         | POST   | `{userId, code}` → step-up verification → `{ok, verifiedAt}`           |
| `/api/totp/status`         | GET    | `?userId=…` → `{enrolled, backupCodeCount, lastUsedAt}`                |

---

## Operations

### Production deployment

```bash
bun run deploy
```

Set the sensitive values as Wrangler secrets before deploying:

```bash
wrangler secret put IDP_SIGNING_KEY_SECRET
```

> [!IMPORTANT]
> Plaintext in `.env` is fine for local development. In production these must be secrets.

### Database migrations

Changing the schema, generating a migration and applying it goes like this.

1. Edit the schema file for the dialect you use. Keep the structure and types identical across all
   three.
    - D1 and sqlite → `src/lib/server/db/schema.sqlite.ts` (shared)
    - PostgreSQL → `src/lib/server/db/schema.pg.ts`
    - MySQL → `src/lib/server/db/schema.mysql.ts`

2. Generate the SQL for that dialect.

    ```bash
    bun run db:generate          # D1         → drizzle/*.sql
    bun run db:generate:sqlite   # libSQL     → drizzle/sqlite/*.sql (same DDL as D1)
    bun run db:generate:pg       # PostgreSQL → drizzle/pg/*.sql
    bun run db:generate:mysql    # MySQL      → drizzle/mysql/*.sql
    ```

3. Review the generated SQL.

4. Apply it to the remote database yourself.

    ```bash
    bun run db:migrate          # D1 production
    bun run db:migrate:preview  # D1 preview
    ```

    For PostgreSQL and MySQL, set `DATABASE_URL` and apply with `drizzle-kit migrate`.

> [!WARNING]
> Applying a migration to a remote D1 is hard to undo. Make it operational policy that automated
> scripts and agents do not run it on their own.

---

## Development

| Command                      |                                                                |
| ---------------------------- | -------------------------------------------------------------- |
| `bun run dev`                | Vite development server                                        |
| `bun run build`              | Production build                                               |
| `bun run preview`            | Preview the build output through Wrangler (`localhost:4173`)   |
| `bun run check`              | `wrangler types` + `svelte-check`                              |
| `bun run lint`               | Prettier + ESLint                                              |
| `bun run format`             | Prettier, writing                                              |
| `bun run test`               | vitest + `bun test` (see below)                                |
| `bun run test:node`          | vitest only (`test:watch`, `test:coverage`)                    |
| `bun run test:workers`       | `bun test test/workers` — needs Workers' `HTMLRewriter`        |
| `bun run gen`                | Regenerate Wrangler environment types                          |
| `bun run db:generate`        | Generate Drizzle migration SQL (D1)                            |
| `bun run db:generate:sqlite` | Generate migration SQL (libSQL/SQLite)                         |
| `bun run db:generate:pg`     | Generate migration SQL (PostgreSQL)                            |
| `bun run db:generate:mysql`  | Generate migration SQL (MySQL)                                 |
| `bun run db:migrate`         | Apply migrations and the seed migration (D1)                   |
| `bun run db:migrate:pg`      | Apply migrations and the seed migration (PostgreSQL)           |
| `bun run db:seed`            | Seed baseline data — tenant, administrator, service roles (D1) |
| `bun run db:seed:pg`         | Seed baseline data (PostgreSQL)                                |
| `bun run db:studio`          | Drizzle Studio                                                 |
| `bun run deploy`             | Deploy to Cloudflare Workers                                   |

`bun run test` runs the vitest suite and then `bun test test/workers`. The split exists because
`sanitizeSkinHtml` (custom login skins) uses the Workers global `HTMLRewriter`, which vitest's node
process does not have — Bun provides the same API natively, so those tests run there instead. CI
calls `bun run test` and covers both. Use `bun run test:node -- <file>` to run a single vitest file.

`db:migrate`, `db:seed`, `db:push` and `db:studio` all take `:pg`, `:mysql` and `:sqlite` suffixes
for the other dialects. postgres, mysql and sqlite use `DATABASE_URL`; D1 uses the `CLOUDFLARE_*`
variables. `scripts/seed.ts` and `scripts/seed-migrate.ts` are dialect-agnostic through the shared
helper `scripts/lib/db.ts`, and reach D1 over its REST API.

---

## Security notes

### Password hashing

New passwords are hashed with **scrypt** (native `node:crypto`, N=2^15, r=8, p=3 — about 32 MiB,
an OWASP-recommended combination). It behaves identically on Workers, Node and Bun.

Legacy hashes stored as **argon2id** (`@hicaru/argon2-pure.js`) or **PBKDF2-SHA256** still verify,
and are **re-hashed to scrypt automatically on a successful login**. argon2id was abandoned
because the pure-JS implementation spent roughly 4.4 seconds of CPU per verification and was the
main source of request latency on Workers; the reasoning is written up at the top of
`src/lib/server/auth/password.ts`.

### Signing keys

The RSA keys that sign OIDC ID tokens and SAML responses are stored in the database encrypted
under `IDP_SIGNING_KEY_SECRET`. Leaking that secret exposes every signing key, so use a strong
random value (`openssl rand -base64 32`) and rotate it on a schedule. Signing keys themselves are
rotated from the admin UI at `/admin/signing-keys`.

Rotating `IDP_SIGNING_KEY_SECRET` **itself** is a separate procedure — run with
`IDP_SIGNING_KEY_SECRET_PREVIOUS` alongside it for a no-downtime switch, then run the
re-encryption batch. Follow [docs/SECRET_ROTATION.md](docs/SECRET_ROTATION.md).

### WebAuthn challenges

Registration and authentication challenges are stored single-use and deleted the moment they are
consumed. They are isolated by tenant id, so one tenant's challenge cannot be replayed against
another.

### LDAP account linking

When LDAP authentication succeeds and a local account already exists with the same email address,
the two are **not linked automatically**. That prevents an LDAP provider from forging an email to
take over an existing administrator account. Linking to an existing local account is an
administrator's explicit action.

### Security headers

`hooks.server.ts` applies these to every response.

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security` (HSTS)
- `Permissions-Policy` (camera, microphone, geolocation and payment disabled)
- A hash-based `Content-Security-Policy`

### Bootstrap administrator

`bun run setup` inserts the first administrator straight into the active database, whichever
dialect it is. Change that password and set up MFA as soon as setup finishes.

The console is gated on the session's ACR, not just on the role — an administrator without TOTP
enrolled cannot reach `/admin` by any path, including a session established at `/login`. The gate
sits in two places because a `+layout.server.ts` load does not run for form-action POSTs: the
layout redirects to the OTP step-up, and `requireAdminContext()` returns 403 for any admin action
called directly. An administrator with no TOTP credential gets an enrollment notice instead of a
redirect, and can enroll at `/account/mfa`, which does not require admin rights.

### Audit log integrity

Every row in `audit_events` carries an HMAC-SHA256 MAC (`hash`) over its stable fields, which
detects tampering with that row. It is not a prev-hash chain — which avoids the concurrent-write
fork problem, at the cost that **deleting a row is not detectable**. Mirror the log externally,
with Logpush or similar, if you need that.

---

## Status & limitations

**What works.** OIDC (Authorization Code + PKCE, refresh-token rotation and reuse detection,
UserInfo, JWKS, introspection, revocation, end-session), SAML 2.0 SP-initiated SSO and SLO,
WebAuthn/Passkey, TOTP 2FA, LDAP authentication with JIT provisioning, account self-service,
per-service roles and entitlements, per-client and per-SP re-authentication policy (MFA-only
step-up on a live session), the organization hierarchy, multi-tenancy, the admin UI,
custom login skins, an audit log with per-row integrity MACs, and Korean/English i18n. It deploys
to Cloudflare Workers or plain Node, over D1, libSQL, PostgreSQL or MySQL — one per deployment.

**What doesn't yet.** The audit log's MAC catches tampering with a row but **cannot detect a row
being deleted**; an external mirror is the answer where that matters.
`DISPATCHER_SERVICE_TOKEN` is a legacy all-scope path that should go away once every caller has
moved to an issued token.

**Not frozen.** This is an actively developed IdP, built to learn and to experiment with. Do your
own security review against your own threat model before putting it in front of production
traffic. The known security limits are collected under [Security notes](#security-notes).

---

## License

MIT. See [LICENSE](LICENSE).
