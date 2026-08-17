# `@gauts/auth`

Database-backed password authentication and opaque browser sessions for Node.js applications.

`@gauts/auth` provides the reusable authentication layer: password hashing, session lifecycle, secure cookies, database validation, optional short caching, and framework adapters. The application keeps control of registration, account lookup, authorization, routes, responses, and UI.

## Features

| Capability                         | Support | Default             |
| ---------------------------------- | :-----: | ------------------- |
| Argon2id password hashing          |   ✅    | Enabled             |
| bcrypt password hashing            |   ✅    | Opt-in              |
| Opaque server-side sessions        |   ✅    | Enabled             |
| Database-backed validation         |   ✅    | Enabled             |
| Sliding session renewal            |   ✅    | Every 24 hours      |
| Absolute session lifetime          |   ✅    | 30 days             |
| Signed browser cache               |   ✅    | Disabled            |
| Full User-Agent validation         |   ✅    | Enabled             |
| IP validation                      |   ✅    | Disabled            |
| Platform validation                |   ✅    | Disabled            |
| Hono adapter                       |   ✅    | Available           |
| Prisma adapter                     |   ✅    | Available           |
| Next.js renewal adapter            |   ✅    | Available           |
| Session listing and revocation     |   ✅    | Available           |
| Token rotation                     |   ❌    | Stable opaque token |
| JWT sessions                       |   ❌    | Not used            |
| Redis requirement                  |   ❌    | Not required        |
| Registration, OAuth, OTP, or email |   ❌    | Application-owned   |
| Route roles and permissions        |   ❌    | Application-owned   |

“Session renewal” extends the existing session expiry when activity continues. It is not a refresh-token flow and does not rotate the opaque browser token.

## Installation

### Requirements

- Node.js 22 or newer.
- A database adapter.
- Hono 4 when using the Hono adapter.
- Next.js 15 or newer when using the Next.js adapter.

### Hono and Prisma

```bash
npm install @gauts/auth hono @prisma/client
```

### Next.js

```bash
npm install @gauts/auth next
```

`hono` and `next` are optional peer dependencies. The Prisma adapter receives the application's generated Prisma client and does not import Prisma at runtime.

### Package entry points

| Import               | Purpose                                                   |
| -------------------- | --------------------------------------------------------- |
| `@gauts/auth`        | Password service, session core, errors, and public types. |
| `@gauts/auth/prisma` | Prisma database adapter.                                  |
| `@gauts/auth/hono`   | Hono cookies, methods, and middleware.                    |
| `@gauts/auth/next`   | Next.js renewal scheduling and `Set-Cookie` forwarding.   |

## Quick start

The Hono adapter does not create routes automatically. The application defines its own login, renewal, logout, and protected endpoints.

### 1. Create the auth instance

```ts
import { createHonoAuth } from "@gauts/auth/hono";
import { createPrismaAdapter } from "@gauts/auth/prisma";

import { prisma } from "./db.js";

export const auth = createHonoAuth({
    db: createPrismaAdapter({
        client: prisma,
    }),
});
```

This uses the defaults:

```text
password       Argon2id
session TTL    7 days
renewal        every 24 hours
max lifetime   30 days
validation     User-Agent
cache          disabled
cookies        __ses, __cac, __ren
```

### 2. Add the routes

```ts
import { Hono } from "hono";
import type { AuthAccountOf } from "@gauts/auth";
import type { HonoAuthEnv } from "@gauts/auth/hono";

import { auth } from "./auth.js";

type Account = AuthAccountOf<typeof auth>;

const app = new Hono<HonoAuthEnv<Account>>();

app.post("/auth/login", async (c) => {
    const body = await c.req.json<{
        email: string;
        password: string;
    }>();

    const account = await findAccount(body.email);

    const passwordValid = await auth.password.verify({
        password: body.password,
        storedHash: account?.passwordHash,
    });

    if (!account || !passwordValid) {
        return c.json({ error: "Invalid credentials." }, 401);
    }

    await auth.createSession({
        account_id: account.id,
        context: c,
    });

    return c.json({ authenticated: true });
});

app.post("/auth/renew", async (c) => {
    await auth.renewSession(c);
    return c.body(null, 204);
});

app.post("/auth/logout", async (c) => {
    await auth.revokeSession(c);
    return c.body(null, 204);
});

app.get("/account", auth.requireSession, (c) => {
    return c.json({
        account: c.get("account"),
        session: c.get("session"),
    });
});
```

When `storedHash` is missing, the package performs password work with the configured algorithm and always returns `false`. Applications do not need a dummy hash. Keep the response identical for unknown accounts and incorrect passwords.

### 3. Enable the optional cache

```ts
export const auth = createHonoAuth({
    cache: {
        ttl: 60,
    },
    db,
    secret: requiredEnv("AUTH_SECRET"),
});
```

`AUTH_SECRET` must contain at least 32 high-entropy bytes. It stays in the API and is never shared with Next.js.

`requiredEnv()` represents an application helper that returns a non-empty environment string or fails during startup.

## Configuration reference

### `createHonoAuth()`

| Property   | Type / allowed values |        Required         | Default           | Description                                                                                         |
| ---------- | --------------------- | :---------------------: | ----------------- | --------------------------------------------------------------------------------------------------- |
| `db`       | `DbAdapter`           |           ✅            | —                 | Authoritative session persistence and account loading.                                              |
| `getIp`    | `HonoGetIp`           | Only with IP validation | Omitted           | Returns the client IP from a source trusted by the application. May be synchronous or asynchronous. |
| `password` | `PasswordConfig`      |           ❌            | Argon2id defaults | Password hashing and verification configuration.                                                    |
| `session`  | `SessionConfig`       |           ❌            | Session defaults  | Expiry, renewal, and client validation configuration.                                               |
| `cookie`   | `HonoCookieConfig`    |           ❌            | Cookie defaults   | Names, domain, path, SameSite, and Secure settings.                                                 |
| `cache`    | `{ ttl: number }`     |           ❌            | Disabled          | Enables the short signed browser cache.                                                             |
| `secret`   | `string`              | When `cache` is enabled | —                 | HMAC secret for the signed cache. Minimum 32 UTF-8 bytes.                                           |

```ts
type HonoGetIp = (c: Context) => Promise<string | null | undefined> | string | null | undefined;
```

When `getIp` is omitted, the adapter stores `ip: null` and does not read IP headers automatically. Configuring `session.validation` with `"ip"` requires `getIp` and fails during initialization when it is missing.

### Password

#### Argon2id

Argon2id is selected when `password.algorithm` is omitted or set to `"argon2id"`.

| Property      | Type / allowed values       |      Default | Description                                                       |
| ------------- | --------------------------- | -----------: | ----------------------------------------------------------------- |
| `algorithm`   | `"argon2id"`                | `"argon2id"` | Password algorithm used for both hashing and verification.        |
| `hashLength`  | Integer `16`–`64`           |         `32` | Output hash length in bytes.                                      |
| `maxBytes`    | Integer `1`–`1,048,576`     |       `1024` | Maximum UTF-8 password size accepted by hashing and verification. |
| `memoryCost`  | Integer `8,192`–`1,048,576` |     `65,536` | Argon2 memory cost in KiB.                                        |
| `parallelism` | Integer `1`–`16`            |          `4` | Number of parallel lanes.                                         |
| `timeCost`    | Integer `1`–`10`            |          `3` | Number of Argon2 iterations.                                      |

```ts
password: {
    algorithm: "argon2id",
}
```

#### bcrypt

Applications with existing bcrypt hashes must select bcrypt explicitly.

| Property         | Type / allowed values                  |  Default | Description                                             |
| ---------------- | -------------------------------------- | -------: | ------------------------------------------------------- |
| `algorithm`      | `"bcrypt"`                             | Required | Selects bcrypt for both hashing and verification.       |
| `maxBytes`       | Integer `1`–`72`                       |     `72` | Maximum UTF-8 size accepted for new passwords.          |
| `rounds`         | Integer `4`–`31`                       |     `12` | bcrypt cost factor.                                     |
| `verifyMaxBytes` | Integer from `maxBytes` to `1,048,576` |     `72` | Maximum input accepted while verifying existing hashes. |

```ts
password: {
    algorithm: "bcrypt",
}
```

The package does not detect algorithms, migrate hashes, rehash passwords, or fall back to another algorithm.

`auth.password.verify()` accepts a missing `storedHash` so account lookup and password verification can follow one path. A missing or incompatible hash performs password work with the configured algorithm and returns `false`; it is never accepted or passed to another algorithm.

### Session

All time values are seconds.

| Property        | Type / allowed values                           |               Default | Description                                                               |
| --------------- | ----------------------------------------------- | --------------------: | ------------------------------------------------------------------------- |
| `maxLifetime`   | Integer from `ttl` to `31,536,000`              | `2,592,000` (30 days) | Maximum session lifetime from the original login, regardless of activity. |
| `renewInterval` | Integer `1` to `ttl - 1`                        |   `86,400` (24 hours) | Minimum interval before sliding renewal is due.                           |
| `ttl`           | Integer `60`–`31,536,000`                       |    `604,800` (7 days) | Inactivity lifetime assigned at login and renewal.                        |
| `validation`    | Unique array of `"agent"`, `"ip"`, `"platform"` |           `["agent"]` | Client fields that must match the stored session exactly.                 |

```ts
session: {
    maxLifetime: 60 * 60 * 24 * 30,
    renewInterval: 60 * 60 * 24,
    ttl: 60 * 60 * 24 * 7,
    validation: ["agent", "ip"],
}
```

Validation values:

| Enum         | Source                                | Behavior                                                 |
| ------------ | ------------------------------------- | -------------------------------------------------------- |
| `"agent"`    | Complete `User-Agent` header          | Enabled by default. The complete value must match.       |
| `"ip"`       | Application-provided `getIp()` result | IPv4 and IPv6 are canonicalized before exact comparison. |
| `"platform"` | `Sec-CH-UA-Platform` header           | Normalized and compared exactly.                         |

Every selected field is required during session creation and validation. A mismatch revokes the database session.

Expiry is derived as follows:

```text
maxExpiresAt = created_at + maxLifetime
expires_at   = min(now + ttl, maxExpiresAt)
renew_at     = min((updated_at ?? created_at) + renewInterval, maxExpiresAt)
```

### Cookies

| Property      | Type / allowed values         | Default           | Description                                                               |
| ------------- | ----------------------------- | ----------------- | ------------------------------------------------------------------------- |
| `sessionName` | Valid cookie name             | `"__ses"`         | Contains the opaque token. This is the only authenticating cookie.        |
| `cacheName`   | Valid cookie name             | `"__cac"`         | Contains the optional signed short cache.                                 |
| `renewName`   | Valid cookie name             | `"__ren"`         | Contains the untrusted `renew_at` Unix timestamp.                         |
| `domain`      | `string`                      | Browser host only | Optional cookie domain.                                                   |
| `path`        | String beginning with `/`     | `"/"`             | Cookie path.                                                              |
| `sameSite`    | `"Strict" \| "Lax" \| "None"` | `"Lax"`           | Browser SameSite policy.                                                  |
| `secure`      | `boolean`                     | `true`            | Requires HTTPS when enabled. Set `false` only for local HTTP development. |

All three cookies are always `HttpOnly` and expire with their respective server-side purpose. Their names must be unique.

Cookie prefix rules are enforced:

- `__Host-` requires `secure: true`, `path: "/"`, and no `domain`.
- `__Secure-` requires `secure: true`.
- `SameSite=None` requires `secure: true`.

SameSite values:

| Enum       | Behavior                                                                     |
| ---------- | ---------------------------------------------------------------------------- |
| `"Strict"` | Sends cookies only in same-site contexts.                                    |
| `"Lax"`    | Sends cookies in same-site contexts and eligible top-level safe navigations. |
| `"None"`   | Allows cross-site cookie use and requires `secure: true`.                    |

The resolved names are available through:

```ts
auth.cookie.sessionName; // "__ses"
auth.cookie.cacheName; // "__cac"
auth.cookie.renewName; // "__ren"
```

### Signed cache

| Property    | Type / allowed values               | Default  | Description                                               |
| ----------- | ----------------------------------- | -------- | --------------------------------------------------------- |
| `cache.ttl` | Integer `1` to `session.ttl`        | Disabled | Maximum cache lifetime in seconds.                        |
| `secret`    | String with at least 32 UTF-8 bytes | —        | Signs the cache with HMAC-SHA-256. Required with `cache`. |

The cache:

- is cryptographically bound to the opaque token and client identity;
- is accepted only for `GET` and `HEAD`;
- never extends the authoritative database session;
- is bypassed for unsafe methods, renewal, logout, WebSockets, and core calls;
- falls back to normal database authentication when absent, expired, malformed, or altered.

The cache is signed but not encrypted. Do not place passwords, password hashes, raw session tokens, or application secrets in account/session data.

<details>
<summary>Internal compact cache payload</summary>

```ts
{
    exp: cacheExpiresAt,
    acc: {
        id,
        email,
        name,
        role,
        status,
        timezone,
        user: { id, role, status },
    },
    ses: {
        id,
        client: { ip, agent, platform },
        created_at,
        exp: expiresAt,
        ren: renewAt,
    },
}
```

`session.account_id` is reconstructed from `acc.id` after signature validation.

</details>

### Prisma adapter

The default adapter requires the Prisma models `sessions` and `account`. The session model must expose an `account` relation. The default account model must contain string `id`, `email`, and `password_hash` fields. Custom account models require string `id` and `email`; their password column remains application-defined because the session adapter never reads it. Only `account.id` and `account.email` enter the payload by default.

#### Default models

```ts
const db = createPrismaAdapter({
    client: prisma,
});
```

The resolved account payload is:

```ts
{
    email: "owner@example.com",
    id: "account-id",
}
```

#### Selected fields and access rules

`select` defines the public account payload. `access` defines the values required to authenticate:

```ts
const db = createPrismaAdapter({
    client: prisma,
    models: {
        account: {
            select: ["id", "email", "name", "role"],
            access: {
                role: ["OWNER", "ADMIN"],
                status: ["ACTIVE"],
            },
        },
    },
});
```

`status` is selected internally for validation but is not exposed because it is absent from `select`.

#### Custom models and nested relations

Use `name` when the Prisma delegate differs from the default. Nested relation keys must match the relation fields on the parent model:

```ts
const db = createPrismaAdapter({
    client: prisma,
    models: {
        sessions: {
            name: "admin_sessions",
        },
        account: {
            name: "user_accounts",
            select: ["id", "email", "name", "role", "status", "timezone"],
            access: {
                role: ["OWNER", "ADMIN"],
                status: ["ACTIVE"],
            },
            relations: {
                user: {
                    name: "users",
                    select: ["id", "role", "status"],
                    access: {
                        status: ["ACTIVE"],
                    },
                },
            },
        },
    },
});
```

This configuration uses `prisma.admin_sessions`, `prisma.user_accounts`, and `prisma.users`. The root relation on `admin_sessions` must still be named `account`.

When a relation name differs from its target model, the object key identifies the relation and `name` identifies the delegate:

```ts
relations: {
    owner: {
        name: "users",
        select: ["id", "email", "status"],
        access: {
            status: ["ACTIVE"],
        },
    },
}
```

This loads the `account.owner` relation using the `prisma.users` model metadata.

| Property                              | Type / allowed values                     | Required | Default              | Description                                                                 |
| ------------------------------------- | ----------------------------------------- | :------: | -------------------- | --------------------------------------------------------------------------- |
| `client`                              | Generated Prisma client                   |    ✅    | —                    | Prisma client containing every configured model.                            |
| `models.sessions.name`                | Compatible session delegate name          |    ❌    | `"sessions"`         | Overrides the Prisma model used to persist sessions.                         |
| `models.account.name`                 | Account delegate with string `id`, `email` |    ❌    | `"account"`          | Identifies a custom account model. Its password column may use any name.      |
| `models.account.select`               | Unique scalar field array                 |    ❌    | `["id", "email"]`    | Fields exposed in `account` and the signed cache. `id` is always included.   |
| `models.account.access`               | Scalar equality or allowed-value arrays   |    ❌    | `{}`                 | Conditions required for authentication.                                     |
| `models.account.relations`            | Relation configuration object             |    ❌    | `{}`                 | Additional required to-one relations loaded inside `account`.               |
| `models.account.relations[key].name`  | Compatible related-model delegate name    |    ❌    | Relation key         | Identifies the related model and types its `select` and `access`.            |
| `models.account.relations[key].select`| Unique scalar field array                 |    ❌    | `["id"]`             | Fields exposed under that relation. `id` is always included.                 |
| `models.account.relations[key].access`| Scalar equality or allowed-value arrays   |    ❌    | `{}`                 | Conditions required on the related record.                                  |

The root Prisma relation on the session model is always named `account`. Keys inside `relations` are the actual Prisma relation field names. `name` identifies the target Prisma model/delegate; it does not rename a relation or a physical SQL table.

`select` accepts only JSON-safe scalar fields. It controls the public account payload and receives autocomplete from the generated Prisma client. Treat it as an explicit allowlist: never select passwords, password hashes, tokens, or other secrets because the cache is signed, not encrypted. Fields used only by `access` are selected for validation and removed before the account is exposed or cached.

Each `access` condition is either an exact scalar value or an array of accepted values:

```ts
access: {
    active: true,
    role: ["OWNER", "ADMIN"],
}
```

All configured conditions and nested relations must match. Omitting `access` applies no application-specific account restriction.

### Next.js adapter

```ts
import { createNextAuth } from "@gauts/auth/next";

export const nextAuth = createNextAuth({
    renewUrl: `${process.env.NEXT_PRIVATE_API_URL}/auth/renew`,
});
```

| Property             | Type / allowed values            | Required | Default   | Description                                   |
| -------------------- | -------------------------------- | :------: | --------- | --------------------------------------------- |
| `renewUrl`           | Absolute `http:` or `https:` URL |    ✅    | —         | Trusted private API renewal endpoint.         |
| `cookie.sessionName` | Valid cookie name                |    ❌    | `"__ses"` | Session cookie read and forwarded to the API. |
| `cookie.renewName`   | Valid cookie name                |    ❌    | `"__ren"` | Renewal scheduling cookie read by Next.js.    |

## Session flow

### Login

```text
credentials accepted
    -> generate 256-bit opaque token
    -> store SHA-256 token hash in DB
    -> load selected current account data and configured relations
    -> apply configured access rules
    -> write __ses
    -> write __ren
    -> optionally write __cac
```

Only the raw browser token authenticates. The database stores only its SHA-256 hash.

### Protected `GET` or `HEAD`

```text
session token
    -> valid signed cache?
        -> yes: expose cached account and session
        -> no: validate through DB and create a fresh cache
```

### Unsafe request

```text
session token
    -> SHA-256 hash
    -> indexed DB lookup
    -> validate expiry, revocation, account access, configured relations, and client
    -> clear short cache
    -> continue
```

### Renewal

```text
Next reads __ren
    -> future timestamp: no API request
    -> missing, invalid, or due: POST /auth/renew
    -> API validates through DB
    -> update expires_at when renewal is due
    -> Set-Cookie with the same token, new renewAt, and fresh cache
```

`auth.session.resolve()` is always DB-backed and read-only. Only explicit renewal updates database expiry.

## Prisma schema

The default Prisma adapter resolves:

```text
sessions -> account
```

The following is a complete MySQL/MariaDB example for email/password authentication. The account model requires `id`, `email`, and `password_hash`; the password hash is used only by the application's login query and never enters the session payload.

```prisma
model account {
  id            String @id @default(uuid()) @db.VarChar(255)
  email         String @unique @db.VarChar(255)
  password_hash String @db.VarChar(255)

  sessions sessions[]
}

model sessions {
  id          String    @id @default(uuid()) @db.VarChar(255)
  account_id  String    @db.VarChar(255)
  token_hash  String    @unique @db.VarChar(64)
  ip          String?   @db.VarChar(45)
  platform    String?   @db.VarChar(255)
  agent       String?   @db.Text
  expires_at  DateTime  @db.Timestamp(0)
  revoked_at  DateTime? @db.Timestamp(0)
  created_at  DateTime  @default(now()) @db.Timestamp(0)
  updated_at  DateTime? @db.Timestamp(0)

  account account @relation(fields: [account_id], references: [id], onDelete: Cascade)

  @@index([account_id])
  @@index([expires_at])
  @@index([revoked_at])
}
```

Required fields and relation names:

| Path               | Required fields                                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------- |
| Session model      | `id`, `account_id`, `token_hash`, `ip`, `platform`, `agent`, `expires_at`, `revoked_at`, `created_at`, `updated_at` |
| `account` relation | String `id`, `email`, and `password_hash`                                                                           |

The session relation must be named `account`. Additional account fields and nested relations are selected through `models.account`. Application models may add fields, indexes, defaults, mappings, and relations. Access fields may use Prisma enums, strings, booleans, numbers, or null.

Keep `agent` large enough for the complete User-Agent. Use provider-compatible native annotations when the database is not MySQL/MariaDB.

`models.sessions.name` and every model `name` are Prisma client delegate names. Physical SQL table names remain an application concern and can use Prisma `@@map` without changing the adapter configuration.

Create and run migrations through the application's Prisma workflow. The package never manages migrations.

## Hono adapter

### Request values

`auth.requireSession` sets fully typed values on the Hono context:

```ts
const account = c.get("account");
const session = c.get("session");
```

```ts
type AuthAccount = {
    id: string;
};

type Session = {
    account_id: string;
    client: {
        agent: string | null;
        ip: string | null;
        platform: string | null;
    };
    created_at: Date;
    expires_at: Date;
    id: string;
    renew_at: Date;
};
```

The Prisma adapter refines `AuthAccount` with the exact fields and nested relations declared in `select`.

Only `account_id` is persisted in the session row. Current selected account data and configured relations are loaded through the database relation and never copied into the table.

### Methods

| Method                                        | Purpose                                                                    |
| --------------------------------------------- | -------------------------------------------------------------------------- |
| `auth.createSession({ account_id, context })` | Creates the DB session and writes the browser cookies.                     |
| `auth.resolveSession(context)`                | Resolves a request and returns the selected account and session.           |
| `auth.renewSession(context)`                  | Performs DB validation, renews when due, and writes authoritative cookies. |
| `auth.revokeSession(context)`                 | Revokes the current DB session and clears cookies.                         |
| `auth.clearSession(context)`                  | Clears browser cookies without revoking the DB session.                    |
| `auth.getToken(context)`                      | Returns the validated opaque token from the request cookie.                |
| `auth.requireSession`                         | Hono middleware that authenticates and populates the context.              |

`requireSession` authenticates only. Application-specific route permissions remain the application's responsibility.

### Core and adapter composition

`createHonoAuth()` is the normal entry point. Use separate composition only when the same core instance is required outside Hono:

```ts
import { createAuth } from "@gauts/auth";
import { createHonoAdapter } from "@gauts/auth/hono";

const core = createAuth({ db });
const hono = createHonoAdapter({
    auth: core,
});
```

## Next.js adapter

The Next.js adapter schedules renewal; it does not authenticate pages or API requests.

```ts
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

export const proxy = async (request: NextRequest) => {
    const response = NextResponse.next();
    const renewal = await nextAuth.renew({ request, response });

    if (renewal.status === 401) {
        return NextResponse.redirect(new URL("/auth/login", request.url));
    }

    if (renewal.status !== null && renewal.status >= 500) {
        return NextResponse.redirect(new URL("/maintenance", request.url));
    }

    return renewal.response;
};
```

Result values:

| `attempted` |    `status` | Meaning                                                         |
| :---------: | ----------: | --------------------------------------------------------------- |
|   `false`   |      `null` | Session token exists and renewal is not due.                    |
|   `false`   |       `401` | Session token is missing or malformed; no API request occurred. |
|   `true`    | HTTP status | The renewal endpoint was called and returned this status.       |

The adapter copies every returned `Set-Cookie` header to the browser response. It forwards only the session cookie and controlled client/origin headers required by the private API. Other cookies, authorization headers, and arbitrary headers are not forwarded.

`buildForwardHeaders()` and `FORWARD_HEADERS` are exported from `@gauts/auth/next` for application fetchers that need the same controlled forwarding rules:

```ts
import { buildForwardHeaders } from "@gauts/auth/next";

const headers = buildForwardHeaders({
    headers: incoming,
    extra: ["cookie", "authorization"],
});
```

Safe client and proxy metadata is copied by default. Credentials such as `cookie` and `authorization` are excluded unless explicitly listed in `extra`.

When `Origin` is absent and trusted `X-Forwarded-Proto` and `X-Forwarded-Host` headers exist, the adapter reconstructs the public origin from them. It never derives a public origin from the internal Next.js request URL. The deployment proxy must overwrite forwarded headers received from untrusted clients.

Apply renewal only to protected routes or skip public routes before calling `nextAuth.renew()`.

## Core session API

```ts
await auth.session.create({ account_id, client });
await auth.session.resolve({ client, token });
await auth.session.renew({ client, token });
await auth.session.list(account_id);
await auth.session.revoke({ account_id, session_id });
await auth.session.revokeToken(token);
await auth.session.revokeAccount(account_id);
```

| Method          | Behavior                                               |
| --------------- | ------------------------------------------------------ |
| `create`        | Creates a session and returns the raw token once.      |
| `resolve`       | Performs read-only DB authentication.                  |
| `renew`         | Validates through DB and updates expiry only when due. |
| `list`          | Returns active sessions without token hashes.          |
| `revoke`        | Revokes one session belonging to an account.           |
| `revokeToken`   | Revokes the session matching a raw token.              |
| `revokeAccount` | Revokes every active session for an account.           |

The package does not limit session count or delete historical rows. Retention and cleanup belong to the application.

## Custom database adapter

The core depends on `DbAdapter`, not Prisma:

```ts
import type { DbAdapter } from "@gauts/auth";

const db = {
    create: async (session) => {},
    find: async ({ account_id, session_id }) => null,
    findActive: async ({ account_id, now }) => [],
    findToken: async (token_hash) => null,
    revoke: async ({ revoked_at, session_ids }) => {},
    updateExpiry: async ({ expires_at, session_id, updated_at }) => {},
} satisfies DbAdapter;
```

`findToken` receives only the SHA-256 token hash. It must return the current selected account plus an `allowed` result. Raw tokens must never be persisted.

## Performance

The package contains no Redis or in-process cache.

Without the optional browser cache, each `requireSession` performs an indexed database lookup through `sessions.token_hash`.

With a valid cache, `GET` and `HEAD` skip the lookup until `cache.ttl` expires. Unsafe methods always use current database state.

The tradeoff is explicit: revocation and selected account or relation changes made elsewhere may remain visible to safe cached requests until the short TTL expires. A 60-second TTL limits this stale-read window to one minute. Disable cache when immediate read revocation is required.

## Errors

```ts
type AuthErrorCode =
    | "AUTH_CONFIG_INVALID"
    | "PASSWORD_INPUT_INVALID"
    | "SESSION_CLIENT_MISMATCH"
    | "SESSION_DATA_INVALID"
    | "SESSION_INVALID"
    | "SESSION_NOT_FOUND"
    | "DB_UNAVAILABLE";
```

Use `isAuthError(error)` before reading `error.code`.

| Code                      | Suggested HTTP status | Meaning                                                           |
| ------------------------- | --------------------: | ----------------------------------------------------------------- |
| `AUTH_CONFIG_INVALID`     |                 `500` | Invalid startup configuration.                                    |
| `PASSWORD_INPUT_INVALID`  |                 `400` | Password input violates configured limits.                        |
| `SESSION_CLIENT_MISMATCH` |                 `403` | A configured client field does not match; the session is revoked. |
| `SESSION_DATA_INVALID`    |                 `400` | Invalid session or renewal data.                                  |
| `SESSION_INVALID`         |                 `401` | Missing, expired, revoked, or unknown session.                    |
| `SESSION_NOT_FOUND`       |                 `404` | Requested session does not exist for the account.                 |
| `DB_UNAVAILABLE`          |                 `503` | Database operation failed. Authentication fails closed.           |

The package throws typed errors but does not choose application HTTP responses.

## Security responsibilities

The package provides authentication primitives, not a complete application security policy. Applications remain responsible for:

- TLS and trusted-proxy configuration;
- CSRF, CORS, host, and origin validation;
- login and renewal rate limiting;
- equivalent password verification work for unknown accounts;
- route roles and authorization;
- re-authentication for sensitive operations;
- database migrations and session cleanup;
- never logging passwords, raw tokens, cookie headers, or password hashes.

Exact IP, User-Agent, and platform validation are defense in depth. They do not prevent every stolen-cookie replay scenario.
