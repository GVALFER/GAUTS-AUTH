# `@gauts/auth`

[![Unpacked Size](https://img.shields.io/npm/unpacked-size/%40gauts%2Fauth)](https://www.npmjs.com/package/@gauts/auth)

Database-backed password authentication, opaque browser sessions, and optional social authentication for Node.js applications.

`@gauts/auth` provides password hashing, session lifecycle, secure cookies, database validation, optional short caching, Prisma or Drizzle persistence, Hono/Express/Fastify integration, and Google/GitHub/X OAuth. The application keeps control of credential lookup, business-specific registration data, authorization, responses, and UI.

## Features

| Capability                     | Support | Default             |
| ------------------------------ | :-----: | ------------------- |
| Argon2id password hashing      |   ✅    | Enabled             |
| bcrypt password hashing        |   ✅    | Opt-in              |
| Opaque server-side sessions    |   ✅    | Enabled             |
| Database-backed validation     |   ✅    | Enabled             |
| Automatic sliding renewal      |   ✅    | Every 24 hours      |
| Absolute session lifetime      |   ✅    | 30 days             |
| Signed browser cache           |   ✅    | Disabled            |
| Full User-Agent validation     |   ✅    | Enabled             |
| IP validation                  |   ✅    | Disabled            |
| Platform validation            |   ✅    | Disabled            |
| Hono adapter                   |   ✅    | Available           |
| Express adapter                |   ✅    | Available           |
| Fastify adapter                |   ✅    | Available           |
| Prisma adapter                 |   ✅    | Available           |
| Drizzle MySQL/MariaDB adapter  |   ✅    | Available           |
| Next.js renewal adapter        |   ✅    | Available           |
| Google social authentication   |   ✅    | Opt-in              |
| GitHub social authentication   |   ✅    | Opt-in              |
| X social authentication        |   ✅    | Opt-in              |
| Social account registration    |   ✅    | Disabled            |
| Session listing and revocation |   ✅    | Available           |
| Token rotation                 |   ❌    | Stable opaque token |
| JWT sessions                   |   ❌    | Not used            |
| Redis requirement              |   ❌    | Not required        |
| OTP and transactional email    |   ❌    | Application-owned   |
| Route roles and permissions    |   ❌    | Application-owned   |

“Session renewal” extends the existing session expiry when authenticated activity continues. Framework middleware performs it inline when due. It is not a refresh-token flow and does not rotate the opaque browser token.

## Quick start

The application defines its credential login, logout, protected endpoints, and the optional explicit renewal endpoint used by server-rendered frontends. Optional addons are configured separately after this base setup.

### 1. Install the package

Install the package and the framework used by the API. Only one framework adapter is required:

```bash
npm install @gauts/auth hono
npm install @gauts/auth express
npm install @gauts/auth fastify
```

When the Next.js frontend is a separate project, run this command inside the frontend project:

```bash
npm install @gauts/auth next
```

Run only the matching API command. `hono`, `express`, `fastify`, and `next` only need to be installed when the corresponding project does not already provide them.

Express TypeScript projects also install its type declarations:

```bash
npm install --save-dev @types/express
```

### 2. Choose the database adapter and schema

One database adapter is required. Prisma and Drizzle are equivalent persistence choices; install and configure only one.

| Adapter | Database support           | Setup                                          |
| ------- | -------------------------- | ---------------------------------------------- |
| Prisma  | Prisma-supported databases | [Use Prisma](#option-a--prisma)                |
| Drizzle | MySQL and MariaDB          | [Use Drizzle](#option-b--drizzle-mysqlmariadb) |

Both schemas use the same relationship tree:

```text
users
└── user_accounts
    └── account_sessions
```

Social authentication is an optional addon with separate schema instructions later in this README.

#### Option A — Prisma

Install Prisma inside the API project:

```bash
npm install @prisma/client
npm install --save-dev prisma
```

[View and copy the Prisma schema](./src/adapters/prisma/schema.prisma) into the application's Prisma schema.

Create the migration through the application's Prisma workflow, then regenerate its client:

```bash
npx prisma migrate dev --name add_auth
npx prisma generate
```

Create the database adapter:

```ts
import { createPrismaAdapter } from "@gauts/auth/prisma";

import { prisma } from "./db.js";

export const authDb = createPrismaAdapter({
    client: prisma,
});
```

#### Option B — Drizzle MySQL/MariaDB

Install Drizzle and the application's MySQL driver inside the API project:

```bash
npm install drizzle-orm mysql2
npm install --save-dev drizzle-kit
```

[View and copy the Drizzle MySQL/MariaDB schema](./src/adapters/drizzle/schema.ts) into the application.

Create and apply the migration through the application's Drizzle workflow, then create the database adapter:

```ts
import { createDrizzleAdapter } from "@gauts/auth/drizzle";

import { db } from "./db.js";
import { accountSessions, userAccounts, users } from "./schema.js";

export const authDb = createDrizzleAdapter({
    client: db,
    models: {
        accounts: { table: userAccounts },
        sessions: { table: accountSessions },
        users: { table: users },
    },
});
```

### 3. Create the auth instance and routes

This Hono example is identical for Prisma and Drizzle:

Generate one high-entropy API secret and keep it server-side:

```bash
openssl rand -base64 48
```

Store the result as `AUTH_SECRET` in the API environment. Do not expose it through a public frontend variable.

```ts
import { createHonoAuth } from "@gauts/auth/hono";

import { authDb } from "./authDb.js";

export const auth = createHonoAuth({
    db: authDb,
    secret: process.env.AUTH_SECRET!,
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
cookies        __ses, __ctx
```

Mount the application-owned login routes and the package middleware:

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
        storedHash: account?.password_hash,
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
        user: c.get("user"),
    });
});
```

The equivalent framework examples are available here:

| Framework | Simple example                                                  | Advanced example                                                    |
| --------- | --------------------------------------------------------------- | ------------------------------------------------------------------- |
| Hono      | [`examples/hono/simple`](./examples/hono/simple/index.ts)       | [`examples/hono/advanced`](./examples/hono/advanced/index.ts)       |
| Express   | [`examples/express/simple`](./examples/express/simple/index.ts) | [`examples/express/advanced`](./examples/express/advanced/index.ts) |
| Fastify   | [`examples/fastify/simple`](./examples/fastify/simple/index.ts) | [`examples/fastify/advanced`](./examples/fastify/advanced/index.ts) |

Express exposes authenticated values through `response.locals`. Fastify exposes them through request decorators and requires one `auth.decorate(app)` call before routes are registered. All routes remain application-owned.

When `storedHash` is missing, the package performs password work with the configured algorithm and always returns `false`. Applications do not need a dummy hash. Keep the response identical for unknown accounts and incorrect passwords.

### 4. Connect the Next.js frontend

Create the renewal adapter with the API's private URL:

```ts
import { createNextAuth } from "@gauts/auth/next";

export const nextAuth = createNextAuth({
    renewUrl: `${process.env.NEXT_PRIVATE_API_URL}/auth/renew`,
});
```

Call it from the Next.js middleware (proxy.ts) on protected routes:

```ts
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { nextAuth } from "./lib/auth.js";

export const proxy = async (request: NextRequest) => {
    const response = NextResponse.next();

    const renewal = await nextAuth.renew({
        request,
        response,
        unauthorizedUrl: "/auth/login",
    });

    if (renewal.status !== null && renewal.status >= 500) {
        return NextResponse.redirect(new URL("/maintenance", request.url));
    }

    return renewal.response;
};
```

The application owns the redirect URL. When `unauthorizedUrl` is provided, the adapter creates the redirect and copies every API `Set-Cookie` header to it before returning the final response. The frontend does not receive `AUTH_SECRET`; it reads only untrusted scheduling dates from `__ctx`. The API verifies the signature and remains responsible for session validation.

## Requirements and package entry points

- Node.js 22 or newer.
- A database adapter.
- Drizzle ORM 0.45.2 or newer when using the Drizzle adapter.
- Hono 4 when using the Hono adapter.
- Express 5 when using the Express adapter.
- Fastify 5 when using the Fastify adapter.
- Next.js 15 or newer when using the Next.js adapter.

`drizzle-orm`, `hono`, `express`, `fastify`, and `next` are optional peer dependencies. Installing or importing one adapter does not load the others. The Prisma adapter receives the application's generated Prisma client and does not import Prisma at runtime. The Drizzle adapter imports `drizzle-orm`, while the application owns the MySQL/MariaDB driver.

| Import                  | Purpose                                                   |
| ----------------------- | --------------------------------------------------------- |
| `@gauts/auth`           | Password service, session core, errors, and public types. |
| `@gauts/auth/drizzle`   | Drizzle database adapter for MySQL and MariaDB.           |
| `@gauts/auth/prisma`    | Prisma database adapter.                                  |
| `@gauts/auth/hono`      | Hono cookies, methods, and middleware.                    |
| `@gauts/auth/express`   | Express cookies, methods, and middleware.                 |
| `@gauts/auth/fastify`   | Fastify cookies, methods, decorators, and hooks.          |
| `@gauts/auth/next`      | Next.js renewal scheduling and `Set-Cookie` forwarding.   |
| `@gauts/auth/headers`   | Browser-safe controlled header forwarding helpers.        |
| `@gauts/auth/providers` | Google, GitHub, and X OAuth providers.                    |

## Configuration reference

### `createHonoAuth()`

| Property   | Type / allowed values |         Required         | Default           | Description                                                                                         |
| ---------- | --------------------- | :----------------------: | ----------------- | --------------------------------------------------------------------------------------------------- |
| `db`       | `DbAdapter`           |            ✅            | —                 | Authoritative session persistence and account loading.                                              |
| `getIp`    | `HonoGetIp`           | Only with IP validation  | Omitted           | Returns the client IP from a source trusted by the application. May be synchronous or asynchronous. |
| `password` | `PasswordConfig`      |            ❌            | Argon2id defaults | Password hashing and verification configuration.                                                    |
| `session`  | `SessionConfig`       |            ❌            | Session defaults  | Expiry, renewal, and client validation configuration.                                               |
| `cookie`   | `HonoCookieConfig`    |            ❌            | Cookie defaults   | Names, domain, path, SameSite, and Secure settings.                                                 |
| `cache`    | `{ ttl: number }`     |            ❌            | Disabled          | Enables the short signed browser cache.                                                             |
| `secret`   | `string`              |            ✅            | —                 | HMAC secret for signed session context and optional social data. Minimum 32 UTF-8 bytes.             |
| `social`   | `SocialConfig`        |            ❌            | Disabled          | Enables configured social providers, redirects, and optional registration.                          |

```ts
type HonoGetIp = (c: Context) => Promise<string | null | undefined> | string | null | undefined;
```

When `getIp` is omitted, the adapter stores `ip: null` and does not read IP headers automatically. Configuring `session.validation` with `"ip"` requires `getIp` and fails during initialization when it is missing.

`createExpressAuth()` and `createFastifyAuth()` accept the same configuration. Their `getIp` callback receives the native Express or Fastify request instead of a Hono context.

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

| Property      | Type / allowed values         | Default           | Description                                                                                   |
| ------------- | ----------------------------- | ----------------- | --------------------------------------------------------------------------------------------- |
| `sessionName` | Valid cookie name             | `"__ses"`         | Contains the opaque token. This is the only authenticating cookie.                            |
| `contextName` | Valid cookie name             | `"__ctx"`         | Contains signed renewal scheduling and the optional short cache. It never authenticates alone. |
| `domain`      | `string`                      | Browser host only | Optional cookie domain.                                                                       |
| `path`        | String beginning with `/`     | `"/"`             | Cookie path.                                                                                  |
| `sameSite`    | `"Strict" \| "Lax" \| "None"` | `"Lax"`           | Browser SameSite policy.                                                                      |
| `secure`      | `boolean`                     | `true`            | Requires HTTPS when enabled. Set `false` only for local HTTP development.                     |

Both cookies are always `HttpOnly`, expire with the authoritative session, and must use unique names. Deleting `__ctx` does not log the user out: the next authenticated API request validates `__ses` through the database and rebuilds the signed context. Deleting `__ses` ends browser authentication because `__ctx` is never accepted on its own.

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
auth.cookie.contextName; // "__ctx"
```

### Signed session context

| Property    | Type / allowed values               | Default  | Description                                                        |
| ----------- | ----------------------------------- | -------- | ------------------------------------------------------------------ |
| `secret`    | String with at least 32 UTF-8 bytes | Required | Signs `__ctx` with HMAC-SHA-256 and binds it to the opaque token.  |
| `cache.ttl` | Integer `1` to `session.ttl`        | Disabled | Enables cached account/session data for at most this many seconds. |

The signed context always contains the session expiry and next renewal time. When caching is configured, it may also contain the selected account and session data. The context:

- is cryptographically bound to `__ses` and cannot authenticate without it;
- is verified by the API before any cached data is trusted;
- exposes untrusted `renew` and `exp` scheduling values to the Next.js adapter without exposing `AUTH_SECRET`;
- uses cached data only for `GET` and `HEAD`;
- never extends the authoritative database session by itself;
- bypasses cached data for unsafe methods, renewal, logout, WebSockets, and core calls;
- triggers normal database authentication and a fresh signed context when absent, expired, malformed, altered, or bound to another token.

The context is signed but not encrypted. Do not place passwords, password hashes, raw session tokens, or application secrets in selected account/session data.

<details>
<summary>Internal signed context payload</summary>

```ts
{
    cache: {
        data: {
            account,
            session: {
                client,
                created,
                id,
            },
        },
        exp: cacheExpiresAt,
    } | null,
    exp: sessionExpiresAt,
    renew: renewAt,
}
```

The payload is encoded as `base64url(payload).signature`. The Next.js adapter may decode `exp` and `renew` only as scheduling hints. The API verifies the signature against the current opaque token before using any value. `session.account_id` is reconstructed from `account.id` after verification.

</details>

### Prisma adapter

The Prisma adapter uses one fixed, predictable session relationship tree:

```text
users
└── user_accounts
    └── account_sessions
```

[View and copy the required Prisma schema](./src/adapters/prisma/schema.prisma).

The required default delegate names are `prisma.users`, `prisma.user_accounts`, and `prisma.account_sessions`. The fixed Prisma relation fields are:

- `user_accounts.user`;
- `account_sessions.account`;

There is no relation mapping configuration. Applications may rename delegates with `table`, add payload fields with `select`, and define access conditions with `access`.

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
    user: {
        id: "user-id",
        name: "Company name",
    },
}
```

#### Selected fields and access rules

`select` defines the public account payload. `access` defines the values required to authenticate:

```ts
const db = createPrismaAdapter({
    client: prisma,
    models: {
        accounts: {
            select: ["name", "role", "status", "timezone"],
            access: {
                role: ["OWNER", "ADMIN"],
                status: ["ACTIVE"],
            },
        },
        users: {
            select: ["role", "status"],
            access: {
                status: ["ACTIVE", "PENDING"],
            },
        },
    },
});
```

Fields used by `access` are selected internally. They enter the returned/cached payload only when they are also present in `select`.

#### Custom delegate names

Use `table` only when a Prisma delegate differs from the default:

```ts
const db = createPrismaAdapter({
    client: prisma,
    models: {
        accounts: {
            table: "admin_accounts",
            select: ["name", "role", "status"],
        },
        sessions: {
            table: "admin_sessions",
        },
        users: {
            table: "admin_users",
            select: ["role", "status"],
        },
    },
});
```

| Property                 | Type / allowed values                   | Required | Default              | Description                                                |
| ------------------------ | --------------------------------------- | :------: | -------------------- | ---------------------------------------------------------- |
| `client`                 | Generated Prisma client                 |    ✅    | —                    | Prisma client containing the three required auth models.   |
| `models.users.table`     | Compatible user delegate name           |    ❌    | `"users"`            | Overrides the user delegate.                               |
| `models.users.select`    | Unique scalar field array               |    ❌    | `[]`                 | Adds payload fields; `id` and `name` are always included.  |
| `models.users.access`    | Scalar equality or allowed-value arrays |    ❌    | `{}`                 | Conditions required on the owning user/entity.             |
| `models.accounts.table`  | Compatible account delegate name        |    ❌    | `"user_accounts"`    | Overrides the account delegate.                            |
| `models.accounts.select` | Unique scalar field array               |    ❌    | `[]`                 | Adds payload fields; `id` and `email` are always included. |
| `models.accounts.access` | Scalar equality or allowed-value arrays |    ❌    | `{}`                 | Conditions required on the authenticating account.         |
| `models.sessions.table`  | Compatible session delegate name        |    ❌    | `"account_sessions"` | Overrides authoritative session persistence.               |

`select` accepts JSON-safe scalar fields and receives autocomplete from the generated Prisma client. `password`, `hash`, `password_hash`, and `passwordHash` are rejected by both TypeScript and runtime validation. Never select tokens or other secrets because the optional cache is signed, not encrypted.

Each `access` condition is either an exact scalar value or an array of accepted values:

```ts
access: {
    active: true,
    role: ["OWNER", "ADMIN"],
}
```

Every configured account and user condition must match. Omitting `access` applies no application-specific account restriction.

### Drizzle MySQL/MariaDB adapter

The Drizzle adapter supports MySQL and MariaDB. Install it inside the API project with the driver used by the application:

```bash
npm install @gauts/auth drizzle-orm mysql2
```

Unlike Prisma, Drizzle does not expose model delegates that can be discovered by name. Pass the application's table objects explicitly:

```ts
import { createDrizzleAdapter } from "@gauts/auth/drizzle";
import { createHonoAuth } from "@gauts/auth/hono";
import { db } from "./db.js";
import { accountSessions, userAccounts, users } from "./schema.js";

export const auth = createHonoAuth({
    db: createDrizzleAdapter({
        client: db,
        models: {
            accounts: { table: userAccounts },
            sessions: { table: accountSessions },
            users: { table: users },
        },
    }),
    secret: process.env.AUTH_SECRET!,
});
```

The minimum Drizzle schema uses the same relationship tree and canonical TypeScript field names as the Prisma adapter. [View and copy the required Drizzle MySQL/MariaDB schema](./src/adapters/drizzle/schema.ts).

The adapter queries these tables through explicit SQL joins, so Drizzle `relations()` declarations are not required. Physical SQL column names may use aliases, but the TypeScript keys shown above are part of the adapter contract. Date columns must use `{ mode: "date" }`.

`select` and `access` work exactly like the Prisma adapter and are inferred from the supplied table:

```ts
const database = createDrizzleAdapter({
    client: db,
    models: {
        accounts: {
            access: {
                role: ["OWNER", "ADMIN"],
                status: ["ACTIVE"],
            },
            select: ["role", "status", "timezone"],
            table: userAccounts,
        },
        sessions: { table: accountSessions },
        users: {
            access: { status: ["ACTIVE", "PENDING"] },
            select: ["status"],
            table: users,
        },
    },
});
```

| Property                 | Required | Description                                                            |
| ------------------------ | :------: | ---------------------------------------------------------------------- |
| `client`                 |    ✅    | Drizzle MySQL client created by the application.                       |
| `models.users.table`     |    ✅    | Table with `id` and `name` columns.                                    |
| `models.users.select`    |    ❌    | Additional public scalar fields; `id` and `name` are always included.  |
| `models.users.access`    |    ❌    | Required values for the owning user/entity.                            |
| `models.accounts.table`  |    ✅    | Table with `id`, `email`, and `user_id` columns.                       |
| `models.accounts.select` |    ❌    | Additional public scalar fields; `id` and `email` are always included. |
| `models.accounts.access` |    ❌    | Required values for the authenticating account.                        |
| `models.sessions.table`  |    ✅    | Table implementing the complete documented session column contract.    |
| `models.socials.table`   |    ❌    | Enables social persistence when the optional social table is supplied. |

Private password fields are rejected from `select` and `access` by both TypeScript and runtime validation. The adapter does not load or execute the Prisma adapter, and Prisma is not required in a Drizzle application.

### Next.js adapter

```ts
import { createNextAuth } from "@gauts/auth/next";

export const nextAuth = createNextAuth({
    renewUrl: `${process.env.NEXT_PRIVATE_API_URL}/auth/renew`,
});
```

| Property             | Type / allowed values            | Required | Default   | Description                                              |
| -------------------- | -------------------------------- | :------: | --------- | -------------------------------------------------------- |
| `renewUrl`           | Absolute `http:` or `https:` URL |    ✅    | —         | Trusted private API renewal endpoint.                    |
| `cookie.sessionName` | Valid cookie name                |    ❌    | `"__ses"` | Session cookie read and forwarded to the API.            |
| `cookie.contextName` | Valid cookie name                |    ❌    | `"__ctx"` | Signed context decoded only to schedule SSR renewal.     |

## Session flow

### Login

```text
credentials accepted
    -> generate 256-bit opaque token
    -> store SHA-256 token hash in DB
    -> load current account and owning user
    -> apply configured account/user access rules
    -> write __ses
    -> write signed __ctx with renewal schedule
    -> optionally include short cached data inside __ctx
```

Only the raw browser token authenticates. The database stores only its SHA-256 hash.

### Protected `GET` or `HEAD`

```text
__ses + __ctx
    -> renewal due?
        -> yes: validate and renew through DB, then write both cookies
        -> no: valid signed cache?
            -> yes: expose cached account and session
            -> no: validate through DB and write a fresh signed context
```

Renewal happens inside the same protected API request. A client-side fetch does not need a second renewal request.

### Unsafe request

```text
session token
    -> SHA-256 hash
    -> indexed DB lookup
    -> validate expiry, revocation, account/user access, and client
    -> write signed context without cached account data
    -> continue
```

### Next.js SSR renewal

```text
Next decodes renew and exp from __ctx as untrusted hints
    -> future timestamps: no renewal request
    -> missing, invalid, or due: POST /auth/renew
    -> API validates through DB
    -> update expires_at when renewal is due
    -> Set-Cookie with the same token and fresh signed context
```

`auth.session.resolve()` is always DB-backed and read-only. `auth.session.renew()` performs the authoritative renewal. Framework `requireSession` calls it automatically when the verified context says renewal is due; the explicit endpoint gives Next.js the same behavior during SSR navigation.

## Hono adapter

### Request values

`auth.requireSession` sets fully typed values on the Hono context:

```ts
const account = c.get("account");
const session = c.get("session");
const user = c.get("user");
```

```ts
type AuthAccount = {
    email: string;
    id: string;
    user: {
        id: string;
        name: string;
    };
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

The Prisma and Drizzle adapters refine `account` and `user` with the exact additional scalar fields declared in their respective `select` arrays.

Only `account_id` is copied into the session row. Current account/user data is loaded through the fixed database relations and is never duplicated in the session table.

### Login country metadata

An application may resolve a country once during login and persist it with the session:

```ts
await auth.createSession({
    account_id: account.id,
    context: c,
    country: userInfo.country?.code ?? null,
});
```

`country` is normalized to uppercase and is never used for authentication or client matching. It is not resolved by the package and does not trigger GeoIP work during normal requests. When supplied, the configured session model must provide a nullable `country` column. When omitted, the database adapter does not send the field.

### Methods

| Method                                                  | Purpose                                                                                           |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `auth.createSession({ account_id, context, country? })` | Creates the DB session and writes the browser cookies. `country` is optional login-time metadata. |
| `auth.resolveSession(context)`                          | Resolves a request, renews inline when due, and returns the selected account and session.          |
| `auth.renewSession(context)`                            | Performs DB validation, renews when due, and writes authoritative cookies.                        |
| `auth.revokeSession(context)`                           | Revokes the current DB session and clears cookies.                                                |
| `auth.clearSession(context)`                            | Clears browser cookies without revoking the DB session.                                           |
| `auth.getToken(context)`                                | Returns the validated opaque token from the request cookie.                                       |
| `auth.requireSession`                                   | Hono middleware that authenticates and populates the context.                                     |

`requireSession` authenticates only. Application-specific route permissions remain the application's responsibility.

## Express adapter

```ts
import { createExpressAuth, type ExpressAuthLocals } from "@gauts/auth/express";

const auth = createExpressAuth({ db, secret: process.env.AUTH_SECRET! });

app.get("/account", auth.requireSession, (_request, response) => {
    const { account, session, user } = response.locals as ExpressAuthLocals;
    response.json({ account, session, user });
});
```

| Method                                                            | Purpose                                              |
| ----------------------------------------------------------------- | ---------------------------------------------------- |
| `auth.createSession({ account_id, request, response, country? })` | Creates the DB session and writes cookies.           |
| `auth.resolveSession({ request, response })`                      | Resolves and automatically renews when due.           |
| `auth.renewSession({ request, response })`                        | Renews when due and writes authoritative cookies.    |
| `auth.revokeSession({ request, response })`                       | Revokes the current session and clears cookies.      |
| `auth.clearSession(response)`                                     | Clears cookies without revoking the DB session.      |
| `auth.getToken(request)`                                          | Reads and validates the opaque session token.        |
| `auth.requireSession`                                             | Express middleware that populates `response.locals`. |

Express 5 forwards rejected async middleware promises to the application's error handler. The adapter does not install routes or an error handler.

## Fastify adapter

Register the request decorators once before declaring routes:

```ts
import { createFastifyAuth } from "@gauts/auth/fastify";

const auth = createFastifyAuth({ db, secret: process.env.AUTH_SECRET! });

auth.decorate(app);

app.get("/account", { preHandler: auth.requireSession }, (request) => ({
    account: request.getDecorator("account"),
    session: request.getDecorator("session"),
    user: request.getDecorator("user"),
}));
```

| Method                                                         | Purpose                                                        |
| -------------------------------------------------------------- | -------------------------------------------------------------- |
| `auth.decorate(app)`                                           | Declares the native request decorators once at startup.        |
| `auth.createSession({ account_id, request, reply, country? })` | Creates the DB session and writes cookies.                     |
| `auth.resolveSession({ request, reply })`                      | Resolves and automatically renews when due.                     |
| `auth.renewSession({ request, reply })`                        | Renews when due and writes authoritative cookies.              |
| `auth.revokeSession({ request, reply })`                       | Revokes the current session and clears cookies.                |
| `auth.clearSession(reply)`                                     | Clears cookies without revoking the DB session.                |
| `auth.getToken(request)`                                       | Reads and validates the opaque session token.                  |
| `auth.requireSession`                                          | Fastify `preHandler` that populates native request decorators. |

When social authentication is enabled, `auth.decorate(app)` also declares `social`. The adapter does not register a Fastify plugin or create routes.

## Social authentication

Social authentication is an optional addon and remains disabled unless `social` is configured. Complete these steps only in applications that need Google, GitHub, or X authentication.

### 1. Add social persistence

#### Prisma

Add the social relation inside the existing `user_accounts` model in the API schema:

```prisma
model user_accounts {
  // Existing fields and relations...

  socials social_accounts[]
}
```

Then add the provider association model:

```prisma
model social_accounts {
  id          String   @id @default(uuid()) @db.VarChar(255)
  account_id  String   @db.VarChar(255)
  provider    String   @db.VarChar(32)
  provider_id String   @db.VarChar(255)
  created_at  DateTime @default(now()) @db.Timestamp(0)

  account user_accounts @relation(fields: [account_id], references: [id], onDelete: Cascade)

  @@unique([provider, provider_id])
  @@unique([account_id, provider])
  @@index([account_id])
}
```

Run the social migration from the API project, then regenerate its Prisma client:

```bash
npx prisma migrate dev --name add_social_auth
npx prisma generate
```

Without this model, `createPrismaAdapter()` remains a session-only adapter. Configuring `social` without social database capabilities fails during application startup.

The default Prisma delegate is `prisma.social_accounts` and its relation to `user_accounts` must be named `account`. Configure a different compatible delegate only when the application uses another model name:

```ts
const db = createPrismaAdapter({
    client: prisma,
    models: {
        socials: {
            table: "admin_social_accounts",
        },
    },
});
```

#### Drizzle MySQL/MariaDB

Add the provider table to the API schema:

```ts
export const socialAccounts = mysqlTable(
    "social_accounts",
    {
        account_id: varchar("account_id", { length: 255 })
            .notNull()
            .references(() => userAccounts.id, { onDelete: "cascade" }),
        created_at: timestamp("created_at", { mode: "date" }).defaultNow().notNull(),
        id: varchar("id", { length: 255 }).primaryKey(),
        provider: varchar("provider", { length: 32 }).notNull(),
        provider_id: varchar("provider_id", { length: 255 }).notNull(),
    },
    (table) => [
        index("social_accounts_account_id_idx").on(table.account_id),
        uniqueIndex("social_accounts_provider_provider_id_key").on(
            table.provider,
            table.provider_id,
        ),
        uniqueIndex("social_accounts_account_id_provider_key").on(table.account_id, table.provider),
    ],
);
```

Then supply it to the adapter:

```ts
const db = createDrizzleAdapter({
    client,
    models: {
        accounts: { table: userAccounts },
        sessions: { table: accountSessions },
        socials: { table: socialAccounts },
        users: { table: users },
    },
});
```

Omitting `models.socials` keeps the Drizzle adapter session-only. The adapter creates the owning user and account in one transaction during default social registration, so that path requires a Drizzle MySQL driver with transaction support. Additional required user/account columns must have database defaults; otherwise the application must provide `registration.createAccount`.

### 2. Configure the providers

Import only the providers used by the API:

```ts
import { createHonoAuth } from "@gauts/auth/hono";
import { createPrismaAdapter } from "@gauts/auth/prisma";
import { github, google, x } from "@gauts/auth/providers";

export const auth = createHonoAuth({
    db: createPrismaAdapter({ client: prisma }),
    secret: requiredEnv("AUTH_SECRET"),
    social: {
        providers: [
            google({
                callbackUrl: "https://app.example.com/proxy/auth/social/google/callback",
                clientId: requiredEnv("GOOGLE_CLIENT_ID"),
                clientSecret: requiredEnv("GOOGLE_CLIENT_SECRET"),
            }),
            github({
                callbackUrl: "https://app.example.com/proxy/auth/social/github/callback",
                clientId: requiredEnv("GITHUB_CLIENT_ID"),
                clientSecret: requiredEnv("GITHUB_CLIENT_SECRET"),
            }),
            x({
                callbackUrl: "https://app.example.com/proxy/auth/social/x/callback",
                clientId: requiredEnv("X_CLIENT_ID"),
                clientSecret: requiredEnv("X_CLIENT_SECRET"),
            }),
        ],
    },
});
```

Register every `callbackUrl` shown above in the corresponding provider dashboard.

### 3. Add the API route and frontend start

Declare one dynamic API route covering every configured provider. `social.handle` completes `start` and expected error responses itself, then continues to the application handler only after a successful callback.

```ts
app.get("/auth/social/:provider/:action", auth.social.handle, async (c) => {
    const social = c.get("social");

    await auth.createSession({
        account_id: social.account.id,
        context: c,
    });

    // Application notifications, audit logs, or other login work.

    return c.redirect(social.returnTo);
});
```

The frontend starts authentication with local navigation paths:

```text
GET /proxy/auth/social/google/start?intent=login&returnTo=/dashboard&errorTo=/auth/login
GET /proxy/auth/social/google/start?intent=register&returnTo=/dashboard&errorTo=/auth/login
GET /proxy/auth/social/google/callback
GET /proxy/auth/social/github/start?intent=login&returnTo=/dashboard&errorTo=/auth/login
GET /proxy/auth/social/github/callback
GET /proxy/auth/social/x/start?intent=login&returnTo=/dashboard&errorTo=/auth/login
GET /proxy/auth/social/x/callback
```

`intent` defaults to `login`. `returnTo` and `errorTo` are required local paths supplied by the frontend. `registerTo` is required only when registration continues in an application form. The package rejects external URLs, signs these paths into the OAuth transaction, and never trusts callback query parameters for navigation.

Only `start` and `callback` are accepted as actions. The public `/proxy` path in this example forwards to the Hono `/auth` path. Provider callback URLs must exactly match the public callback paths registered with each provider.

On an authenticated callback the middleware exposes:

```ts
const social = c.get("social");

social.account;
social.identity;
social.registered;
social.returnTo;
```

The native equivalents are:

```ts
// Express
const social = (response.locals as ExpressSocialLocals).social;

// Fastify
const social = request.getDecorator<SocialAuthenticated>("social");
```

See the advanced framework examples for complete social routes and custom registration.

The package does not create the application route, session, notifications, logs, or final success response. Those remain explicit in the route handler.

### Social configuration

| Property                     | Type / allowed values                | Required | Default   | Description                                                                |
| ---------------------------- | ------------------------------------ | :------: | --------- | -------------------------------------------------------------------------- |
| `social.providers`           | `SocialProvider[]`                   |    ✅    | —         | Configured Google, GitHub, or X providers.                                 |
| `social.cookieName`          | Valid cookie name                    |    ❌    | `"__soc"` | Signed temporary OAuth/registration transaction cookie.                    |
| `social.registration`        | `SocialRegistrationConfig`           |    ❌    | Disabled  | Enables default or application-specific social registration.               |
| `registration.createAccount` | Async callback returning `accountId` |    ❌    | Built-in  | Creates required business data when the default structure is insufficient. |

Provider configuration:

| Property       | Type                 | Required | Description                                             |
| -------------- | -------------------- | :------: | ------------------------------------------------------- |
| `clientId`     | Non-empty string     |    ✅    | Public OAuth client identifier.                         |
| `clientSecret` | Non-empty string     |    ✅    | Server-only OAuth client secret.                        |
| `callbackUrl`  | Absolute HTTP(S) URL |    ✅    | Exact public callback URL registered with the provider. |

The normalized verified identity is:

```ts
type SocialIdentity = {
    avatarUrl: string | null;
    email: string;
    name: string;
    provider: "google" | "github" | "x";
    providerId: string;
    username: string | null;
};
```

Provider access/refresh tokens and raw provider profiles are never exposed to application callbacks or persisted.

### Registration modes

Login only (default):

```ts
social: {
    providers: [googleProvider],
}
```

Default registration creates `users { id, name }`, `user_accounts { id, email, user_id }`, and the provider link. The application route creates the session after the middleware succeeds:

```ts
social: {
    providers: [googleProvider],
    registration: {},
}
```

This requires every additional application column on `users` and `user_accounts` to be nullable or have a database default.

For additional required form data, configure the account callback:

```ts
import type { SocialRegistrationInput } from "@gauts/auth";

type RegisterData = {
    companyNumber: string;
};

social: {
    providers: [googleProvider],
    registration: {
        createAccount: async ({ data, identity }: SocialRegistrationInput<RegisterData>) => {
            const account = await createApplicationAccount({
                companyNumber: data.companyNumber,
                email: identity.email,
                name: identity.name,
            });

            return { accountId: account.id };
        },
    },
}
```

The frontend includes `registerTo` when it starts OAuth:

```text
/proxy/auth/social/google/start?intent=register&returnTo=/dashboard&errorTo=/auth/login&registerTo=/auth/register/social
```

The application endpoints read the verified identity and complete registration:

```ts
app.get("/auth/register/social", (c) => {
    return c.json(auth.social.getRegistration(c));
});

app.post("/auth/register/social", async (c) => {
    const data = await c.req.json<{ companyNumber: string }>();

    const social = await auth.social.completeRegistration({
        context: c,
        data,
    });

    await auth.createSession({
        account_id: social.account.id,
        context: c,
    });

    return c.json({ registered: true, returnTo: social.returnTo });
});
```

`registerTo` requires `createAccount`; otherwise submitted application data would have no owner. `createAccount` must create the fixed `users`/`user_accounts` relation and return the created account ID. The package then creates `social_accounts`; the application explicitly creates the authenticated session.

### OAuth security

- Authorization Code flow with PKCE `S256` is used for every provider.
- State, PKCE verifier, intent, and local navigation paths live in the signed, HttpOnly `__soc` cookie for at most 10 minutes.
- The temporary cookie is cleared after success or expected failure.
- Only provider-verified email addresses are accepted.
- Provider IDs, not email addresses, are the stable social link identifiers.
- The current verified provider email must match the linked account email on every login.
- Frontend navigation accepts local paths only. The paths are validated before OAuth, signed into the transaction, and restored only after state validation.
- Social OAuth requires `SameSite=Lax` or `SameSite=None`; `Strict` fails during startup.

### Core and adapter composition

Use the entry point matching the application framework: `createHonoAuth()`, `createExpressAuth()`, or `createFastifyAuth()`. Use separate composition only when the same core instance is required outside the framework adapter:

```ts
import { createAuth } from "@gauts/auth";
import { createHonoAdapter } from "@gauts/auth/hono";

const core = createAuth({ db });
const hono = createHonoAdapter({
    auth: core,
    secret: process.env.AUTH_SECRET!,
});
```

## Next.js adapter

The Next.js adapter schedules SSR renewal; it does not authenticate pages or API requests. Normal API middleware independently verifies `__ctx` and renews inline, including requests made directly by client-side SWR or `fetch`.

```ts
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

export const proxy = async (request: NextRequest) => {
    const response = NextResponse.next();
    const renewal = await nextAuth.renew({
        request,
        response,
        unauthorizedUrl: "/auth/login",
    });

    if (renewal.status !== null && renewal.status >= 500) {
        return NextResponse.redirect(new URL("/maintenance", request.url));
    }

    return renewal.response;
};
```

Result values:

| `attempted` |    `status` | Meaning                                                         |
| :---------: | ----------: | --------------------------------------------------------------- |
|   `false`   |      `null` | Session token and context schedule exist; renewal is not due.   |
|   `false`   |       `401` | Session token is missing or malformed; no API request occurred. |
|   `true`    | HTTP status | The renewal endpoint was called and returned this status.       |

`unauthorizedUrl` is optional. When provided, the adapter redirects a `401` to that relative or absolute URL and transfers every returned `Set-Cookie` header to the redirect. Without it, the original response is returned with `status: 401` as before.

The adapter forwards only the session cookie and controlled client/origin headers required by the private API. `__ctx` is not forwarded because the API renewal endpoint always validates the opaque token through the database and returns a new signed context. Other cookies, authorization headers, and arbitrary headers are not forwarded.

`buildForwardHeaders()` and `FORWARD_HEADERS` are exported from the browser-safe `@gauts/auth/headers` entrypoint for application fetchers that need the same controlled forwarding rules:

```ts
import { buildForwardHeaders } from "@gauts/auth/headers";

const headers = buildForwardHeaders({
    headers: incoming,
    extra: ["cookie", "authorization"],
});
```

Safe client and proxy metadata is copied by default. Credentials such as `cookie` and `authorization` are excluded unless explicitly listed in `extra`.

When `Origin` is absent and trusted `X-Forwarded-Proto` and `X-Forwarded-Host` headers exist, the adapter reconstructs the public origin from them. It never derives a public origin from the internal Next.js request URL. The deployment proxy must overwrite forwarded headers received from untrusted clients.

Apply renewal only to protected routes or skip public routes before calling `nextAuth.renew()`. The adapter calls the API only when `__ctx` is missing, malformed, expired, or its decoded renewal time is due. Those decoded dates are untrusted scheduling hints; they never authenticate the request.

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

Custom adapters used with `social` must additionally implement `SocialDbAdapter`:

```ts
import type { SocialDbAdapter } from "@gauts/auth";

const socialDb = {
    createAccount: async ({ email, name }) => accountId,
    createSocial: async (record) => {},
    findAccount: async (account_id) => null,
    findEmail: async (email) => null,
    findSocial: async ({ provider, provider_id }) => null,
} satisfies SocialDbAdapter;
```

The Prisma and Drizzle adapters implement both `DbAdapter` and `SocialDbAdapter` when their optional social model is available.

## Performance

The package contains no Redis or in-process cache.

Without the optional browser cache, each `requireSession` performs an indexed database lookup through `account_sessions.token_hash`. When renewal is due, that same request also updates the authoritative expiry and returns refreshed cookies; there is no additional client-side API call.

With valid cached data inside `__ctx`, `GET` and `HEAD` skip the lookup until `cache.ttl` expires. Unsafe methods always use current database state. Renewal still validates through the database even if cached data is present.

The tradeoff is explicit: revocation and selected account or relation changes made elsewhere may remain visible to safe cached requests until the short TTL expires. A 60-second TTL limits this stale-read window to one minute. Disable cache when immediate read revocation is required.

## Errors

```ts
type AuthErrorCode =
    | "AUTH_CONFIG_INVALID"
    | "SOCIAL_ACCOUNT_INVALID"
    | "SOCIAL_ACCOUNT_NOT_FOUND"
    | "SOCIAL_EMAIL_INVALID"
    | "SOCIAL_EMAIL_MISMATCH"
    | "SOCIAL_PROVIDER_ERROR"
    | "SOCIAL_REGISTRATION_INVALID"
    | "SOCIAL_STATE_INVALID"
    | "PASSWORD_INPUT_INVALID"
    | "SESSION_CLIENT_MISMATCH"
    | "SESSION_DATA_INVALID"
    | "SESSION_INVALID"
    | "SESSION_NOT_FOUND"
    | "DB_UNAVAILABLE";
```

Use `isAuthError(error)` before reading `error.code`.

| Code                          | Suggested HTTP status | Meaning                                                           |
| ----------------------------- | --------------------: | ----------------------------------------------------------------- |
| `AUTH_CONFIG_INVALID`         |                 `500` | Invalid startup configuration.                                    |
| `SOCIAL_ACCOUNT_INVALID`      |                 `403` | Linked account or owning user failed configured access rules.     |
| `SOCIAL_ACCOUNT_NOT_FOUND`    |                 `401` | Provider identity is not linked and registration is unavailable.  |
| `SOCIAL_EMAIL_INVALID`        |                 `400` | Provider did not return a verified usable email address.          |
| `SOCIAL_EMAIL_MISMATCH`       |                 `409` | Verified provider email differs from the linked account email.    |
| `SOCIAL_PROVIDER_ERROR`       |                 `401` | Provider denied or failed the OAuth exchange.                     |
| `SOCIAL_REGISTRATION_INVALID` |                 `400` | Custom registration did not return a valid account ID.            |
| `SOCIAL_STATE_INVALID`        |                 `400` | OAuth/registration state is missing, altered, or expired.         |
| `PASSWORD_INPUT_INVALID`      |                 `400` | Password input violates configured limits.                        |
| `SESSION_CLIENT_MISMATCH`     |                 `403` | A configured client field does not match; the session is revoked. |
| `SESSION_DATA_INVALID`        |                 `400` | Invalid session or renewal data.                                  |
| `SESSION_INVALID`             |                 `401` | Missing, expired, revoked, or unknown session.                    |
| `SESSION_NOT_FOUND`           |                 `404` | Requested session does not exist for the account.                 |
| `DB_UNAVAILABLE`              |                 `503` | Database operation failed. Authentication fails closed.           |

The package throws typed errors but does not choose application HTTP responses.

## Security responsibilities

The package provides authentication primitives, not a complete application security policy. Applications remain responsible for:

- TLS and trusted-proxy configuration;
- CSRF, CORS, host, and origin validation;
- login and renewal rate limiting;
- route roles and authorization;
- re-authentication for sensitive operations;
- database migrations and session cleanup;
- never logging passwords, raw tokens, cookie headers, or password hashes.

Exact IP, User-Agent, and platform validation are defense in depth. They do not prevent every stolen-cookie replay scenario.
