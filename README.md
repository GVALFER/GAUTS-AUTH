# `@gauts/auth`

Database-backed password authentication, opaque browser sessions, and optional social authentication for Node.js applications.

`@gauts/auth` provides password hashing, session lifecycle, secure cookies, database validation, optional short caching, Prisma persistence, Hono integration, and Google/GitHub/X OAuth. The application keeps control of credential lookup, business-specific registration data, authorization, responses, and UI.

## Features

| Capability                     | Support | Default             |
| ------------------------------ | :-----: | ------------------- |
| Argon2id password hashing      |   ✅    | Enabled             |
| bcrypt password hashing        |   ✅    | Opt-in              |
| Opaque server-side sessions    |   ✅    | Enabled             |
| Database-backed validation     |   ✅    | Enabled             |
| Sliding session renewal        |   ✅    | Every 24 hours      |
| Absolute session lifetime      |   ✅    | 30 days             |
| Signed browser cache           |   ✅    | Disabled            |
| Full User-Agent validation     |   ✅    | Enabled             |
| IP validation                  |   ✅    | Disabled            |
| Platform validation            |   ✅    | Disabled            |
| Hono adapter                   |   ✅    | Available           |
| Prisma adapter                 |   ✅    | Available           |
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

“Session renewal” extends the existing session expiry when activity continues. It is not a refresh-token flow and does not rotate the opaque browser token.

## Quick start

The application defines its credential login, renewal, logout, protected endpoints, and social route paths. Optional social authentication exposes the Hono handler used inside the application-owned route.

### 1. Install the package

```bash
npm install @gauts/auth
```

Install the peer dependencies used by each application if they are not already present:

```bash
npm install hono @prisma/client
npm install next
```

### 2. Add the Prisma schema

The default adapter uses this fixed relationship tree:

```text
users
└── user_accounts
    ├── account_sessions
    └── social_accounts (optional)
```

Add the three required models to the API schema. `password_hash` may be nullable when the same account model also supports social authentication.

```prisma
model users {
  id   String @id @default(uuid()) @db.VarChar(255)
  name String @db.VarChar(255)

  accounts user_accounts[]
}

model user_accounts {
  id            String  @id @default(uuid()) @db.VarChar(255)
  user_id       String  @db.VarChar(255)
  email         String  @unique @db.VarChar(255)
  password_hash String? @db.VarChar(255)

  user     users             @relation(fields: [user_id], references: [id], onDelete: Cascade)
  sessions account_sessions[]

  @@index([user_id])
}

model account_sessions {
  id          String    @id @default(uuid()) @db.VarChar(255)
  account_id  String    @db.VarChar(255)
  token_hash  String    @unique @db.VarChar(64)
  ip          String?   @db.VarChar(45)
  country     String?   @db.VarChar(2)
  platform    String?   @db.VarChar(255)
  agent       String?   @db.Text
  expires_at  DateTime  @db.Timestamp(0)
  revoked_at  DateTime? @db.Timestamp(0)
  created_at  DateTime  @default(now()) @db.Timestamp(0)
  updated_at  DateTime? @db.Timestamp(0)

  account user_accounts @relation(fields: [account_id], references: [id], onDelete: Cascade)

  @@index([account_id])
  @@index([expires_at])
  @@index([revoked_at])
}
```

When social authentication is enabled, add this relation inside `user_accounts`:

```prisma
socials social_accounts[]
```

Then add the optional model:

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

Create the migration through the application's Prisma workflow, then regenerate its client:

```bash
npx prisma migrate dev --name add_auth
npx prisma generate
```

### 3. Create the auth instance and routes

Create the API auth instance:

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
        user: c.get("user"),
    });
});
```

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

The frontend does not receive `AUTH_SECRET`. The API remains responsible for session validation and every `Set-Cookie` response.

## Requirements and package entry points

- Node.js 22 or newer.
- A database adapter.
- Hono 4 when using the Hono adapter.
- Next.js 15 or newer when using the Next.js adapter.

`hono` and `next` are optional peer dependencies. The Prisma adapter receives the application's generated Prisma client and does not import Prisma at runtime.

| Import                  | Purpose                                                   |
| ----------------------- | --------------------------------------------------------- |
| `@gauts/auth`           | Password service, session core, errors, and public types. |
| `@gauts/auth/prisma`    | Prisma database adapter.                                  |
| `@gauts/auth/hono`      | Hono cookies, methods, and middleware.                    |
| `@gauts/auth/next`      | Next.js renewal scheduling and `Set-Cookie` forwarding.   |
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
| `secret`   | `string`              | With `cache` or `social` | —                 | HMAC secret for signed authentication data. Minimum 32 UTF-8 bytes.                                 |
| `social`   | `SocialConfig`        |            ❌            | Disabled          | Enables configured social providers, redirects, and optional registration.                          |

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

The Prisma adapter uses one fixed, predictable session relationship tree and one optional social relation:

```text
users
└── user_accounts
    ├── account_sessions
    └── social_accounts (optional)
```

The required default delegate names are `prisma.users`, `prisma.user_accounts`, and `prisma.account_sessions`. When `prisma.social_accounts` exists, the adapter adds social persistence automatically. The fixed Prisma relation fields are:

- `user_accounts.user`;
- `account_sessions.account`;
- `social_accounts.account` when social persistence is present.

There is no relation mapping configuration. Applications may rename delegates with `table`, add payload fields with `select`, and define access conditions with `access`. Omitting the social model removes the social methods from the adapter without affecting password or session authentication.

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
        // Only when social authentication is enabled.
        socials: {
            table: "admin_social_accounts",
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
| `client`                 | Generated Prisma client                 |    ✅    | —                    | Prisma client containing the three required auth models.    |
| `models.users.table`     | Compatible user delegate name           |    ❌    | `"users"`            | Overrides the user delegate.                               |
| `models.users.select`    | Unique scalar field array               |    ❌    | `[]`                 | Adds payload fields; `id` and `name` are always included.  |
| `models.users.access`    | Scalar equality or allowed-value arrays |    ❌    | `{}`                 | Conditions required on the owning user/entity.             |
| `models.accounts.table`  | Compatible account delegate name        |    ❌    | `"user_accounts"`    | Overrides the account delegate.                            |
| `models.accounts.select` | Unique scalar field array               |    ❌    | `[]`                 | Adds payload fields; `id` and `email` are always included. |
| `models.accounts.access` | Scalar equality or allowed-value arrays |    ❌    | `{}`                 | Conditions required on the authenticating account.         |
| `models.sessions.table`  | Compatible session delegate name        |    ❌    | `"account_sessions"` | Overrides authoritative session persistence.               |
| `models.socials.table`   | Compatible social delegate name         |    ❌    | `"social_accounts"`  | Overrides optional provider association persistence.       |

`select` accepts JSON-safe scalar fields and receives autocomplete from the generated Prisma client. `password`, `hash`, `password_hash`, and `passwordHash` are rejected by both TypeScript and runtime validation. Never select tokens or other secrets because the optional cache is signed, not encrypted.

Each `access` condition is either an exact scalar value or an array of accepted values:

```ts
access: {
    active: true,
    role: ["OWNER", "ADMIN"],
}
```

Every configured account and user condition must match. Omitting `access` applies no application-specific account restriction.

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
    -> load current account and owning user
    -> apply configured account/user access rules
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
    -> validate expiry, revocation, account/user access, and client
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

The Prisma adapter refines `account` and `user` with the exact additional scalar fields declared in their respective `select` arrays.

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

`country` is normalized to uppercase and is never used for authentication or client matching. It is not resolved by the package and does not trigger GeoIP work during normal requests. When supplied, the configured session model must provide a nullable `country` column. When omitted, the Prisma adapter does not send the field.

### Methods

| Method                                                  | Purpose                                                                                           |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `auth.createSession({ account_id, context, country? })` | Creates the DB session and writes the browser cookies. `country` is optional login-time metadata. |
| `auth.resolveSession(context)`                          | Resolves a request and returns the selected account and session.                                  |
| `auth.renewSession(context)`                            | Performs DB validation, renews when due, and writes authoritative cookies.                        |
| `auth.revokeSession(context)`                           | Revokes the current DB session and clears cookies.                                                |
| `auth.clearSession(context)`                            | Clears browser cookies without revoking the DB session.                                           |
| `auth.getToken(context)`                                | Returns the validated opaque token from the request cookie.                                       |
| `auth.requireSession`                                   | Hono middleware that authenticates and populates the context.                                     |

`requireSession` authenticates only. Application-specific route permissions remain the application's responsibility.

## Social authentication

Social authentication is disabled unless `social` is configured. Import providers separately so applications only include the providers they use:

Social authentication requires the optional `social_accounts` model documented in the schema setup. Without that model, `createPrismaAdapter()` remains a session-only adapter and configuring `social` fails during application startup.

```ts
import { createHonoAuth } from "@gauts/auth/hono";
import { createPrismaAdapter } from "@gauts/auth/prisma";
import { github, google, x } from "@gauts/auth/providers";

export const auth = createHonoAuth({
    db: createPrismaAdapter({ client: prisma }),
    secret: requiredEnv("AUTH_SECRET"),
    social: {
        errorUrl: "https://app.example.com/auth/login",
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
        successUrl: "https://app.example.com/dashboard",
    },
});
```

Declare one application route for every configured provider and supported action:

```ts
app.get("/auth/social/:provider/:action", async (c) => {
    return auth.social.handle(c);
});
```

The same route handles the explicit `start` and `callback` paths:

```text
GET /proxy/auth/social/google/start?intent=login
GET /proxy/auth/social/google/start?intent=register
GET /proxy/auth/social/google/callback
GET /proxy/auth/social/github/start?intent=login
GET /proxy/auth/social/github/callback
GET /proxy/auth/social/x/start?intent=login
GET /proxy/auth/social/x/callback
```

`intent` defaults to `login`. Only `start` and `callback` are accepted as actions. The public `/proxy` path in this example is expected to forward to the Hono `/auth` path. Provider callback URLs must exactly match the public callback paths registered with each provider.

The package does not create or mount routes. Applications may wrap `auth.social.handle(c)` with their own logging, metrics, rate limiting, or other route-level behavior.

### Social configuration

| Property                     | Type / allowed values                |  Required   | Default   | Description                                                                |
| ---------------------------- | ------------------------------------ | :---------: | --------- | -------------------------------------------------------------------------- |
| `social.providers`           | `SocialProvider[]`                   |     ✅      | —         | Configured Google, GitHub, or X providers.                                 |
| `social.successUrl`          | Absolute HTTP(S) URL                 |     ✅      | —         | Fixed redirect after session creation.                                     |
| `social.errorUrl`            | Absolute HTTP(S) URL                 |     ✅      | —         | Fixed redirect for expected provider/authentication failures.              |
| `social.cookieName`          | Valid cookie name                    |     ❌      | `"__soc"` | Signed temporary OAuth/registration transaction cookie.                    |
| `social.registration`        | `SocialRegistrationConfig`           |     ❌      | Disabled  | Enables default or application-specific social registration.               |
| `registration.registerUrl`   | Absolute HTTP(S) URL                 |     ❌      | Direct    | Defers account creation to an application form.                            |
| `registration.createAccount` | Async callback returning `accountId` | Conditional | Built-in  | Creates required business data when the default structure is insufficient. |

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
    errorUrl,
    providers: [googleProvider],
    successUrl,
}
```

Default registration creates `users { id, name }`, `user_accounts { id, email, user_id }`, the provider link, and the session:

```ts
social: {
    errorUrl,
    providers: [googleProvider],
    registration: {},
    successUrl,
}
```

This requires every additional application column on `users` and `user_accounts` to be nullable or have a database default.

For additional required form data, configure a registration URL and callback:

```ts
import type { SocialRegistrationInput } from "@gauts/auth";

type RegisterData = {
    companyNumber: string;
};

social: {
    errorUrl,
    providers: [googleProvider],
    registration: {
        registerUrl: "https://app.example.com/auth/register/social",
        createAccount: async ({ data, identity }: SocialRegistrationInput<RegisterData>) => {
            const account = await createApplicationAccount({
                companyNumber: data.companyNumber,
                email: identity.email,
                name: identity.name,
            });

            return { accountId: account.id };
        },
    },
    successUrl,
}
```

The application endpoint reads the verified identity and completes registration:

```ts
app.get("/auth/register/social", (c) => {
    return c.json(auth.social.getRegistration(c));
});

app.post("/auth/register/social", async (c) => {
    const data = await c.req.json<{ companyNumber: string }>();

    await auth.social.completeRegistration({
        context: c,
        data,
    });

    return c.json({ registered: true });
});
```

`registerUrl` requires `createAccount`; otherwise submitted application data would have no owner. `createAccount` must create the fixed `users`/`user_accounts` relation and return the created account ID. The package then creates `social_accounts` and the authenticated session.

### OAuth security

- Authorization Code flow with PKCE `S256` is used for every provider.
- State and the PKCE verifier live in the signed, HttpOnly `__soc` cookie for at most 10 minutes.
- The temporary cookie is cleared after success or expected failure.
- Only provider-verified email addresses are accepted.
- Provider IDs, not email addresses, are the stable social link identifiers.
- Redirect URLs come only from startup configuration; request query parameters cannot choose them.
- Social OAuth requires `SameSite=Lax` or `SameSite=None`; `Strict` fails during startup.

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

The Prisma adapter already implements both `DbAdapter` and `SocialDbAdapter`.

## Performance

The package contains no Redis or in-process cache.

Without the optional browser cache, each `requireSession` performs an indexed database lookup through `account_sessions.token_hash`.

With a valid cache, `GET` and `HEAD` skip the lookup until `cache.ttl` expires. Unsafe methods always use current database state.

The tradeoff is explicit: revocation and selected account or relation changes made elsewhere may remain visible to safe cached requests until the short TTL expires. A 60-second TTL limits this stale-read window to one minute. Disable cache when immediate read revocation is required.

## Errors

```ts
type AuthErrorCode =
    | "AUTH_CONFIG_INVALID"
    | "SOCIAL_ACCOUNT_INVALID"
    | "SOCIAL_ACCOUNT_NOT_FOUND"
    | "SOCIAL_EMAIL_INVALID"
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
- equivalent password verification work for unknown accounts;
- route roles and authorization;
- re-authentication for sensitive operations;
- database migrations and session cleanup;
- never logging passwords, raw tokens, cookie headers, or password hashes.

Exact IP, User-Agent, and platform validation are defense in depth. They do not prevent every stolen-cookie replay scenario.
