# `@gauts/auth`

Reusable password authentication and database-backed opaque sessions for Node.js applications.

The package stores only a SHA-256 token hash in the database. Browser integration uses three cookies with separate responsibilities:

```text
session cookie -> opaque token
cache cookie   -> short signed session snapshot
renew cookie   -> untrusted renewAt timestamp
```

Only the opaque session token authenticates. It remains stable during sliding renewal, but the session can never exceed its configured maximum lifetime. The optional cache is disabled when omitted and never replaces database validation for unsafe methods, renewal, logout, WebSockets, or direct core calls.

## Requirements

- Node.js 22 or newer.
- A database adapter, or a Prisma client containing the required schema contract.
- Hono 4 when using `@gauts/auth/hono`.
- Next.js 15 or newer when using `@gauts/auth/next`.

## Installation

For Hono and Prisma:

```bash
npm install @gauts/auth hono @prisma/client
```

For the Next.js adapter, the application must already use Next.js:

```bash
npm install @gauts/auth next
```

`hono` and `next` are optional peer dependencies. The Prisma adapter receives the consuming application's generated client and does not import Prisma at runtime.

## Package entry points

| Import | Purpose |
| --- | --- |
| `@gauts/auth` | Framework-independent password and session core types. |
| `@gauts/auth/prisma` | Prisma implementation of the database adapter. |
| `@gauts/auth/hono` | Hono cookies, session methods, and middleware. |
| `@gauts/auth/next` | Next.js renewal scheduling and `Set-Cookie` forwarding. |

## Flow

Login:

```text
credentials accepted
    -> generate 256-bit opaque token
    -> store SHA-256 token hash in DB
    -> load current account and user relations
    -> validate configured status and role rules
    -> write opaque session token cookie
    -> write renewAt as Unix seconds
    -> optionally write signed short cache
```

Protected `GET` or `HEAD`:

```text
opaque session token
    -> valid signed cache bound to token and client?
        -> yes: expose cached session, account, and user
        -> no: perform indexed DB validation and issue a fresh cache
```

Unsafe methods and direct core calls:

```text
opaque session token
    -> SHA-256 token
    -> indexed DB lookup
    -> expiry, revocation, account, user, and client validation
    -> clear any existing cache after successful unsafe validation
    -> route
```

Renewal:

```text
Next reads renewAt from the renewal cookie
    -> valid future Unix timestamp: no API call
    -> missing, invalid, or due timestamp: POST /auth/renew
    -> API performs full DB validation
    -> DB expires_at = min(now + ttl, created_at + maxLifetime)
    -> Set-Cookie with same token, a new renewAt, and a fresh cache
```

`auth.session.resolve()` is always DB-backed and read-only. Only the explicit renewal operation updates database expiry, and neither activity nor renewal can extend the session beyond `maxLifetime`.

## Prisma schema contract

The Prisma adapter resolves authentication through this relation chain:

```text
account_sessions -> account -> user
```

The default Prisma client delegate is `account_sessions`. A different session model delegate can be selected through `config.table`.

### Complete minimal schema

This is a complete MySQL/MariaDB example. If `users` and `user_accounts` already exist, merge the required fields and relations into those models instead of duplicating them.

```prisma
model users {
  id      String @id @default(uuid()) @db.VarChar(255)
  role    String @db.VarChar(255)
  status  String @db.VarChar(255)

  accounts user_accounts[]
}

model user_accounts {
  id         String  @id @default(uuid()) @db.VarChar(255)
  user_id    String  @db.VarChar(255)
  email      String  @db.VarChar(255)
  name       String  @db.VarChar(255)
  role       String  @db.VarChar(255)
  status     String  @db.VarChar(255)
  timezone   String? @db.VarChar(255)

  user     users              @relation(fields: [user_id], references: [id], onDelete: Cascade)
  sessions account_sessions[]

  @@index([user_id])
}

model account_sessions {
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

  account user_accounts @relation(fields: [account_id], references: [id], onDelete: Cascade)

  @@index([account_id])
  @@index([expires_at])
  @@index([revoked_at])
}
```

The adapter requires these Prisma field and relation names:

| Path | Required fields |
| --- | --- |
| Session model | `id`, `account_id`, `token_hash`, `ip`, `platform`, `agent`, `expires_at`, `revoked_at`, `created_at`, `updated_at` |
| `account` relation | `id`, `email`, `name`, `role`, `status`, `timezone` |
| `account.user` relation | `id`, `role`, `status` |

The relation fields must be named `account` and `user`, because those are the names selected by the adapter. Prisma also requires the inverse relations; their field names (`sessions` and `accounts` above) can be changed because the adapter never queries them.

Application models may contain additional fields, defaults, indexes, and relations. `role` and `status` may use application-specific Prisma enums instead of `String`; Prisma returns both as strings to the adapter. For other database providers, replace the native `@db.*` annotations with compatible types and keep `agent` large enough to store the complete User-Agent.

`config.table` is the Prisma client delegate name, not the physical database table name. For example, a Prisma model named `AdminSession` mapped with `@@map("account_sessions")` normally uses the `adminSession` delegate.

Create migrations through the consuming application's normal Prisma workflow. The package never creates or runs migrations.

## Hono quick start

The Hono adapter provides methods and middleware; it does not register routes automatically. The application remains responsible for creating its login, renewal, logout, and protected endpoints.

### Create one auth instance

```ts
import { createHonoAuth } from "@gauts/auth/hono";
import { createPrismaAdapter } from "@gauts/auth/prisma";

export const auth = createHonoAuth({
    secret: process.env.AUTH_SECRET,

    db: createPrismaAdapter({
        client: prisma,
        config: {
            account: {
                status: ["ACTIVE", "PENDING"],
            },
            user: {
                status: ["ACTIVE", "PENDING"],
            },
        },
    }),

    getIp: (c) => getTrustedClientIp(c),

    session: {
        validation: ["agent"],
    },

    cache: {
        ttl: 60,
    },
});
```

`secret` is required only when `cache` is configured. Supply at least 32 high-entropy bytes from the API environment. It is never shared with the Next.js application.

`createHonoAuth` is the normal Hono entry point: it creates the framework-independent core and attaches the Hono methods in one object. Use `createAuth` plus `createHonoAdapter` only when the same core instance must be composed manually:

The resolved cookie names are exposed on the auth instance, including defaults:

```ts
auth.cookie.name;      // "__sec"
auth.cookie.cacheName; // "__cac"
auth.cookie.renewName; // "__ren"
```

```ts
import { createAuth } from "@gauts/auth";
import { createHonoAdapter } from "@gauts/auth/hono";

const core = createAuth({ db });
const hono = createHonoAdapter({
    auth: core,
    cache: { ttl: 60 },
    getIp: (c) => getTrustedClientIp(c),
    secret: process.env.AUTH_SECRET,
});
```

Do not create a second core for the adapter; pass the existing `core` instance through `auth`.

Only `account_id` is stored in the session row. The Prisma adapter loads the current `account` and `user` relations during authentication; no dynamic account data is copied into the session.

### Type the application

```ts
import { Hono } from "hono";
import type { HonoAuthEnv } from "@gauts/auth/hono";

const app = new Hono<HonoAuthEnv>();
```

`auth.requireSession` installs:

```ts
const session = c.get("session");
const account = c.get("account");
const user = c.get("user");
```

The values have these shapes:

```ts
type AuthAccount = {
    email: string;
    id: string;
    name: string;
    role: string;
    status: string;
    timezone: string | null;
    user: AuthUser;
};

type AuthUser = {
    id: string;
    role: string;
    status: string;
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

### Login

The application owns input validation, credential lookup, rate limiting, and error responses. The adapter access rules validate current account and user status/role before the session is accepted.

```ts
const DUMMY_PASSWORD_HASH =
    "$argon2id$v=19$m=65536,p=4,t=3$PUotpfVXonc0VRFuV1pKZQ$oxxA8DMvGRTSbZvh2Dkokeyih9sbKeodWYROqVxP9BI";

app.post("/auth/login", async (c) => {
    const body = await c.req.json<{
        email: string;
        password: string;
    }>();
    const account = await findAccount(body.email);
    const passwordValid = await auth.password.verify({
        password: body.password,
        storedHash: account?.passwordHash ?? DUMMY_PASSWORD_HASH,
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
```

The dummy hash ensures that unknown accounts still perform the configured password verification. Precompute it once with the same algorithm and cost as the application; never generate it inside the request handler. Keep the response identical for unknown accounts and invalid passwords.

Only `account_id` is persisted by the session. Email, roles, statuses, password hashes, and other dynamic account data never enter the session table.

### Protect routes

```ts
app.get("/account", auth.requireSession, (c) => {
    return c.json({
        account: c.get("account"),
        session_id: c.get("session").id,
        user: c.get("user"),
    });
});
```

`requireSession` authenticates the request. With cache configured, only `GET` and `HEAD` may use it. Every other method validates through the database and clears the short cache after successful validation. It does not apply application-specific route roles or permissions.

### Renewal endpoint

```ts
app.post("/auth/renew", async (c) => {
    await auth.renewSession(c);
    return c.body(null, 204);
});
```

`renewSession` always performs full database validation. It independently derives whether renewal is due from `created_at` and the last database renewal; the renewal marker never authorizes renewal.

If renewal is not yet due, database expiry is not changed. The API still returns the authoritative session cookie, renewal marker, and cache.

### Logout

```ts
app.post("/auth/logout", async (c) => {
    await auth.revokeSession(c);
    return c.body(null, 204);
});
```

Logout marks the database session as revoked and then clears all three cookies. If database revocation fails, the cookies are not cleared and the error is propagated.

## Next.js renewal adapter

The Next.js adapter does not authenticate sessions. It calls the private API renewal URL when `renewAt` is missing, invalid, or due.

```ts
import { createNextAuth } from "@gauts/auth/next";

export const nextAuth = createNextAuth({
    renewUrl: `${process.env.NEXT_PRIVATE_API_URL}/auth/renew`,
});
```

The controlled header list is also exported for application fetchers that need to follow the same forwarding policy:

```ts
import { FORWARD_HEADERS } from "@gauts/auth/next";
```

Use it in `proxy.ts` before returning the browser-facing response:

```ts
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

export const proxy = async (request: NextRequest) => {
    const response = NextResponse.next();
    const renewal = await nextAuth.renew({
        request,
        response,
    });

    if (renewal.status === 401) {
        return NextResponse.redirect(new URL("/login", request.url));
    }

    if (renewal.status !== null && renewal.status >= 500) {
        return NextResponse.redirect(new URL("/maintenance", request.url));
    }

    return renewal.response;
};
```

Result semantics:

| `attempted` | `status` | Meaning |
| --- | ---: | --- |
| `false` | `null` | Session token exists and `renewAt` is a valid future timestamp. |
| `false` | `401` | Session token is missing or malformed. No API call occurred. |
| `true` | HTTP status | `/auth/renew` was called and its `Set-Cookie` headers were copied. |

The adapter forwards only the session cookie and the client/origin headers required for session, host, and CSRF validation. If the browser request has no `Origin` or `X-Forwarded-Host`, it derives them from the public `NextRequest` URL. Other cookies, `Authorization`, and arbitrary request headers are never forwarded. Renewal rejects redirects and times out after five seconds. `renewUrl` must point to the application's trusted private API.

Protected API endpoints remain responsible for real authentication. The renewal marker is only a browser scheduling mechanism and never acts as a refresh token.

Apply the proxy only to protected application routes, or skip renewal handling for public routes before calling `nextAuth.renew`. Otherwise a missing cookie produces `status: 401`, which is correct for protected routes but not for login or public pages.

## Configuration

### Password

Argon2id is the default:

```ts
password: {
    algorithm: "argon2id",
}
```

| Argon2id property | Default | Allowed |
| --- | ---: | ---: |
| `hashLength` | `32` | `16` to `64` |
| `maxBytes` | `1024` | `1` to `1,048,576` |
| `memoryCost` | `65,536` | `8,192` to `1,048,576` |
| `parallelism` | `4` | `1` to `16` |
| `timeCost` | `3` | `1` to `10` |

Applications with existing bcrypt hashes must select bcrypt explicitly:

```ts
password: {
    algorithm: "bcrypt",
}
```

| bcrypt property | Default | Allowed |
| --- | ---: | ---: |
| `maxBytes` | `72` | `1` to `72` |
| `rounds` | `12` | `4` to `31` |
| `verifyMaxBytes` | `72` | `maxBytes` to `1,048,576` |

The selected algorithm is used for both hashing and verification. The package never detects algorithms, migrates hashes, rehashes passwords, or falls back to another algorithm.

### Session

```ts
session: {
    maxLifetime: 30 * 24 * 60 * 60,
    renewInterval: 24 * 60 * 60,
    ttl: 7 * 24 * 60 * 60,
    validation: ["agent"],
}
```

Time values are seconds.

| Property | Default | Allowed | Purpose |
| --- | ---: | ---: | --- |
| `maxLifetime` | `2,592,000` | `ttl` to `31,536,000` | Maximum lifetime from the original login, regardless of activity. |
| `renewInterval` | `86,400` | `1` to `ttl - 1` | Minimum interval before renewal is due. |
| `ttl` | `604,800` | `60` to `31,536,000` | Sliding inactivity lifetime. |
| `validation` | `["agent"]` | Unique `agent`, `ip`, `platform` fields | Exact client fields compared on every validation. |

The authoritative limits are derived from the immutable creation time and the last successful renewal:

```text
maxExpiresAt = created_at + maxLifetime
expires_at   = min(now + ttl, maxExpiresAt)
renew_at    = min((updated_at ?? created_at) + renewInterval, maxExpiresAt)
```

`maxLifetime` must be greater than or equal to `ttl`. It is enforced by the session core and requires a new login after the limit is reached; no additional database column is required.

### Cookie

```ts
cookie: {
    cacheName: "__cac",
    domain: undefined,
    name: "__sec",
    path: "/",
    renewName: "__ren",
    sameSite: "Lax",
    secure: true,
}
```

`HttpOnly` is always enabled.

- The session cookie contains only the stable opaque token and expires with the database session.
- The cache cookie contains the signed snapshot and expires after `cache.ttl`.
- The renewal cookie contains the authoritative `renew_at` as Unix seconds and expires with the session cookie.
- The renewal timestamp is an untrusted scheduling hint. It never authenticates or extends a session.
- Cookie names default to `__sec`, `__cac`, and `__ren`.
- All three names must be valid and unique.

- `__Host-` requires `secure: true`, `path: "/"`, and no domain.
- `__Secure-` requires `secure: true`.
- `SameSite=None` requires `secure: true`.
- Local HTTP development requires `secure: false`.

### Signed session cache

The cache is disabled by default. Enable it explicitly:

```ts
secret: process.env.AUTH_SECRET,
cache: {
    ttl: 60,
}
```

`ttl` is measured in seconds and must be an integer from `1` through the configured session TTL. The secret must contain at least 32 bytes and should be generated from a cryptographically secure source.

The cache payload:

- is signed with HMAC-SHA-256 using a domain-separated context;
- is cryptographically bound to the opaque session token;
- contains the resolved session, account, user, and its own expiry;
- compares the same configured IP, User-Agent, and platform fields on every hit;
- never extends the authoritative session expiry;
- is accepted only for `GET` and `HEAD` requests.

An absent, expired, malformed, altered, token-mismatched, or client-mismatched cache is a cache miss. The adapter then performs normal database authentication. A real configured client mismatch is therefore still detected and revoked by the database session service.

Unsafe methods always query the database. Renewal and logout also query the database directly. `auth.session.resolve()` never uses the browser cache, which keeps WebSocket and non-HTTP integrations DB-backed.

### Trusted client IP

```ts
getIp: (c) => getTrustedClientIp(c);
```

Only the application knows which proxy and forwarding header are trusted. The package normalizes the returned value but never chooses `X-Forwarded-For`, `CF-Connecting-IP`, or a socket address itself.

The Hono adapter reads:

```ts
type SessionClientInput = {
    agent?: string | null;
    ip?: string | null;
    platform?: string | null;
};
```

- IPv4, IPv4-mapped IPv6, and IPv6 are canonicalized.
- Invalid or empty IP values become `null`.
- Platform comes from `Sec-CH-UA-Platform`, is normalized, and is limited to 255 characters.
- User-Agent comes from `User-Agent` and is stored in full.
- No GeoIP, DNS, country, or external lookup is performed.
- Every field selected in `session.validation` is required during creation and validation. Missing or invalid configured fields never match.

## Database adapter

The core depends only on the exported `DbAdapter` contract. It does not import Prisma or depend on a specific ORM. `createPrismaAdapter` is the Prisma implementation exposed through `@gauts/auth/prisma`; other ORM implementations can use their own package subpath and factory name.

Default Prisma delegate (`account_sessions`):

```ts
import { createPrismaAdapter } from "@gauts/auth/prisma";

const db = createPrismaAdapter({
    client: prisma,
    config: {
        account: {
            status: ["ACTIVE"],
        },
        user: {
            status: ["ACTIVE"],
        },
    },
});
```

Custom compatible Prisma delegate:

```ts
const db = createPrismaAdapter({
    client: prisma,
    config: {
        account: {
            status: ["ACTIVE"],
        },
        table: "admin_sessions",
        user: {
            status: ["ACTIVE"],
        },
    },
});
```

Access rules:

```ts
const db = createPrismaAdapter({
    client: prisma,
    config: {
        account: {
            status: ["ACTIVE", "PENDING"],
        },
        user: {
            role: ["ADMIN"],
            status: ["ACTIVE", "PENDING"],
        },
    },
});
```

Account and user status lists are required because the package cannot know which application-specific values grant access. Roles are unrestricted unless configured. Every list must contain unique non-empty strings. A role rule controls authentication for the entire application; route-level authorization remains the application's responsibility.

The configured arrays are access allowlists, not declarations of every enum value that exists in the application.

Custom database adapters implement:

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

`findToken` must use the token hash and never accept or persist a raw token. It returns the current nested `account`, its `user`, and an `allowed` result derived from the adapter's access rules.

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

- `resolve` performs read-only authentication.
- `renew` validates and updates expiry only when due.
- `list` returns active, non-expired sessions without token hashes.
- revocation retains database history through `revoked_at`.
- the package does not limit session count or delete historical rows; retention and cleanup belong to the application.

## Performance and cache policy

The package contains no Redis or in-process cache. The optional signed browser cache avoids shared infrastructure and works across API instances that use the same `AUTH_SECRET`.

Without cache, each `requireSession` performs:

```text
1 Prisma relation lookup by indexed account_sessions.token_hash
```

With a valid cache, `GET` and `HEAD` avoid that lookup until `cache.ttl` expires. Cache misses perform the normal indexed lookup and return a new cache cookie. Prisma loads current relations through the session query; the exact number of SQL statements depends on Prisma's configured relation load strategy.

Cookie caching has an explicit consistency tradeoff: revocation and account/user changes made elsewhere may remain visible to safe requests until the short cache expires. Unsafe methods never accept the cache, so writes observe current database state. A 60-second TTL limits the stale-read window to at most one minute.

Logout clears the current browser's cache immediately. Cookies on another device cannot be remotely deleted, so immediate cross-device read revocation requires disabling the cache or using shared server-side state outside this package.

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

The package does not choose HTTP responses. A typical application mapping is:

| Code | Suggested HTTP status |
| --- | ---: |
| `AUTH_CONFIG_INVALID` | `500` during startup |
| `PASSWORD_INPUT_INVALID` | `400` |
| `SESSION_CLIENT_MISMATCH` | `403` |
| `SESSION_DATA_INVALID` | `400` |
| `SESSION_INVALID` | `401` |
| `SESSION_NOT_FOUND` | `404` |
| `DB_UNAVAILABLE` | `503` |

Applications may use a different response policy, but database failures and invalid sessions must continue to fail closed.

## Security responsibilities

The package provides session primitives, not a complete application security policy. Consuming applications remain responsible for:

- TLS and trusted-proxy configuration;
- CSRF, CORS, and origin validation;
- login and renewal rate limiting;
- equivalent password verification work for unknown accounts;
- account status and authorization rules;
- re-authentication for sensitive actions;
- database migrations and cleanup;
- never logging passwords, raw tokens, cookie headers, or password hashes.

Exact IP/User-Agent/platform matching is defense in depth. It does not prevent every stolen-cookie replay scenario.
