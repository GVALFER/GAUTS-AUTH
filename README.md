# `@gauts/auth`

Reusable password authentication and opaque server-side sessions for Node.js applications.

`@gauts/auth` validates sessions through Redis and stores durable session history in a database. Redis is the authentication authority; the database is never used as an authentication fallback.

## Requirements

- Node.js 22 or newer.
- A connected Redis client.
- A Prisma client containing the required session model, or a custom `DbAdapter`.
- Hono 4 when using the Hono adapter.

## Installation

For Hono, Prisma, and Redis:

```bash
npm install @gauts/auth hono redis @prisma/client
```

`hono` and `redis` are optional peer dependencies. The Prisma adapter does not import Prisma at runtime; it receives the generated client from the application.

## Flow

Login:

```text
password -> configured algorithm -> database session row
                                 -> Redis session
                                 -> opaque HttpOnly cookie
```

Authenticated HTTP request:

```text
cookie -> SHA-256 hash -> Redis -> client validation -> route
                               -> renewal due -> database expiry
                                              -> Redis TTL
                                              -> cookie expiry
```

The browser receives one random 256-bit opaque token. The token remains the same throughout the session. Redis and the database store only its SHA-256 hash.

Sessions use sliding inactivity expiry. Activity before `renewInterval` performs no expiry write. The first eligible HTTP request after `renewInterval` extends the database expiry, Redis TTL, and browser cookie expiry.

## Prisma model

The default Prisma model is `auth_sessions`:

```prisma
model auth_sessions {
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

  @@index([account_id])
  @@index([expires_at])
  @@index([revoked_at])
}
```

These field names and compatible types are required. Additional indexes, relations, and optional/defaulted fields are allowed. Do not add required fields without defaults unless the application supplies them separately.

Create migrations through the consuming application's normal Prisma workflow. The package never creates or runs migrations.

## Quick start with Hono

### 1. Define the session data

The generic passed to `createHonoAuth` defines the application data cached in Redis and exposed on authenticated requests. Keep it small and never include secrets or password hashes.

```ts
type AccountSession = {
  email: string;
  role: "admin" | "owner";
};
```

### 2. Create one auth instance

```ts
import { createHonoAuth } from "@gauts/auth/hono";
import { createDbAdapter } from "@gauts/auth/prisma";
import { createRedisAdapter } from "@gauts/auth/redis";

export const auth = createHonoAuth<AccountSession>({
  getIp: (c) => getTrustedClientIp(c),
  db: createDbAdapter({
    client: prisma,
  }),
  redis: createRedisAdapter({
    client: redis,
    config: { prefix: "my-app:auth" },
  }),
});
```

Both clients must already be initialized by the application. The package does not connect, reconnect, disconnect, or close them.

`createDbAdapter` uses `auth_sessions` by default. `config` is optional:

```ts
const db = createDbAdapter({
  client: prisma,
  config: {
    table: "admin_sessions",
  },
});
```

When `table` is supplied, TypeScript only accepts a compatible model from that generated Prisma client.

### 3. Type the Hono application

```ts
import { Hono } from "hono";
import type { HonoAuthEnv } from "@gauts/auth/hono";

const app = new Hono<HonoAuthEnv<AccountSession>>();
```

`auth.requireSession` installs both values:

```ts
const session = c.get("session");
const account = c.get("account");
```

### 4. Login

The application owns request validation, account lookup, rate limiting, status checks, and error responses.

```ts
app.post("/auth/login", async (c) => {
  const { email, password } = await c.req.json<{
    email: string;
    password: string;
  }>();
  const account = await findAccount(email);

  if (
    !account ||
    !(await auth.password.verify({
      password,
      storedHash: account.password_hash,
    }))
  ) {
    return c.json({ error: "Invalid credentials." }, 401);
  }

  const session = await auth.createSession({
    account_id: account.id,
    context: c,
    data: {
      email: account.email,
      role: account.role,
    },
  });

  return c.json({ account: session.data });
});
```

`createSession` inserts the database row, creates the Redis session, writes the cookie, and returns the public session. The raw token remains internal to the Hono adapter.

### 5. Protect routes

```ts
app.get("/account", auth.requireSession, (c) => {
  return c.json({
    account: c.get("account"),
    session_id: c.get("session").id,
  });
});
```

`requireSession` authenticates the request. It does not apply application roles or permissions.

### 6. Logout

```ts
app.post("/auth/logout", async (c) => {
  await auth.revokeSession(c);
  return c.body(null, 204);
});
```

Logout deletes the Redis session, records revocation in the database, and clears the cookie. Backend revocation removes access; clearing the cookie is client cleanup.

## Configuration

### `createHonoAuth`

```ts
const auth = createHonoAuth<AccountSession>({
  getIp,
  db,
  redis,
  password,
  session,
  cookie,
});
```

| Property   | Required | Purpose                                                              |
| ---------- | -------- | -------------------------------------------------------------------- |
| `getIp`    | Yes      | Returns the trusted client IP from the Hono context.                 |
| `db`       | Yes      | Stores durable session history.                                      |
| `redis`    | Yes      | Stores and validates active sessions.                                |
| `password` | No       | Selects password algorithm and cost limits. Defaults to Argon2id.    |
| `session`  | No       | Configures expiry, renewal, maximum sessions, and client validation. |
| `cookie`   | No       | Configures the Hono session cookie.                                  |

Configuration is resolved once when the auth instance is created. Invalid configuration throws `AUTH_CONFIG_INVALID` during startup.

### Password

Argon2id is the default:

```ts
password: {
  algorithm: "argon2id",
}
```

| Argon2id property |      Default |                Allowed | Purpose                           |
| ----------------- | -----------: | ---------------------: | --------------------------------- |
| `algorithm`       | `"argon2id"` |           `"argon2id"` | Selects Argon2id. May be omitted. |
| `hashLength`      |         `32` |           `16` to `64` | Hash output length in bytes.      |
| `maxBytes`        |       `1024` |     `1` to `1,048,576` | Maximum UTF-8 password size.      |
| `memoryCost`      |     `65,536` | `8,192` to `1,048,576` | Memory cost in KiB.               |
| `parallelism`     |          `4` |            `1` to `16` | Number of lanes.                  |
| `timeCost`        |          `3` |            `1` to `10` | Number of iterations.             |

Applications with bcrypt hashes must select bcrypt explicitly:

```ts
password: {
  algorithm: "bcrypt",
}
```

| bcrypt property  |  Default |                   Allowed | Purpose                                       |
| ---------------- | -------: | ------------------------: | --------------------------------------------- |
| `algorithm`      | Required |                `"bcrypt"` | Selects bcrypt for hashing and verification.  |
| `maxBytes`       |     `72` |               `1` to `72` | Maximum UTF-8 size accepted for new hashes.   |
| `rounds`         |     `12` |               `4` to `31` | Cost factor.                                  |
| `verifyMaxBytes` |     `72` | `maxBytes` to `1,048,576` | Maximum UTF-8 size accepted for verification. |

The selected algorithm is used for both hashing and verification. The package never detects algorithms, migrates hashes, rehashes passwords, or falls back to another algorithm.

bcrypt ignores bytes after the first 72. Keep `verifyMaxBytes` at `72` unless preserving historical truncation is an explicit application requirement.

### Session

```ts
session: {
  max: 10,
  renewInterval: 24 * 60 * 60,
  ttl: 7 * 24 * 60 * 60,
  validation: ["agent"],
}
```

Time values are seconds.

| Property        |     Default |                                             Allowed | Purpose                                                                                    |
| --------------- | ----------: | --------------------------------------------------: | ------------------------------------------------------------------------------------------ |
| `max`           |        `10` |                                     `1` to `10,000` | Maximum active sessions per account.                                                       |
| `renewInterval` |    `86,400` |                                    `1` to `ttl - 1` | Minimum activity interval between expiry writes.                                           |
| `ttl`           |   `604,800` |                                `60` to `31,536,000` | Inactivity lifetime on creation and renewal.                                               |
| `validation`    | `["agent"]` | Unique combination of `agent`, `ip`, and `platform` | Client fields compared during validation. An empty array disables client-field comparison. |

Expiry is sliding and has no forced absolute lifetime. The opaque token is not rotated during renewal.

### Cookie

```ts
cookie: {
  domain: undefined,
  name: "__Host-session",
  path: "/",
  sameSite: "Lax",
  secure: true,
}
```

| Property   | Default            | Purpose                                              |
| ---------- | ------------------ | ---------------------------------------------------- |
| `name`     | `"__Host-session"` | Cookie name.                                         |
| `domain`   | Not set            | Optional domain; without it the cookie is host-only. |
| `path`     | `"/"`              | Cookie path.                                         |
| `sameSite` | `"Lax"`            | `"Strict"`, `"Lax"`, or `"None"`.                    |
| `secure`   | `true`             | Sends the cookie only over HTTPS.                    |

`HttpOnly` is always enabled.

- `__Host-` requires `secure: true`, `path: "/"`, and no domain.
- `__Secure-` requires `secure: true`.
- `SameSite=None` requires `secure: true`.
- Local HTTP development with `secure: false` requires a custom name without a secure prefix.

### Redis adapter

```ts
import { createClient } from "redis";
import { createRedisAdapter } from "@gauts/auth/redis";

const redis = createClient({ url: process.env.REDIS_URL });
await redis.connect();

const adapter = createRedisAdapter({
  client: redis,
  config: {
    prefix: "my-app:auth",
  },
});
```

`config` is optional. The prefix defaults to `gauts:auth`, supports letters, numbers, `:`, `_`, and `-`, and has a maximum of 128 characters.

```text
<prefix>:session:<sha256-token-hash>
```

Redis failures throw `REDIS_UNAVAILABLE`. Authentication never falls back to the database.

### Prisma adapter

Default model:

```ts
import { createDbAdapter } from "@gauts/auth/prisma";

const db = createDbAdapter({
  client: prisma,
});
```

Custom compatible model:

```ts
const db = createDbAdapter({
  client: prisma,
  config: {
    table: "admin_sessions",
  },
});
```

The adapter owns the five database operations required by the session service: create, find one, find active, revoke, and update expiry. Applications do not implement those queries.

The default model is `auth_sessions`. If that model does not exist, `config.table` is required. TypeScript rejects a selected model whose generated result does not contain the complete session record shape.

Database failures are exposed by the auth core as `DB_UNAVAILABLE`.

### Custom database adapter

Applications not using Prisma can implement the exported `DbAdapter` contract:

```ts
import type { DbAdapter } from "@gauts/auth";

const db = {
  create: async (session) => {},
  find: async ({ account_id, session_id }) => null,
  findActive: async ({ account_id, now }) => [],
  revoke: async ({ revoked_at, session_ids }) => {},
  updateExpiry: async ({ expires_at, session_id, updated_at }) => {},
} satisfies DbAdapter;
```

The adapter must persist only token hashes, never raw tokens. `find` must scope by both `account_id` and `session_id`. `findActive` must return only non-revoked rows whose `expires_at` is greater than `now`.

### Trusted client IP

```ts
getIp: (c) => getTrustedClientIp(c);
```

`getIp` runs during login and every authenticated HTTP request. It may be synchronous or asynchronous and returns `string`, `null`, or `undefined`.

Only the application knows which reverse proxies and forwarding headers are trusted. The package does not select `X-Forwarded-For`, `CF-Connecting-IP`, socket addresses, or another source. It canonicalizes the value returned by the application.

The Hono adapter reads the remaining metadata from request headers:

```ts
type SessionClientInput = {
  agent?: string | null;
  ip?: string | null;
  platform?: string | null;
};
```

- IPv4, IPv4-mapped IPv6, and IPv6 are canonicalized.
- `::1` becomes `127.0.0.1`.
- Invalid or empty IP values become `null`.
- Platform comes from `Sec-CH-UA-Platform`, is unquoted and limited to 255 characters.
- Agent comes from `User-Agent` and is stored in full without truncation.
- No GeoIP, DNS, country, or database lookup is performed.

## Password API

### `auth.password.algorithm`

The resolved algorithm: `"argon2id"` or `"bcrypt"`.

### `auth.password.hash(password)`

Validates the UTF-8 byte length and creates a hash using the configured algorithm.

```ts
const password_hash = await auth.password.hash(password);
```

### `auth.password.verify({ password, storedHash })`

Verifies only with the configured algorithm. A hash from another algorithm or an invalid hash returns `false`.

```ts
const valid = await auth.password.verify({
  password,
  storedHash: account.password_hash,
});
```

Invalid password size throws `PASSWORD_INPUT_INVALID`. Wrong credentials return `false`.

## Hono API

### `auth.createSession({ account_id, context, data })`

Creates the database and Redis session, writes the HttpOnly cookie, and returns `Session<TData>`.

### `auth.resolveSession(context)`

Reads and validates the cookie and returns `Session<TData>`.

- Throws `SESSION_INVALID` when the cookie or Redis session is missing or invalid.
- Clears an invalid cookie.
- Compares configured client fields.
- Renews database expiry, Redis TTL, and cookie expiry only when due.
- Revokes the backend session and throws `SESSION_CLIENT_MISMATCH` after a mismatch.

### `auth.requireSession`

Middleware that calls `resolveSession` and sets:

```ts
c.set("session", session);
c.set("account", session.data);
```

### `auth.revokeSession(context)`

Revokes the session represented by the request cookie and clears that cookie. Returns the revoked session IDs.

### `auth.clearSession(context)`

Deletes only the response cookie. It does not revoke Redis or update the database and must not be used as logout.

### `auth.getToken(context)`

Returns the raw cookie token or `null`. Never log, persist, or expose this value in a response.

## Core session API

The same instance exposes the framework-independent `auth.session` service.

### `auth.session.create({ account_id, client, data })`

Creates a session and returns:

```ts
{
  session: Session<TData>;
  token: string;
}
```

Prefer `auth.createSession` in Hono applications because the core cannot write the browser cookie.

### `auth.session.resolve({ client, token })`

Validates and renews when due. It returns `null` for an invalid or expired session, otherwise:

```ts
{
  renewed: boolean;
  session: Session<TData>;
}
```

A framework using the core directly must update the cookie expiry when `renewed` is `true`.

### `auth.session.validate({ client, token })`

Validates without renewing Redis, database expiry, or cookie expiry. A configured client mismatch still revokes the backend session.

### `auth.session.list(account_id)`

Returns sessions that are active in both the database and Redis. The public result never contains `token_hash`.

### `auth.session.revoke({ account_id, session_id })`

Revokes one session after confirming it belongs to the supplied account. Throws `SESSION_NOT_FOUND` when it is absent or already revoked.

### `auth.session.revokeAccount(account_id)`

Revokes every active session for one account.

### `auth.session.revokeToken(token)`

Revokes the Redis session represented by a raw token and records the revocation in the database. Invalid or absent tokens return an empty array.

### `auth.session.sync({ account_id, data })`

Replaces the cached `data` in every active Redis session for the account while preserving tokens and TTLs.

Use it after changing cached account data. Use `revokeAccount` when a change must force re-authentication.

## Public session shapes

```ts
type Session<TData> = {
  account_id: string;
  client: {
    agent: string | null;
    ip: string | null;
    platform: string | null;
  };
  created_at: Date;
  data: TData;
  expires_at: Date;
  id: string;
  touched_at: Date;
};
```

```ts
type ActiveSession = {
  account_id: string;
  agent: string | null;
  created_at: Date;
  expires_at: Date;
  id: string;
  ip: string | null;
  platform: string | null;
  revoked_at: Date | null;
  updated_at: Date | null;
};
```

## Client validation

The default compares the complete User-Agent:

```ts
session: {
  validation: ["agent"],
}
```

An administration application can also bind IP and platform:

```ts
session: {
  validation: ["ip", "agent", "platform"],
}
```

An empty array validates only the opaque token:

```ts
session: {
  validation: [],
}
```

Comparison is exact after normalization. A configured mismatch deletes the Redis session and records revocation in the database, so both the suspicious client and legitimate browser must authenticate again.

Exact IP validation can log out legitimate users on VPN, mobile, or rotating networks. Client matching is defense in depth; it does not replace TLS, secure cookies, CSRF protection, XSS prevention, or explicit re-authentication for sensitive actions.

## Expiration and renewal

- Creation assigns `ttl` to Redis, the database row, and the cookie.
- Requests before `renewInterval` validate without expiry writes.
- The first eligible HTTP request after `renewInterval` sets expiry to `now + ttl` in Redis and the database.
- The Hono adapter sends `Set-Cookie` only when renewal occurs.
- The opaque token never changes during renewal.
- Continued eligible HTTP activity can keep a session alive indefinitely.
- A session without renewal activity expires after `ttl`.
- `validate` never renews; `resolve` renews only when due.

## Errors

All package errors have `name: "AuthError"` and a typed `code`.

```ts
import { isAuthError } from "@gauts/auth";

app.onError((error, c) => {
  if (!isAuthError(error)) {
    return c.json({ error: "Internal server error." }, 500);
  }

  if (error.code === "REDIS_UNAVAILABLE" || error.code === "DB_UNAVAILABLE") {
    return c.json({ error: "Authentication service unavailable." }, 503);
  }

  return c.json({ error: error.message }, 401);
});
```

| Code                      | Meaning                                                                |
| ------------------------- | ---------------------------------------------------------------------- |
| `AUTH_CONFIG_INVALID`     | Invalid startup configuration or adapter contract.                     |
| `PASSWORD_INPUT_INVALID`  | Empty or oversized password input.                                     |
| `SESSION_CLIENT_MISMATCH` | A configured client field changed and the backend session was revoked. |
| `SESSION_DATA_INVALID`    | Required session input or stored Redis payload is invalid.             |
| `SESSION_INVALID`         | Hono cookie or Redis session is missing, expired, or invalid.          |
| `SESSION_LIMIT_REACHED`   | The account already has the maximum active sessions.                   |
| `SESSION_NOT_FOUND`       | The selected session is absent or already revoked.                     |
| `DB_UNAVAILABLE`          | The database adapter failed or returned invalid session data.          |
| `REDIS_UNAVAILABLE`       | Redis failed or returned invalid data; authentication fails closed.    |

Applications decide final HTTP statuses and public messages.

## Framework-independent usage

```ts
import { createAuth } from "@gauts/auth";
import { createDbAdapter } from "@gauts/auth/prisma";
import { createRedisAdapter } from "@gauts/auth/redis";

const auth = createAuth<AccountSession>({
  db: createDbAdapter({ client: prisma }),
  redis: createRedisAdapter({ client: redis }),
});
```

The application must then extract client input, read and secure the raw token, call `resolve`, and deliver renewed cookie expiry when `renewed` is `true`.

Hono applications should normally use `createHonoAuth`. `createHonoAdapter` remains available when deliberately composing the core and Hono adapter separately.

## Application responsibilities

The package does not provide:

- Registration, account lookup, OTP, OAuth, password reset, or email flows.
- Endpoints or UI components.
- Roles, permissions, or application authorization policies.
- Prisma migrations or database/Redis connection lifecycle.
- Trusted proxy policy.
- Rate limiting, CSRF, CORS, CSP, logging, or notifications.

The application must use HTTPS in production, protect login endpoints, validate input, prevent account enumeration, define trusted proxies, and apply CSRF and XSS protections.

Never log raw passwords, raw session tokens, cookies, password hashes, or Redis session payloads.

## Package exports

```text
@gauts/auth         createAuth, isAuthError, and core types
@gauts/auth/prisma  createDbAdapter and Prisma adapter types
@gauts/auth/redis   createRedisAdapter and Redis adapter types
@gauts/auth/hono    createHonoAuth, createHonoAdapter, and Hono types
```

The compiled Hono example is available in [`examples/hono`](./examples/hono).
