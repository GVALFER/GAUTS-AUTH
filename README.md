# `@gauts/auth`

Reusable password and opaque server-side session authentication for Node.js applications.

`@gauts/auth` validates sessions through Redis and stores durable session records through an application-owned database adapter. It does not create endpoints, database models, user accounts, or application authorization rules.

## Requirements

- Node.js 22 or newer.
- A connected Redis client when using `@gauts/auth/redis`.
- Hono 4 when using `@gauts/auth/hono`.
- An implementation of the `SessionActions` contract.

## Installation

For a Hono application using the official Redis adapter:

```bash
npm install @gauts/auth hono redis
```

`hono` and `redis` are optional peer dependencies. Install only the integrations used by the application.

## How it works

Login:

```text
password -> configured password algorithm -> account accepted
         -> database session record created
         -> Redis session created
         -> opaque token written to an HttpOnly cookie
```

Authenticated HTTP request:

```text
cookie -> token hash -> Redis session -> client validation -> application route
                                      -> renewal due -> database expiry updated
                                                     -> Redis TTL updated
                                                     -> cookie expiry updated
```

Redis is the sole authority for authentication. The database keeps durable login metadata, expiry, and revocation history, but is never used as an authentication fallback.

The browser receives one random 256-bit opaque token. The token remains stable for the session; normal activity renews its expiry without rotating it. Redis and the database receive only its SHA-256 hash.

## Quick start with Hono

### 1. Define the session data

The generic passed to `createHonoAuth` defines the application data stored in Redis and exposed on authenticated requests. Keep it small and never include secrets or password hashes.

```ts
type AccountSession = {
  email: string;
  role: "admin" | "owner";
};
```

### 2. Implement the session actions

Import `SessionActions` so TypeScript shows every required function and types all arguments:

```ts
import type { SessionActions } from "@gauts/auth";

export const sessionActions = {
  create: async (session) => {
    await db.sessions.create({
      accountId: session.accountId,
      client: session.client,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      id: session.id,
      tokenHash: session.tokenHash,
    });
  },

  find: ({ accountId, sessionId }) => {
    return db.sessions.find({ accountId, sessionId });
  },

  findActive: ({ accountId, now }) => {
    return db.sessions.findActive({
      accountId,
      expiresAfter: now,
      revoked: false,
    });
  },

  revoke: async ({ revokedAt, sessionIds }) => {
    await db.sessions.revoke({ revokedAt, sessionIds });
  },

  updateExpiry: async ({ expiresAt, sessionId, updatedAt }) => {
    await db.sessions.updateExpiry({ expiresAt, sessionId, updatedAt });
  },
} satisfies SessionActions;
```

`db.sessions` represents the consuming application's ORM or query layer. See [Session actions](#session-actions) for the complete contract and database requirements.

### 3. Create one auth instance

```ts
import { createHonoAuth } from "@gauts/auth/hono";
import { createRedisStore } from "@gauts/auth/redis";

export const auth = createHonoAuth<AccountSession>({
  actions: sessionActions,
  getIp: (c) => getTrustedClientIp(c),
  redis: createRedisStore({
    client: redis,
    config: { prefix: "my-app:auth" },
  }),
});
```

The Redis client must already be connected. The package does not create, connect, reconnect, or close it.

### 4. Type the Hono application

```ts
import { Hono } from "hono";
import type { HonoAuthEnv } from "@gauts/auth/hono";

const app = new Hono<HonoAuthEnv<AccountSession>>();
```

This types both values installed by `auth.requireSession`:

```ts
const session = c.get("session");
const account = c.get("account");
```

### 5. Create the login endpoint

The application owns input validation, account lookup, rate limiting, account status checks, and the error response.

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
      storedHash: account.passwordHash,
    }))
  ) {
    return c.json({ error: "Invalid credentials." }, 401);
  }

  const session = await auth.createSession({
    accountId: account.id,
    context: c,
    data: {
      email: account.email,
      role: account.role,
    },
  });

  return c.json({ account: session.data });
});
```

`createSession` creates the database record, creates the Redis session, sets the cookie, and returns the public session data. The raw token is handled internally by the Hono adapter.

### 6. Protect routes

```ts
app.get("/account", auth.requireSession, async (c) => {
  return c.json({
    account: c.get("account"),
    sessionId: c.get("session").id,
  });
});
```

`requireSession` reads the cookie, validates Redis and the configured client fields, renews the session when due, and sets `session` and `account` in the Hono context. It authenticates the request but does not apply application-specific role or permission rules.

### 7. Create the logout endpoint

```ts
app.post("/auth/logout", async (c) => {
  await auth.revokeSession(c);
  return c.body(null, 204);
});
```

`revokeSession` removes the Redis session, records the revocation in the database, and clears the browser cookie. Backend revocation is what removes access; clearing the cookie is client cleanup.

## Configuration reference

### `createHonoAuth`

```ts
const auth = createHonoAuth<AccountSession>({
  actions: sessionActions,
  getIp,
  password,
  session,
  redis,
  cookie,
});
```

| Property   | Required | Purpose                                                                   |
| ---------- | -------- | ------------------------------------------------------------------------- |
| `getIp`    | Yes      | Returns the trusted client IP from the Hono context.                      |
| `redis`    | Yes      | Implements authoritative Redis session storage.                           |
| `actions`  | Yes      | Implements the required session persistence functions.                    |
| `password` | No       | Selects the password algorithm and its cost limits. Defaults to Argon2id. |
| `session`  | No       | Configures expiry, renewal, maximum sessions, and client validation.      |
| `cookie`   | No       | Configures the Hono session cookie.                                       |

Configuration is resolved once when the application creates the auth instance. Invalid configuration throws `AUTH_CONFIG_INVALID` during startup.

### Password configuration

Argon2id is the default:

```ts
password: {
  algorithm: "argon2id",
}
```

| Argon2id property |      Default |         Allowed values | Purpose                                                            |
| ----------------- | -----------: | ---------------------: | ------------------------------------------------------------------ |
| `algorithm`       | `"argon2id"` |           `"argon2id"` | Selects Argon2id. The property may be omitted.                     |
| `hashLength`      |         `32` |           `16` to `64` | Hash output length in bytes.                                       |
| `maxBytes`        |       `1024` |     `1` to `1,048,576` | Maximum UTF-8 password size accepted for hashing and verification. |
| `memoryCost`      |     `65,536` | `8,192` to `1,048,576` | Argon2 memory cost in KiB.                                         |
| `parallelism`     |          `4` |            `1` to `16` | Number of Argon2 lanes.                                            |
| `timeCost`        |          `3` |            `1` to `10` | Number of Argon2 iterations.                                       |

Applications with existing bcrypt hashes must select bcrypt explicitly:

```ts
password: {
  algorithm: "bcrypt",
}
```

| bcrypt property  |  Default |            Allowed values | Purpose                                           |
| ---------------- | -------: | ------------------------: | ------------------------------------------------- |
| `algorithm`      | Required |                `"bcrypt"` | Selects bcrypt for both hashing and verification. |
| `maxBytes`       |     `72` |               `1` to `72` | Maximum UTF-8 size accepted when creating a hash. |
| `rounds`         |     `12` |               `4` to `31` | bcrypt cost factor.                               |
| `verifyMaxBytes` |     `72` | `maxBytes` to `1,048,576` | Maximum UTF-8 size accepted during verification.  |

Keep `verifyMaxBytes` at `72` unless the application has consciously chosen to preserve historical bcrypt truncation behaviour. bcrypt ignores bytes after the first 72, so accepting longer verification input can allow a valid password with an arbitrary suffix to authenticate.

The configured algorithm is used for both hashing and verification. The package never detects hash algorithms, migrates hashes, rehashes passwords, or falls back to a different algorithm.

### Session configuration

```ts
session: {
  max: 10,
  renewInterval: 24 * 60 * 60,
  ttl: 7 * 24 * 60 * 60,
  validation: ["userAgent"],
}
```

All time values are seconds.

| Property        |         Default |                                              Allowed values | Purpose                                                                               |
| --------------- | --------------: | ----------------------------------------------------------: | ------------------------------------------------------------------------------------- |
| `max`           |            `10` |                                             `1` to `10,000` | Maximum number of active Redis sessions per account.                                  |
| `renewInterval` |        `86,400` |                                            `1` to `ttl - 1` | Minimum activity interval between expiry renewals.                                    |
| `ttl`           |       `604,800` |                                        `60` to `31,536,000` | Inactivity lifetime assigned on creation and renewal.                                 |
| `validation`    | `["userAgent"]` | Any unique combination of `ip`, `userAgent`, and `platform` | Client fields compared on every validation. An empty array disables field comparison. |

Session expiry is sliding and has no absolute lifetime. Activity before `renewInterval` validates the session without writing Redis, the database, or the cookie. Activity after `renewInterval` extends expiry by `ttl` and updates all three.

### Cookie configuration

```ts
cookie: {
  domain: undefined,
  name: "__Host-session",
  path: "/",
  sameSite: "Lax",
  secure: true,
}
```

| Property   | Default            | Purpose                                                      |
| ---------- | ------------------ | ------------------------------------------------------------ |
| `name`     | `"__Host-session"` | Cookie name.                                                 |
| `domain`   | Not set            | Optional cookie domain. Without it, the cookie is host-only. |
| `path`     | `"/"`              | Cookie path.                                                 |
| `sameSite` | `"Lax"`            | `"Strict"`, `"Lax"`, or `"None"`.                            |
| `secure`   | `true`             | Sends the cookie only over HTTPS when enabled.               |

`HttpOnly` is always enabled and cannot be disabled.

Cookie constraints are validated during startup:

- `__Host-` names require `secure: true`, `path: "/"`, and no `domain`.
- `__Secure-` names require `secure: true`.
- `SameSite=None` requires `secure: true`.
- Local HTTP development that sets `secure: false` must use a custom cookie name without `__Host-` or `__Secure-`.

### Redis adapter

```ts
import { createClient } from "redis";
import { createRedisStore } from "@gauts/auth/redis";

const redis = createClient({ url: process.env.REDIS_URL });
await redis.connect();

const store = createRedisStore({
  client: redis,
  config: { prefix: "my-app:auth" },
});
```

The prefix defaults to `gauts:auth`. It may contain letters, numbers, `:`, `_`, and `-`, with a maximum length of 128 characters. Session keys use this format:

```text
<prefix>:session:<sha256-token-hash>
```

The package stores the session payload as the Redis value and manages its TTL. Redis failures throw `REDIS_UNAVAILABLE`; the database is never consulted to authenticate around a Redis failure.

### Trusted client IP

```ts
getIp: (c) => getTrustedClientIp(c);
```

`getIp` runs during session creation and every authenticated HTTP request. It may be synchronous or asynchronous and must return `string`, `null`, or `undefined`.

Only the application knows which reverse proxies and forwarding headers are trusted. The package therefore does not select `X-Forwarded-For`, `CF-Connecting-IP`, socket addresses, or any other source. It only canonicalizes the supplied value.

The Hono adapter obtains the remaining client fields directly from request headers:

```ts
type SessionClientInput = {
  ip?: string | null;
  platform?: string | null;
  userAgent?: string | null;
};
```

- IPv4, IPv4-mapped IPv6, and IPv6 values are canonicalized.
- `::1` is normalized to `127.0.0.1`.
- Invalid or empty IP values become `null`.
- Platform comes from `Sec-CH-UA-Platform`, is unquoted and trimmed, and is limited to 255 characters.
- User-Agent comes from `User-Agent` and is stored in full without truncation.
- No GeoIP, DNS, country, or database lookup is performed.

## Session actions

Every application must implement this exported contract:

```ts
import type {
  CreateSessionRecord,
  SessionActions,
  SessionRecord,
} from "@gauts/auth";

type SessionActions = {
  create(session: CreateSessionRecord): Promise<void>;

  find(input: {
    accountId: string;
    sessionId: string;
  }): Promise<SessionRecord | null>;

  findActive(input: { accountId: string; now: Date }): Promise<SessionRecord[]>;

  revoke(input: { revokedAt: Date; sessionIds: string[] }): Promise<void>;

  updateExpiry(input: {
    expiresAt: Date;
    sessionId: string;
    updatedAt: Date;
  }): Promise<void>;
};
```

Use `satisfies SessionActions` on the object. TypeScript then suggests all required functions, types their parameters, rejects missing methods, and preserves the concrete implementation types.

### Record shape

```ts
type SessionRecord = {
  accountId: string;
  client: {
    ip: string | null;
    platform: string | null;
    userAgent: string | null;
  };
  createdAt: Date;
  expiresAt: Date;
  id: string;
  revokedAt: Date | null;
  tokenHash: string;
  updatedAt: Date | null;
};
```

`CreateSessionRecord` contains the same fields except `revokedAt` and `updatedAt`, which should initially be `null` or use the database defaults.

### `actions.create(session)`

Called once during login before Redis is created.

It must:

- Insert one durable session record.
- Preserve the provided session `id`.
- Store `accountId`, client metadata, dates, and `tokenHash` exactly as supplied.
- Never store a raw browser token.
- Reject duplicate session IDs or token hashes.

If Redis creation subsequently fails, the package calls `actions.revoke` for this new session as compensation.

### `actions.find({ accountId, sessionId })`

Called when revoking one selected session.

It must:

- Find by both `accountId` and `sessionId`.
- Return the complete `SessionRecord` when it belongs to that account.
- Return `null` when it does not exist or belongs to a different account.

The account condition prevents one account from revoking another account's session by guessing its ID.

### `actions.findActive({ accountId, now })`

Called when:

- Enforcing the maximum session count during login.
- Listing active sessions.
- Revoking all sessions for an account.
- Synchronizing cached session data.

It should query records where:

```text
accountId = input.accountId
revokedAt IS NULL
expiresAt > input.now
```

Return complete `SessionRecord` objects, including `tokenHash`. The package filters the result defensively and then checks Redis in a batch. A database record is reported as active only when its Redis key also exists.

### `actions.revoke({ revokedAt, sessionIds })`

Called after Redis deletion for explicit revocation and client-field mismatch. It is also used to compensate for failed Redis creation.

It must:

- Set `revokedAt` for every supplied session ID.
- Set `updatedAt` to the same timestamp when the schema has that field.
- Perform no work when `sessionIds` is empty.
- Be safe when a record was already revoked.

Do not delete the historical database row. Revocation history is one of the reasons the record exists.

### `actions.updateExpiry({ expiresAt, sessionId, updatedAt })`

Called only when an active HTTP session reaches `renewInterval`.

It must update:

- `expiresAt` to the newly calculated sliding expiry.
- `updatedAt` to the renewal time.

It must not create a new session, rotate the token hash, clear client metadata, or change `createdAt`.

### Recommended database constraints

- Primary key on `id`.
- Unique constraint on `tokenHash` stored as 64 hexadecimal characters.
- Index on `accountId`.
- Index on `expiresAt`.
- Index on `revokedAt`.
- A field large enough to store the complete User-Agent, such as `TEXT`.
- A field capable of storing canonical IPv4 and IPv6 values.
- An application-owned account relation when appropriate.

The database stores session history only. It does not need the Redis payload or session `data` object.

## Password API

### `auth.password.algorithm`

The resolved algorithm: `"argon2id"` or `"bcrypt"`.

### `auth.password.hash(password)`

Validates the UTF-8 byte length and returns a new hash using the configured algorithm and cost values.

```ts
const passwordHash = await auth.password.hash(password);
```

### `auth.password.verify({ password, storedHash })`

Validates the password input and verifies it only with the configured algorithm. A hash from a different algorithm or with an invalid format returns `false`.

```ts
const valid = await auth.password.verify({
  password,
  storedHash: account.passwordHash,
});
```

Invalid password size throws `PASSWORD_INPUT_INVALID`. Wrong credentials return `false`.

## Hono API

`createHonoAuth` returns the password and session core APIs together with these Hono methods.

### `auth.createSession({ accountId, context, data })`

Creates the database and Redis session, writes the HttpOnly cookie, and returns `Session<TData>`. Use this after the application has validated login credentials and account status.

### `auth.resolveSession(context)`

Reads and validates the request cookie and returns `Session<TData>`.

- Throws `SESSION_INVALID` when the cookie or Redis session is missing or invalid.
- Clears the cookie when the session is invalid.
- Compares configured client fields.
- Renews Redis, database expiry, and cookie expiry only when due.
- Throws `SESSION_CLIENT_MISMATCH` and clears the cookie after a mismatch revokes the backend session.

Most protected routes should use `requireSession` instead of calling this directly.

### `auth.requireSession`

Hono middleware that calls `resolveSession` and sets:

```ts
c.set("session", session);
c.set("account", session.data);
```

It does not load an account from the database and does not enforce roles or permissions.

### `auth.revokeSession(context)`

Revokes the session represented by the request cookie and clears that cookie. Returns the revoked session IDs. If no cookie exists, it clears any matching cookie state and returns an empty array.

### `auth.clearSession(context)`

Deletes only the response cookie. It does not revoke Redis or update the database. Do not use it as a logout replacement.

### `auth.getToken(context)`

Returns the raw cookie token or `null`. This is useful for non-HTTP integrations that must call the core API. Never log, persist, or return this value to application code in a response.

## Core session API

The same `auth` instance exposes `auth.session`. These methods are framework-independent.

### `auth.session.create({ accountId, client, data })`

Creates a database and Redis session and returns:

```ts
{
  session: Session<TData>;
  token: string;
}
```

The raw token is returned because the framework-independent core cannot set a cookie. Prefer `auth.createSession` in Hono applications.

### `auth.session.resolve({ client, token })`

Validates a session and performs sliding renewal when due. Returns `null` for an invalid or expired session, otherwise:

```ts
{
  renewed: boolean;
  session: Session<TData>;
}
```

When using the core directly, the caller is responsible for updating the browser cookie expiry when `renewed` is `true`. The Hono adapter handles this automatically.

### `auth.session.validate({ client, token })`

Performs Redis, expiry, payload, and configured client-field validation without renewing the session. It returns `Session<TData>` or `null`.

Use it for consumers that cannot send `Set-Cookie`, such as an established WebSocket connection:

```ts
const session = await auth.session.validate({
  client: {
    ip,
    platform,
    userAgent,
  },
  token,
});
```

A client mismatch still revokes the backend session. `validate` does not update `touchedAt`, Redis TTL, database expiry, or cookie expiry.

### `auth.session.list(accountId)`

Returns sessions that are active in both the database and Redis. The result contains login metadata but never exposes `tokenHash`.

```ts
const sessions = await auth.session.list(accountId);
```

### `auth.session.revoke({ accountId, sessionId })`

Revokes one session after confirming it belongs to the supplied account. Returns the revoked session IDs and throws `SESSION_NOT_FOUND` when it is missing or already revoked.

```ts
await auth.session.revoke({ accountId, sessionId });
```

### `auth.session.revokeAccount(accountId)`

Revokes every currently active session for an account and returns their IDs.

```ts
await auth.session.revokeAccount(accountId);
```

### `auth.session.revokeToken(token)`

Revokes the session represented by one raw token and returns its ID. Invalid or absent Redis tokens return an empty array. Framework adapters use this method for logout.

### `auth.session.sync({ accountId, data })`

Replaces the cached `data` object in every active Redis session for the account while preserving tokens and TTLs.

```ts
await auth.session.sync({
  accountId: account.id,
  data: {
    email: account.email,
    role: account.role,
  },
});
```

Use it after changing session data such as an email address, display name, or role. If a change must force re-authentication, use `revokeAccount` instead.

## Active sessions

An account session page normally uses:

```ts
const sessions = await auth.session.list(accountId);

await auth.session.revoke({
  accountId,
  sessionId,
});
```

Each active session contains:

```ts
type ActiveSession = {
  accountId: string;
  client: SessionClient;
  createdAt: Date;
  expiresAt: Date;
  id: string;
  revokedAt: Date | null;
  updatedAt: Date | null;
};
```

The database supplies durable metadata; Redis existence determines whether the session can currently authenticate.

## Client validation

The default compares the complete User-Agent:

```ts
session: {
  validation: ["userAgent"],
}
```

Applications can select any unique combination:

```ts
session: {
  validation: ["ip", "userAgent", "platform"],
}
```

An empty array validates only the opaque session token:

```ts
session: {
  validation: [],
}
```

Comparison is exact after normalization. If a configured field differs, the package deletes the Redis session and records its revocation. The current and legitimate browser can no longer use that token and must authenticate again.

Exact IP validation is opt-in because VPN, mobile, and other networks can change a legitimate user's public IP. Platform validation is also opt-in because the client-hint header may be absent. Client-field validation is defense in depth and does not replace TLS, secure cookies, CSRF protection, XSS prevention, or re-authentication for sensitive operations.

## Expiration and renewal

- A newly created session receives the configured `ttl` in Redis, the database, and the cookie.
- Requests before `renewInterval` perform read-only Redis validation.
- The first eligible HTTP request after `renewInterval` sets expiry to `now + ttl` in the database and Redis.
- The Hono adapter sends `Set-Cookie` only when this renewal occurs.
- The opaque browser token does not change.
- Continued eligible HTTP activity can keep the session alive indefinitely.
- A session with no renewal activity expires after `ttl`.
- `validate` never renews; `resolve` renews only when due.

## Errors

All package errors have `name: "AuthError"` and a typed `code`. Use `isAuthError` instead of matching error messages.

```ts
import { isAuthError } from "@gauts/auth";

app.onError((error, c) => {
  if (!isAuthError(error)) {
    return c.json({ error: "Internal server error." }, 500);
  }

  if (
    error.code === "REDIS_UNAVAILABLE" ||
    error.code === "SESSION_ACTION_FAILED"
  ) {
    return c.json({ error: "Authentication service unavailable." }, 503);
  }

  return c.json({ error: error.message }, 401);
});
```

| Code                      | Meaning                                                                          |
| ------------------------- | -------------------------------------------------------------------------------- |
| `AUTH_CONFIG_INVALID`     | Invalid startup configuration or adapter contract.                               |
| `PASSWORD_INPUT_INVALID`  | Password is empty or exceeds the configured UTF-8 byte limit.                    |
| `SESSION_CLIENT_MISMATCH` | A configured client field changed; the backend session was revoked.              |
| `SESSION_DATA_INVALID`    | Required session input or stored session data is invalid.                        |
| `SESSION_INVALID`         | Hono cookie or Redis session is missing, expired, or invalid.                    |
| `SESSION_LIMIT_REACHED`   | The account already has the configured maximum active sessions.                  |
| `SESSION_NOT_FOUND`       | The selected account session does not exist or is already revoked.               |
| `REDIS_UNAVAILABLE`       | Redis failed or returned structurally invalid data. Authentication fails closed. |
| `SESSION_ACTION_FAILED`   | One of the injected session actions failed.                                      |

Applications decide the final HTTP status and public message. Avoid exposing infrastructure details or whether a particular account exists.

## Framework-independent usage

Use `createAuth` when the application does not use Hono or wants to build a different framework adapter:

```ts
import { createAuth } from "@gauts/auth";
import { createRedisStore } from "@gauts/auth/redis";

const auth = createAuth<AccountSession>({
  actions: sessionActions,
  redis: createRedisStore({ client: redis }),
});
```

The application must then:

- Extract and normalize the trusted client input.
- Read the raw token from its request mechanism.
- Call `auth.session.resolve` for renewable HTTP activity.
- Deliver the renewed cookie expiry when `renewed` is `true`.
- Call `auth.session.validate` for read-only consumers.
- Set, clear, and secure cookies itself.

Hono applications should normally use the composed `createHonoAuth` factory. `createHonoAdapter` remains available when an application deliberately creates the core and framework adapter separately.

## Application responsibilities

The package does not provide:

- Registration, account lookup, OTP, OAuth, password reset, or email flows.
- Hono endpoints or UI components.
- Application roles, permissions, or authorization policies.
- Prisma schemas, migrations, or database connections.
- Redis connection lifecycle.
- Trusted proxy policy or automatic forwarding-header selection.
- Rate limiting, CSRF, CORS, CSP, request logging, or audit notifications.

The consuming application must use HTTPS in production, protect login endpoints, validate request input, prevent account enumeration, define trusted proxies, apply CSRF and XSS protections, and require explicit re-authentication for sensitive operations when appropriate.

Never log raw passwords, raw session tokens, cookies, password hashes, or Redis session payloads.

## Package exports

```text
@gauts/auth        createAuth, isAuthError, and public core types
@gauts/auth/redis  createRedisStore and Redis adapter types
@gauts/auth/hono   createHonoAuth, createHonoAdapter, and Hono types
```

The complete compiled Hono example is available in [`examples/hono`](./examples/hono).
