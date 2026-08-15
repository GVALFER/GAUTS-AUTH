# `@gauts/auth`

Reusable password and opaque server-side session authentication for Node.js applications.

`@gauts/auth` validates sessions through Redis and records session history through an application-owned database adapter. It does not create endpoints, database models, users, or application authorization rules.

## Design

- Argon2id by default, with explicit bcrypt support.
- One stable 256-bit opaque browser token per session.
- SHA-256 token hashes in Redis and the session records database.
- Redis-authoritative authentication with no database fallback.
- Sliding inactivity expiration without an absolute lifetime.
- Configurable client validation, using the complete User-Agent by default.
- Framework integrations through explicit package exports.

## Installation

```bash
npm install @gauts/auth redis hono
```

## Setup

```ts
import type { SessionRecords } from "@gauts/auth";
import { createHonoAuth } from "@gauts/auth/hono";
import { createRedisStore } from "@gauts/auth/redis";

const records: SessionRecords = {
  create: (session) => db.sessions.create(session),
  find: ({ accountId, sessionId }) =>
    db.sessions.find({ accountId, sessionId }),
  findActive: ({ accountId, now }) =>
    db.sessions.findActive({ accountId, now }),
  revoke: ({ revokedAt, sessionIds }) =>
    db.sessions.revoke({ revokedAt, sessionIds }),
  updateExpiry: ({ expiresAt, sessionId, updatedAt }) =>
    db.sessions.updateExpiry({ expiresAt, sessionId, updatedAt }),
};

type AccountSession = {
  email: string;
  role: "owner" | "admin";
};

const auth = createHonoAuth<AccountSession>({
  getIp: (c) => getTrustedClientIp(c),
  redis: createRedisStore({ client: redis, config: { prefix: "my-app:auth" } }),
  records,
  session: {
    ttl: 60 * 60 * 24 * 7,
    renewInterval: 60 * 60 * 24,
    max: 10,
    validation: ["userAgent"],
  },
});
```

The application must obtain the client IP according to its own trusted-proxy configuration. The package canonicalizes the supplied IPv4 or IPv6 value but never decides which forwarding headers are trusted.

## Client information

The application supplies `getIp` because only its deployment knows which proxies and forwarding
headers are trusted. The Hono adapter reads User-Agent and platform directly from the request.

The resulting client information has this shape:

```ts
type SessionClientInput = {
  ip?: string | null;
  userAgent?: string | null;
  platform?: string | null;
};
```

- `validation` selects which client fields are compared on authenticated requests.
- `userAgent` is compared by default.
- `ip` and `platform` are always stored as session metadata, even when they are not compared.
- IPv4, IPv4-mapped IPv6, and IPv6 values are canonicalized by the package.
- Platform is unquoted, trimmed, and limited to 255 characters.
- User-Agent is stored and compared in full without truncation.

`getIp` runs during session creation and on every authenticated request. It should only resolve the
trusted request IP and must not perform unrelated account or database work.

## Passwords

Argon2id is the default:

```ts
const hash = await auth.password.hash(password);
const valid = await auth.password.verify({ password, storedHash: hash });
```

Applications whose database contains bcrypt hashes select bcrypt explicitly:

```ts
const auth = createHonoAuth({
  getIp: (c) => getTrustedClientIp(c),
  password: {
    algorithm: "bcrypt",
  },
  redis: createRedisStore({ client: redis }),
  records,
});
```

New bcrypt hashes reject passwords above 72 bytes. Applications with historical hashes created from longer bcrypt input can opt into a larger verification-only boundary without permitting new truncated hashes:

```ts
password: {
  algorithm: "bcrypt",
  maxBytes: 72,
  verifyMaxBytes: 1024,
}
```

The configured algorithm is used for both hashing and verification. The package does not detect, convert, migrate, or fall back to another algorithm.

## Login

The application owns the endpoint and account lookup:

```ts
app.post("/auth/login", async (c) => {
  const { email, password } = await c.req.json();
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

Applications must apply their own login rate limiting and account-enumeration protection.

## Protected routes

```ts
app.get("/account", auth.requireSession, async (c) => {
  const session = c.get("session");
  const account = c.get("account");

  return c.json({ account, sessionId: session.id });
});
```

The middleware reads the cookie, resolves Redis, compares the configured client fields, renews expiry when due, and places both the typed `session` and its `account` data in the Hono context. It does not load application data from the database.

## Logout

```ts
app.post("/auth/logout", async (c) => {
  await auth.revokeSession(c);
  return c.body(null, 204);
});
```

The adapter clears the cookie only after backend revocation succeeds. Infrastructure errors are
propagated so the application can return its own service-error response.

## Active sessions

```ts
const sessions = await auth.session.list(accountId);

await auth.session.revoke({
  accountId,
  sessionId,
});

await auth.session.revokeAccount(accountId);
```

The records database supplies session history. Redis is checked in a batch before a session is reported as active. Token hashes are never returned by `list`.

## Synchronizing session data

When cached session claims change:

```ts
await auth.session.sync({
  accountId,
  data: {
    email: account.email,
    role: account.role,
  },
});
```

Synchronization preserves the existing token and Redis TTL.

## Session records contract

Each consuming application maps `SessionRecords` to its database. The durable record contains:

- Session ID.
- Account ID and relation owned by the application.
- SHA-256 token hash.
- Canonical IP.
- Platform metadata.
- Complete User-Agent.
- Creation, current expiry, update, and revocation timestamps.

The database never stores the raw browser token.

## Expiration

Defaults:

```ts
session: {
  ttl: 7 * 24 * 60 * 60,
  renewInterval: 24 * 60 * 60,
  max: 10,
  validation: ["userAgent"],
}
```

- Inactive sessions expire after seven days.
- Active sessions renew at most once every 24 hours.
- Renewal keeps the same browser token.
- There is no absolute session lifetime.
- Every successful `resolve` call counts as HTTP activity and renews the session when due.

Consumers that cannot deliver `Set-Cookie`, such as WebSocket handshakes, validate without renewing:

```ts
const session = await auth.session.validate({
  client,
  token,
});
```

`validate` performs the same Redis, expiry, payload, and configured client-field checks as `resolve`. A client mismatch still revokes the backend session. It does not update `touchedAt`, Redis TTL, or the database expiry.

## Client validation

The default compares only the complete User-Agent:

```ts
session: {
  validation: ["userAgent"],
}
```

Applications can choose any combination of `ip`, `userAgent`, and `platform`:

```ts
session: {
  validation: ["ip", "userAgent", "platform"],
}
```

An empty array disables client-field comparison and validates only the session token. Unknown or duplicate fields are rejected during startup.

If a configured field differs, the package deletes the Redis session first and marks its database record as revoked. Clearing the response cookie is client cleanup; Redis deletion is what removes access.

Exact IP validation is opt-in because VPN, mobile, and other networks can change a legitimate user's public IP. Platform validation is also opt-in because the client-hint header may be absent. Client-field validation is defense in depth and does not replace TLS, secure cookies, CSRF protection, XSS prevention, or re-authentication for sensitive actions.

## Package exports

```text
@gauts/auth        createAuth and public core types
@gauts/auth/redis  createRedisStore
@gauts/auth/hono   createHonoAuth and createHonoAdapter
```
