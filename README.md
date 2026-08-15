# `@gauts/auth`

Reusable password and opaque server-side session authentication for Node.js applications.

`@gauts/auth` validates sessions through Redis and records session history through an application-owned database adapter. It does not create endpoints, database models, users, or application authorization rules.

The package is under active development and has not been published yet.

## Design

- Argon2id by default, with explicit bcrypt support.
- One stable 256-bit opaque browser token per session.
- SHA-256 token hashes in Redis and the session records database.
- Redis-authoritative authentication with no database fallback.
- Sliding inactivity expiration without an absolute lifetime.
- Exact canonical IP and complete User-Agent session binding.
- Framework integrations through explicit package exports.

## Installation

```bash
npm install @gauts/auth redis hono
```

The package is not on npm yet. During local development, use the tarball produced by `npm pack`.

## Setup

```ts
import {
  createAuth,
  type SessionClientInput,
  type SessionRecords,
} from "@gauts/auth";
import { createHonoAdapter } from "@gauts/auth/hono";
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

const auth = createAuth<AccountSession>({
  redis: createRedisStore({ client: redis, config: { prefix: "my-app:auth" } }),
  records,
  session: {
    ttl: 60 * 60 * 24 * 7,
    touchAfter: 60 * 60 * 24,
    max: 10,
  },
});

const getClient = async (c): Promise<SessionClientInput> => ({
  ip: getTrustedClientIp(c),
  userAgent: c.req.header("user-agent") ?? null,
  country: await getCountryCode(c),
  platform: c.req.header("sec-ch-ua-platform") ?? null,
});

const hono = createHonoAdapter({ auth, getClient });
```

The application must obtain the client IP according to its own trusted-proxy configuration. The package canonicalizes the supplied IPv4 or IPv6 value but never decides which forwarding headers are trusted.

## Client information

The Hono adapter calls `getClient` during session creation and on every authenticated request. The
function receives the current Hono `Context` and returns these four values:

```ts
type SessionClientInput = {
  ip?: string | null;
  userAgent?: string | null;
  country?: string | null;
  platform?: string | null;
};
```

- `ip` and `userAgent` form the session identity and are compared on authenticated requests.
- `country` and `platform` are stored as session metadata for history and display.
- IPv4, IPv4-mapped IPv6, and IPv6 values are canonicalized by the package.
- Country is normalized to a two-letter uppercase code or `null`.
- Platform is unquoted, trimmed, and limited to 255 characters.
- User-Agent is stored and compared in full without truncation.

The application extracts the raw values because trusted proxies, GeoIP sources, and request headers
are deployment-specific. `getClient` should remain request-focused and should not perform unrelated
account or database work.

## Passwords

Argon2id is the default:

```ts
const hash = await auth.password.hash(password);
const valid = await auth.password.verify({ password, storedHash: hash });
```

Applications whose database contains bcrypt hashes select bcrypt explicitly:

```ts
const auth = createAuth({
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

  const session = await hono.createSession({
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
app.get("/account", hono.requireSession, async (c) => {
  const session = c.get("session");
  const account = await findAccountById(session.accountId);

  return c.json({ account });
});
```

The middleware reads the cookie, resolves Redis, compares IP and User-Agent, renews expiry when due, and places the typed session in the Hono context. It does not load application data from the database.

Applications that need to populate additional Hono context variables can resolve through the same adapter without duplicating its cookie behavior:

```ts
const requireAccount = async (c, next) => {
  const session = await hono.resolveSession(c);

  c.set("account", session.data);
  await next();
};
```

## Logout

```ts
app.post("/auth/logout", async (c) => {
  await hono.revokeSession(c);
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
- Country and platform metadata.
- Complete User-Agent.
- Creation, current expiry, update, and revocation timestamps.

The database never stores the raw browser token.

## Expiration

Defaults:

```ts
session: {
  ttl: 7 * 24 * 60 * 60,
  touchAfter: 24 * 60 * 60,
  max: 10,
}
```

- Inactive sessions expire after seven days.
- Active sessions renew at most once every 24 hours.
- Renewal keeps the same browser token.
- There is no absolute session lifetime.
- Every successful `resolve` call counts as activity and renews the session when due.

## Client mismatch

If the canonical IP or complete User-Agent differs, the package deletes the Redis session first and marks its database record as revoked. Clearing the response cookie is client cleanup; Redis deletion is what removes access.

Strict IP binding can log out legitimate users whose public IP changes. It is defense in depth and does not replace TLS, secure cookies, CSRF protection, XSS prevention, or re-authentication for sensitive actions.

## Package exports

```text
@gauts/auth        createAuth and public core types
@gauts/auth/redis  createRedisStore
@gauts/auth/hono   createHonoAdapter
```
