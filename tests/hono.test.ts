import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { Hono } from "hono";

import type { Auth } from "../src/auth.js";
import {
  createHonoAdapter,
  type HonoAuthEnv,
  type HonoAuthVariables,
} from "../src/adapters/hono/index.js";
import { createError, isAuthError } from "../src/errors.js";
import type { ResolvedSession, Session } from "../src/session/types.js";

type Data = {
  email: string;
};

const token = "a".repeat(43);
const expiresAt = new Date("2026-08-22T12:00:00.000Z");
const session: Session<Data> = {
  accountId: "account-1",
  client: {
    ip: "192.0.2.10",
    platform: "macOS",
    userAgent: "Hono Test",
  },
  createdAt: new Date("2026-08-15T12:00:00.000Z"),
  data: { email: "owner@example.com" },
  expiresAt,
  id: "session-1",
  touchedAt: new Date("2026-08-15T12:00:00.000Z"),
};

const createMockAuth = (
  resolve: (tokenValue: string) => Promise<ResolvedSession<Data> | null>,
): Auth<Data> => ({
  password: {
    algorithm: "argon2id",
    async hash() {
      return "hash";
    },
    async verify() {
      return true;
    },
  },
  session: {
    async create() {
      return { session, token };
    },
    async list() {
      return [];
    },
    async resolve(input) {
      return resolve(input.token);
    },
    async validate(input) {
      return (await resolve(input.token))?.session ?? null;
    },
    async revoke() {
      return [];
    },
    async revokeAccount() {
      return [];
    },
    async revokeToken() {
      return [];
    },
    sync: () => Promise.resolve(),
  },
});

const createApp = (auth: Auth<Data>) => {
  const adapter = createHonoAdapter({
    auth,
    cookie: {
      name: "session",
      secure: false,
    },
    getIp: (c) => c.req.header("x-forwarded-for"),
  });
  const app = new Hono<HonoAuthEnv<Data>>();

  app.onError((error, c) => {
    if (isAuthError(error)) {
      return c.json(
        { code: error.code },
        error.code === "SESSION_INVALID" ? 401 : 403,
      );
    }

    return c.json({ code: "INTERNAL" }, 500);
  });
  app.get("/protected", adapter.requireSession, (c) =>
    c.json({
      account: c.get("account"),
      accountId: c.get("session").accountId,
    }),
  );

  return { adapter, app };
};

describe("Hono adapter", () => {
  it("reads the cookie and exposes the resolved session", async () => {
    const { app } = createApp(
      createMockAuth(async () => ({ renewed: false, session })),
    );
    const response = await app.request("/protected", {
      headers: {
        Cookie: `session=${token}`,
        "User-Agent": "Hono Test",
        "X-Forwarded-For": "192.0.2.10",
      },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      account: session.data,
      accountId: "account-1",
    });
    assert.equal(response.headers.get("Set-Cookie"), null);
  });

  it("refreshes cookie expiry without changing the token", async () => {
    const { app } = createApp(
      createMockAuth(async () => ({ renewed: true, session })),
    );
    const response = await app.request("/protected", {
      headers: { Cookie: `session=${token}` },
    });
    const cookie = response.headers.get("Set-Cookie") ?? "";

    assert.equal(response.status, 200);
    assert.match(cookie, new RegExp(`^session=${token};`));
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Lax/);
    assert.match(cookie, /Expires=/);
  });

  it("resolves sessions for applications with additional context variables", async () => {
    type AppEnv = {
      Variables: HonoAuthVariables<Data> & {
        account: Data;
      };
    };

    const { adapter } = createApp(
      createMockAuth(async () => ({ renewed: false, session })),
    );
    const app = new Hono<AppEnv>();

    app.get(
      "/account",
      async (c, next) => {
        const resolved = await adapter.resolveSession(c);

        c.set("session", resolved);
        c.set("account", resolved.data);
        await next();
      },
      (c) => c.json(c.get("account")),
    );

    const response = await app.request("/account", {
      headers: { Cookie: `session=${token}` },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), session.data);
  });

  it("clears invalid and mismatched sessions", async () => {
    const invalid = createApp(createMockAuth(async () => null));
    const invalidResponse = await invalid.app.request("/protected", {
      headers: { Cookie: `session=${token}` },
    });

    assert.equal(invalidResponse.status, 401);
    assert.match(invalidResponse.headers.get("Set-Cookie") ?? "", /^session=;/);

    const mismatch = createApp(
      createMockAuth(async () => {
        throw createError({
          code: "SESSION_CLIENT_MISMATCH",
          message: "Mismatch.",
        });
      }),
    );
    const mismatchResponse = await mismatch.app.request("/protected", {
      headers: { Cookie: `session=${token}` },
    });

    assert.equal(mismatchResponse.status, 403);
    assert.match(
      mismatchResponse.headers.get("Set-Cookie") ?? "",
      /^session=;/,
    );
  });

  it("creates and revokes browser sessions without exposing token wiring", async () => {
    const auth = createMockAuth(async () => ({ renewed: false, session }));
    auth.session.create = async (input) => {
      assert.deepEqual(input, {
        accountId: session.accountId,
        client: {
          ip: "192.0.2.10",
          platform: '"macOS"',
          userAgent: "Hono Test",
        },
        data: session.data,
      });

      return { session, token };
    };
    auth.session.revokeToken = async (value) => {
      assert.equal(value, token);
      return [session.id];
    };

    const { adapter } = createApp(auth);
    const setApp = new Hono();

    setApp.get("/set", async (c) => {
      const created = await adapter.createSession({
        accountId: session.accountId,
        context: c,
        data: session.data,
      });

      return c.json({ sessionId: created.id });
    });
    setApp.get("/revoke", async (c) => {
      const revoked = await adapter.revokeSession(c);

      return c.json({ revoked });
    });

    const setResponse = await setApp.request("/set", {
      headers: {
        "Sec-CH-UA-Platform": '"macOS"',
        "User-Agent": "Hono Test",
        "X-Forwarded-For": "192.0.2.10",
      },
    });
    const revokeResponse = await setApp.request("/revoke", {
      headers: { Cookie: `session=${token}` },
    });

    assert.deepEqual(await setResponse.json(), { sessionId: session.id });
    assert.match(
      setResponse.headers.get("Set-Cookie") ?? "",
      new RegExp(`^session=${token};`),
    );
    assert.deepEqual(await revokeResponse.json(), { revoked: [session.id] });
    assert.match(revokeResponse.headers.get("Set-Cookie") ?? "", /^session=;/);
  });

  it("keeps the browser cookie when backend revocation fails", async () => {
    const auth = createMockAuth(async () => ({ renewed: false, session }));
    auth.session.revokeToken = async () => {
      throw createError({ code: "REDIS_UNAVAILABLE", message: "Offline." });
    };

    const { adapter } = createApp(auth);
    const app = new Hono();

    app.onError((_error, c) => c.body(null, 503));
    app.get("/revoke", async (c) => {
      await adapter.revokeSession(c);
      return c.body(null, 204);
    });

    const response = await app.request("/revoke", {
      headers: { Cookie: `session=${token}` },
    });

    assert.equal(response.status, 503);
    assert.equal(response.headers.get("Set-Cookie"), null);
  });

  it("validates secure cookie prefixes at startup", () => {
    const auth = createMockAuth(async () => ({ renewed: false, session }));

    assert.throws(
      () => createHonoAdapter({ auth, getIp: null as never }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
    assert.throws(
      () =>
        createHonoAdapter({
          auth,
          cookie: { name: "__Host-session", secure: false },
          getIp: () => null,
        }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
  });
});
