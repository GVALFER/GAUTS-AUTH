import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { resolveSessionConfig, type SessionValidation } from "../src/config.js";
import { isAuthError } from "../src/errors.js";
import { parseSession } from "../src/session/schema.js";
import { createSessionService } from "../src/session/service.js";
import { hashToken, tokenPattern } from "../src/session/token.js";
import type {
  CreateSessionRecord,
  RedisSessionStore,
  SessionActions,
  SessionRecord,
} from "../src/session/types.js";

type Data = {
  email: string;
  role: string;
};

const client = {
  ip: "2001:0DB8:0:0:0:0:0:1",
  platform: '"macOS"',
  userAgent: "Complete  User Agent",
};

const createRedis = () => {
  const values = new Map<string, string>();
  const ttls = new Map<string, number>();
  const calls = { create: 0, delete: 0, exists: 0, get: 0, update: 0 };
  const store: RedisSessionStore = {
    async create({ tokenHash, ttl, value }) {
      calls.create += 1;
      if (values.has(tokenHash)) throw new Error("collision");
      values.set(tokenHash, value);
      ttls.set(tokenHash, ttl);
    },
    async delete(tokenHashes) {
      calls.delete += 1;
      for (const tokenHash of tokenHashes) {
        values.delete(tokenHash);
        ttls.delete(tokenHash);
      }
    },
    async exists(tokenHashes) {
      calls.exists += 1;
      return tokenHashes.map((tokenHash) => values.has(tokenHash));
    },
    async get(tokenHash) {
      calls.get += 1;
      return values.get(tokenHash) ?? null;
    },
    async getMany(tokenHashes) {
      return tokenHashes.map((tokenHash) => values.get(tokenHash) ?? null);
    },
    async keep({ tokenHash, value }) {
      if (!values.has(tokenHash)) return false;
      values.set(tokenHash, value);
      return true;
    },
    async update({ tokenHash, ttl, value }) {
      calls.update += 1;
      if (!values.has(tokenHash)) return false;
      values.set(tokenHash, value);
      ttls.set(tokenHash, ttl);
      return true;
    },
  };

  return { redisCalls: calls, store, ttls, values };
};

const createActions = () => {
  const rows = new Map<string, SessionRecord>();
  const calls = { create: 0, findActive: 0, revoke: 0, updateExpiry: 0 };
  const actions: SessionActions = {
    async create(input: CreateSessionRecord) {
      calls.create += 1;
      rows.set(input.id, { ...input, revokedAt: null, updatedAt: null });
    },
    async find({ accountId, sessionId }) {
      const row = rows.get(sessionId);
      return row?.accountId === accountId ? row : null;
    },
    async findActive({ accountId, now }) {
      calls.findActive += 1;
      return [...rows.values()].filter(
        (row) =>
          row.accountId === accountId &&
          row.revokedAt === null &&
          row.expiresAt.getTime() > now.getTime(),
      );
    },
    async revoke({ revokedAt, sessionIds }) {
      calls.revoke += 1;
      for (const sessionId of sessionIds) {
        const row = rows.get(sessionId);
        if (row)
          rows.set(sessionId, { ...row, revokedAt, updatedAt: revokedAt });
      }
    },
    async updateExpiry({ expiresAt, sessionId, updatedAt }) {
      calls.updateExpiry += 1;
      const row = rows.get(sessionId);
      if (row) rows.set(sessionId, { ...row, expiresAt, updatedAt });
    },
  };

  return { actionCalls: calls, actions, rows };
};

const createHarness = (
  validation: readonly SessionValidation[] = ["userAgent"],
) => {
  let current = new Date("2026-08-15T12:00:00.000Z");
  const redis = createRedis();
  const sessionActions = createActions();
  const session = createSessionService<Data>({
    actions: sessionActions.actions,
    config: resolveSessionConfig({
      max: 2,
      renewInterval: 60,
      ttl: 300,
      validation,
    }),
    now: () => new Date(current),
    redis: redis.store,
  });

  return {
    ...redis,
    ...sessionActions,
    advance(seconds: number) {
      current = new Date(current.getTime() + seconds * 1000);
    },
    now: () => new Date(current),
    session,
  };
};

describe("session service", () => {
  it("creates an opaque Redis session and a database record", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    });
    const tokenHash = hashToken(created.token);
    const stored = parseSession<Data>(harness.values.get(tokenHash) ?? "");
    const row = harness.rows.get(created.session.id);

    assert.match(created.token, tokenPattern);
    assert.equal(tokenHash.length, 64);
    assert.equal(harness.values.has(created.token), false);
    assert.equal(row?.tokenHash, tokenHash);
    assert.equal(row?.client.ip, "2001:db8::1");
    assert.equal(row?.client.userAgent, client.userAgent);
    assert.equal(stored?.data.email, "owner@example.com");
    assert.equal(harness.ttls.get(tokenHash), 300);
  });

  it("authenticates from Redis without a session action lookup", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    });
    const findCalls = harness.actionCalls.findActive;
    const resolved = await harness.session.resolve({
      client: { ip: "2001:db8::1", userAgent: client.userAgent },
      token: created.token,
    });

    assert.equal(resolved?.renewed, false);
    assert.equal(resolved?.session.accountId, "account-1");
    assert.equal(harness.actionCalls.findActive, findCalls);
    assert.equal(harness.actionCalls.updateExpiry, 0);
  });

  it("renews the same session token after renewInterval without an absolute expiry", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    });
    const originalExpiry = created.session.expiresAt;

    harness.advance(61);
    const renewed = await harness.session.resolve({
      client,
      token: created.token,
    });

    assert.equal(renewed?.renewed, true);
    assert.ok(
      (renewed?.session.expiresAt.getTime() ?? 0) > originalExpiry.getTime(),
    );
    assert.equal(harness.actionCalls.updateExpiry, 1);
    assert.equal(harness.redisCalls.update, 1);

    harness.advance(240);
    const renewedAgain = await harness.session.resolve({
      client,
      token: created.token,
    });

    assert.equal(renewedAgain?.renewed, true);
    assert.match(created.token, tokenPattern);
  });

  it("validates without renewing an elapsed session", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    });

    harness.advance(61);
    const validated = await harness.session.validate({
      client,
      token: created.token,
    });

    assert.equal(validated?.id, created.session.id);
    assert.equal(
      validated?.expiresAt.getTime(),
      created.session.expiresAt.getTime(),
    );
    assert.equal(harness.actionCalls.updateExpiry, 0);
    assert.equal(harness.redisCalls.update, 0);

    const resolved = await harness.session.resolve({
      client,
      token: created.token,
    });

    assert.equal(resolved?.renewed, true);
  });

  it("revokes the backend session on configured client mismatch", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    });
    assert.ok(
      await harness.session.resolve({
        client: { ...client, ip: "2001:db8::2" },
        token: created.token,
      }),
    );

    const second = await harness.session.create({
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    });

    await assert.rejects(
      harness.session.resolve({
        client: { ip: client.ip, userAgent: "Stolen Token Agent" },
        token: second.token,
      }),
      (error) => isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH",
    );
    assert.equal(harness.values.has(hashToken(second.token)), false);
    assert.ok(harness.rows.get(second.session.id)?.revokedAt);

    const strict = createHarness(["ip", "userAgent"]);
    const strictSession = await strict.session.create({
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    });

    await assert.rejects(
      strict.session.validate({
        client: { ...client, ip: "2001:db8::2" },
        token: strictSession.token,
      }),
      (error) => isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH",
    );
    assert.equal(strict.values.has(hashToken(strictSession.token)), false);
    assert.ok(strict.rows.get(strictSession.session.id)?.revokedAt);
  });

  it("deletes corrupt and expired Redis sessions", async () => {
    const harness = createHarness();
    const corruptToken = "a".repeat(43);
    const corruptHash = hashToken(corruptToken);
    harness.values.set(corruptHash, "not-json");

    assert.equal(
      await harness.session.resolve({ client, token: corruptToken }),
      null,
    );
    assert.equal(harness.values.has(corruptHash), false);

    const created = await harness.session.create({
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    });
    harness.advance(301);

    assert.equal(
      await harness.session.resolve({ client, token: created.token }),
      null,
    );
    assert.equal(harness.values.has(hashToken(created.token)), false);
  });

  it("lists, synchronizes and revokes active sessions", async () => {
    const harness = createHarness();
    const first = await harness.session.create({
      client,
      data: { email: "old@example.com", role: "owner" },
      accountId: "account-1",
    });
    const second = await harness.session.create({
      client,
      data: { email: "old@example.com", role: "owner" },
      accountId: "account-1",
    });

    assert.equal((await harness.session.list("account-1")).length, 2);
    await harness.session.sync({
      data: { email: "new@example.com", role: "admin" },
      accountId: "account-1",
    });

    const resolved = await harness.session.resolve({
      client,
      token: first.token,
    });
    assert.equal(resolved?.session.data.email, "new@example.com");

    assert.deepEqual(
      await harness.session.revoke({
        sessionId: first.session.id,
        accountId: "account-1",
      }),
      [first.session.id],
    );
    assert.deepEqual(await harness.session.revokeAccount("account-1"), [
      second.session.id,
    ]);
    assert.equal((await harness.session.list("account-1")).length, 0);
  });

  it("enforces the active-session limit", async () => {
    const harness = createHarness();
    const input = {
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    };

    await harness.session.create(input);
    await harness.session.create(input);
    await assert.rejects(
      harness.session.create(input),
      (error) => isAuthError(error) && error.code === "SESSION_LIMIT_REACHED",
    );
  });

  it("does not access Redis for malformed tokens", async () => {
    const harness = createHarness();

    assert.equal(
      await harness.session.resolve({ client, token: "invalid" }),
      null,
    );
    assert.equal(harness.redisCalls.get, 0);
  });

  it("fails explicitly when Redis is unavailable", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      client,
      data: { email: "owner@example.com", role: "owner" },
      accountId: "account-1",
    });

    harness.store.get = () => Promise.reject(new Error("offline"));

    await assert.rejects(
      harness.session.resolve({ client, token: created.token }),
      (error) => isAuthError(error) && error.code === "REDIS_UNAVAILABLE",
    );
  });

  it("revokes the database record when Redis creation fails", async () => {
    const harness = createHarness();
    harness.store.create = () => Promise.reject(new Error("offline"));

    await assert.rejects(
      harness.session.create({
        client,
        data: { email: "owner@example.com", role: "owner" },
        accountId: "account-1",
      }),
      (error) => isAuthError(error) && error.code === "REDIS_UNAVAILABLE",
    );

    const [row] = [...harness.rows.values()];
    assert.ok(row?.revokedAt);
  });
});
