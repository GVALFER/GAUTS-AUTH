import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { resolveSessionConfig, type SessionValidation } from "../src/config.js";
import { isAuthError } from "../src/errors.js";
import { parseSession } from "../src/session/schema.js";
import { createSessionService } from "../src/session/service.js";
import { hashToken, tokenPattern } from "../src/session/token.js";
import type {
  CreateSessionRecord,
  DbAdapter,
  RedisAdapter,
  SessionRecord,
} from "../src/session/types.js";

type Data = {
  email: string;
  role: string;
};

const client = {
  agent: "Complete  User Agent",
  ip: "2001:0DB8:0:0:0:0:0:1",
  platform: '"macOS"',
};

const createRedis = () => {
  const values = new Map<string, string>();
  const ttls = new Map<string, number>();
  const calls = { create: 0, delete: 0, exists: 0, get: 0, update: 0 };
  const adapter: RedisAdapter = {
    create: async ({ token_hash, ttl, value }) => {
      calls.create += 1;
      if (values.has(token_hash)) throw new Error("collision");
      values.set(token_hash, value);
      ttls.set(token_hash, ttl);
    },
    delete: async (token_hashes) => {
      calls.delete += 1;
      for (const token_hash of token_hashes) {
        values.delete(token_hash);
        ttls.delete(token_hash);
      }
    },
    exists: async (token_hashes) => {
      calls.exists += 1;
      return token_hashes.map((token_hash) => values.has(token_hash));
    },
    get: async (token_hash) => {
      calls.get += 1;
      return values.get(token_hash) ?? null;
    },
    getMany: async (token_hashes) =>
      token_hashes.map((token_hash) => values.get(token_hash) ?? null),
    keep: async ({ token_hash, value }) => {
      if (!values.has(token_hash)) return false;
      values.set(token_hash, value);
      return true;
    },
    update: async ({ token_hash, ttl, value }) => {
      calls.update += 1;
      if (!values.has(token_hash)) return false;
      values.set(token_hash, value);
      ttls.set(token_hash, ttl);
      return true;
    },
  };

  return { adapter, calls, ttls, values };
};

const createDb = () => {
  const rows = new Map<string, SessionRecord>();
  const calls = { create: 0, findActive: 0, revoke: 0, updateExpiry: 0 };
  const adapter: DbAdapter = {
    create: async (input: CreateSessionRecord) => {
      calls.create += 1;
      rows.set(input.id, { ...input, revoked_at: null, updated_at: null });
    },
    find: async ({ account_id, session_id }) => {
      const row = rows.get(session_id);
      return row?.account_id === account_id ? row : null;
    },
    findActive: async ({ account_id, now }) => {
      calls.findActive += 1;
      return [...rows.values()].filter(
        (row) =>
          row.account_id === account_id &&
          row.revoked_at === null &&
          row.expires_at.getTime() > now.getTime(),
      );
    },
    revoke: async ({ revoked_at, session_ids }) => {
      calls.revoke += 1;
      for (const session_id of session_ids) {
        const row = rows.get(session_id);
        if (row) {
          rows.set(session_id, { ...row, revoked_at, updated_at: revoked_at });
        }
      }
    },
    updateExpiry: async ({ expires_at, session_id, updated_at }) => {
      calls.updateExpiry += 1;
      const row = rows.get(session_id);
      if (row) rows.set(session_id, { ...row, expires_at, updated_at });
    },
  };

  return { adapter, calls, rows };
};

const createHarness = (
  validation: readonly SessionValidation[] = ["agent"],
) => {
  let current = new Date("2026-08-15T12:00:00.000Z");
  const db = createDb();
  const redis = createRedis();
  const session = createSessionService<Data>({
    config: resolveSessionConfig({
      max: 2,
      renewInterval: 60,
      ttl: 300,
      validation,
    }),
    db: db.adapter,
    now: () => new Date(current),
    redis: redis.adapter,
  });

  return {
    db,
    redis,
    advance: (seconds: number) => {
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
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
    });
    const token_hash = hashToken(created.token);
    const stored = parseSession<Data>(
      harness.redis.values.get(token_hash) ?? "",
    );
    const row = harness.db.rows.get(created.session.id);

    assert.match(created.token, tokenPattern);
    assert.equal(token_hash.length, 64);
    assert.equal(harness.redis.values.has(created.token), false);
    assert.equal(row?.token_hash, token_hash);
    assert.equal(row?.ip, "2001:db8::1");
    assert.equal(row?.agent, client.agent);
    assert.equal(stored?.data.email, "owner@example.com");
    assert.equal(harness.redis.ttls.get(token_hash), 300);
  });

  it("authenticates from Redis without a database lookup", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
    });
    const findCalls = harness.db.calls.findActive;
    const resolved = await harness.session.resolve({
      client: { agent: client.agent, ip: "2001:db8::1" },
      token: created.token,
    });

    assert.equal(resolved?.renewed, false);
    assert.equal(resolved?.session.account_id, "account-1");
    assert.equal(harness.db.calls.findActive, findCalls);
    assert.equal(harness.db.calls.updateExpiry, 0);
  });

  it("renews the same session token after renewInterval without an absolute expiry", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
    });
    const originalExpiry = created.session.expires_at;

    harness.advance(61);
    const renewed = await harness.session.resolve({
      client,
      token: created.token,
    });

    assert.equal(renewed?.renewed, true);
    assert.ok(
      (renewed?.session.expires_at.getTime() ?? 0) > originalExpiry.getTime(),
    );
    assert.equal(harness.db.calls.updateExpiry, 1);
    assert.equal(harness.redis.calls.update, 1);

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
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
    });

    harness.advance(61);
    const validated = await harness.session.validate({
      client,
      token: created.token,
    });

    assert.equal(validated?.id, created.session.id);
    assert.equal(
      validated?.expires_at.getTime(),
      created.session.expires_at.getTime(),
    );
    assert.equal(harness.db.calls.updateExpiry, 0);
    assert.equal(harness.redis.calls.update, 0);

    const resolved = await harness.session.resolve({
      client,
      token: created.token,
    });

    assert.equal(resolved?.renewed, true);
  });

  it("revokes the backend session on configured client mismatch", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
    });
    assert.ok(
      await harness.session.resolve({
        client: { ...client, ip: "2001:db8::2" },
        token: created.token,
      }),
    );

    const second = await harness.session.create({
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
    });

    await assert.rejects(
      harness.session.resolve({
        client: { agent: "Stolen Token Agent", ip: client.ip },
        token: second.token,
      }),
      (error) => isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH",
    );
    assert.equal(harness.redis.values.has(hashToken(second.token)), false);
    assert.ok(harness.db.rows.get(second.session.id)?.revoked_at);

    const strict = createHarness(["ip", "agent"]);
    const strictSession = await strict.session.create({
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
    });

    await assert.rejects(
      strict.session.validate({
        client: { ...client, ip: "2001:db8::2" },
        token: strictSession.token,
      }),
      (error) => isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH",
    );
    assert.equal(
      strict.redis.values.has(hashToken(strictSession.token)),
      false,
    );
    assert.ok(strict.db.rows.get(strictSession.session.id)?.revoked_at);
  });

  it("deletes corrupt and expired Redis sessions", async () => {
    const harness = createHarness();
    const corruptToken = "a".repeat(43);
    const corruptHash = hashToken(corruptToken);
    harness.redis.values.set(corruptHash, "not-json");

    assert.equal(
      await harness.session.resolve({ client, token: corruptToken }),
      null,
    );
    assert.equal(harness.redis.values.has(corruptHash), false);

    const created = await harness.session.create({
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
    });
    harness.advance(301);

    assert.equal(
      await harness.session.resolve({ client, token: created.token }),
      null,
    );
    assert.equal(harness.redis.values.has(hashToken(created.token)), false);
  });

  it("lists, synchronizes and revokes active sessions", async () => {
    const harness = createHarness();
    const first = await harness.session.create({
      account_id: "account-1",
      client,
      data: { email: "old@example.com", role: "owner" },
    });
    const second = await harness.session.create({
      account_id: "account-1",
      client,
      data: { email: "old@example.com", role: "owner" },
    });

    assert.equal((await harness.session.list("account-1")).length, 2);
    await harness.session.sync({
      account_id: "account-1",
      data: { email: "new@example.com", role: "admin" },
    });

    const resolved = await harness.session.resolve({
      client,
      token: first.token,
    });
    assert.equal(resolved?.session.data.email, "new@example.com");

    assert.deepEqual(
      await harness.session.revoke({
        account_id: "account-1",
        session_id: first.session.id,
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
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
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
    assert.equal(harness.redis.calls.get, 0);
  });

  it("fails explicitly when Redis is unavailable", async () => {
    const harness = createHarness();
    const created = await harness.session.create({
      account_id: "account-1",
      client,
      data: { email: "owner@example.com", role: "owner" },
    });

    harness.redis.adapter.get = () => Promise.reject(new Error("offline"));

    await assert.rejects(
      harness.session.resolve({ client, token: created.token }),
      (error) => isAuthError(error) && error.code === "REDIS_UNAVAILABLE",
    );
  });

  it("fails explicitly when the database is unavailable", async () => {
    const harness = createHarness();
    harness.db.adapter.findActive = () => Promise.reject(new Error("offline"));

    await assert.rejects(
      harness.session.create({
        account_id: "account-1",
        client,
        data: { email: "owner@example.com", role: "owner" },
      }),
      (error) => isAuthError(error) && error.code === "DB_UNAVAILABLE",
    );
  });

  it("revokes the database record when Redis creation fails", async () => {
    const harness = createHarness();
    harness.redis.adapter.create = () => Promise.reject(new Error("offline"));

    await assert.rejects(
      harness.session.create({
        account_id: "account-1",
        client,
        data: { email: "owner@example.com", role: "owner" },
      }),
      (error) => isAuthError(error) && error.code === "REDIS_UNAVAILABLE",
    );

    const [row] = [...harness.db.rows.values()];
    assert.ok(row?.revoked_at);
  });
});
