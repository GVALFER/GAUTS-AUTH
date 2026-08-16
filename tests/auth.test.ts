import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createAuth } from "../src/auth.js";
import { createHonoAuth } from "../src/adapters/hono/index.js";
import { resolveSessionConfig } from "../src/config.js";
import { isAuthError } from "../src/errors.js";
import type { DbAdapter, RedisAdapter } from "../src/session/types.js";

const db: DbAdapter = {
  create: () => Promise.resolve(),
  find: () => Promise.resolve(null),
  findActive: () => Promise.resolve([]),
  revoke: () => Promise.resolve(),
  updateExpiry: () => Promise.resolve(),
};

const redis: RedisAdapter = {
  create: () => Promise.resolve(),
  delete: () => Promise.resolve(),
  exists: () => Promise.resolve([]),
  get: () => Promise.resolve(null),
  getMany: () => Promise.resolve([]),
  keep: () => Promise.resolve(false),
  update: () => Promise.resolve(false),
};

describe("auth configuration", () => {
  it("creates an auth instance from valid adapters", () => {
    const auth = createAuth({ db, redis });

    assert.equal(auth.password.algorithm, "argon2id");
  });

  it("creates one Hono auth instance with core and HTTP methods", () => {
    const auth = createHonoAuth({
      db,
      getIp: () => null,
      redis,
    });

    assert.equal(auth.password.algorithm, "argon2id");
    assert.equal(typeof auth.session.resolve, "function");
    assert.equal(typeof auth.requireSession, "function");
    assert.equal(typeof auth.createSession, "function");
  });

  it("rejects incomplete adapters during startup", () => {
    assert.throws(
      () => createAuth({ db, redis: {} as RedisAdapter }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
    assert.throws(
      () => createAuth({ db: null as never, redis }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
  });

  it("validates session client fields during startup", () => {
    assert.deepEqual(resolveSessionConfig().validation, ["agent"]);
    assert.deepEqual(
      resolveSessionConfig({ validation: ["ip", "platform", "agent"] })
        .validation,
      ["ip", "platform", "agent"],
    );
    assert.deepEqual(resolveSessionConfig({ validation: [] }).validation, []);
    assert.throws(
      () => resolveSessionConfig({ validation: ["unknown"] as never }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
    assert.throws(
      () => resolveSessionConfig({ validation: ["ip", "ip"] }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
  });
});
