import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createAuth } from "../src/auth.js";
import { createHonoAuth } from "../src/adapters/hono/index.js";
import { resolveSessionConfig } from "../src/config.js";
import { isAuthError } from "../src/errors.js";
import type {
  RedisSessionStore,
  SessionRecords,
} from "../src/session/types.js";

const records: SessionRecords = {
  create: () => Promise.resolve(),
  find: () => Promise.resolve(null),
  findActive: () => Promise.resolve([]),
  revoke: () => Promise.resolve(),
  updateExpiry: () => Promise.resolve(),
};

const redis: RedisSessionStore = {
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
    const auth = createAuth({ records, redis });

    assert.equal(auth.password.algorithm, "argon2id");
  });

  it("creates one Hono auth instance with core and HTTP methods", () => {
    const auth = createHonoAuth({
      getIp: () => null,
      records,
      redis,
    });

    assert.equal(auth.password.algorithm, "argon2id");
    assert.equal(typeof auth.session.resolve, "function");
    assert.equal(typeof auth.requireSession, "function");
    assert.equal(typeof auth.createSession, "function");
  });

  it("rejects incomplete adapters during startup", () => {
    assert.throws(
      () => createAuth({ records, redis: {} as RedisSessionStore }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
    assert.throws(
      () => createAuth({ records: null as never, redis }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
  });

  it("validates session client fields during startup", () => {
    assert.deepEqual(resolveSessionConfig().validation, ["userAgent"]);
    assert.deepEqual(
      resolveSessionConfig({ validation: ["ip", "platform", "userAgent"] })
        .validation,
      ["ip", "platform", "userAgent"],
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
