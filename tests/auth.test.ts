import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createAuth } from "../src/auth.js";
import { isAuthError } from "../src/errors.js";
import type { RedisSessionStore, SessionRecords } from "../src/session/types.js";

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
});
