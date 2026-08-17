import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createHonoAuth } from "../src/adapters/hono/index.js";
import { createAuth } from "../src/auth.js";
import { resolveSessionConfig } from "../src/config.js";
import { isAuthError } from "../src/errors.js";
import type { DbAdapter } from "../src/session/types.js";

const db: DbAdapter = {
    create: () => Promise.resolve(),
    find: () => Promise.resolve(null),
    findActive: () => Promise.resolve([]),
    findToken: () => Promise.resolve(null),
    revoke: () => Promise.resolve(),
    updateExpiry: () => Promise.resolve(),
};

describe("auth configuration", () => {
    it("creates an auth instance from a valid database adapter", () => {
        const auth = createAuth({ db });

        assert.equal(auth.password.algorithm, "argon2id");
    });

    it("creates one Hono auth instance with core and HTTP methods", () => {
        const auth = createHonoAuth({
            cache: { ttl: 60 },
            db,
            getIp: () => null,
            secret: "s".repeat(32),
        });

        assert.equal(auth.password.algorithm, "argon2id");
        assert.equal(typeof auth.session.resolve, "function");
        assert.equal(typeof auth.requireSession, "function");
        assert.equal(typeof auth.renewSession, "function");
    });

    it("rejects incomplete adapters during startup", () => {
        assert.throws(
            () => createAuth({ db: {} as DbAdapter }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => createAuth({ db: null as never }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });

    it("validates session client fields during startup", () => {
        assert.equal(resolveSessionConfig().maxLifetime, 30 * 24 * 60 * 60);
        assert.deepEqual(resolveSessionConfig().validation, ["agent"]);
        assert.deepEqual(
            resolveSessionConfig({ validation: ["ip", "platform", "agent"] }).validation,
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
        assert.throws(
            () => resolveSessionConfig({ maxLifetime: 299, ttl: 300 }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
