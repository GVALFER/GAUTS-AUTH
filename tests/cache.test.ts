import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { resolveSessionConfig } from "../src/config.js";
import { isAuthError } from "../src/errors.js";
import { createSessionCache } from "../src/session/cache.js";
import type { ResolvedSession } from "../src/session/types.js";

const token = "a".repeat(43);
const secret = "s".repeat(32);
const client = {
    agent: "Cache Test",
    ip: "192.0.2.10",
    platform: "macOS",
};
const account = {
    email: "owner@example.com",
    id: "account-1",
    name: "Owner",
    role: "OWNER",
    status: "ACTIVE",
    timezone: "Europe/Lisbon",
    user: {
        id: "user-1",
        role: "ADMIN",
        status: "ACTIVE",
    },
} as const;

const resolved: ResolvedSession<typeof account> = {
    account,
    session: {
        account_id: "account-1",
        client,
        created_at: new Date("2026-08-17T10:00:00.000Z"),
        expires_at: new Date("2026-08-17T11:00:00.000Z"),
        id: "session-1",
        renew_at: new Date("2026-08-17T10:30:00.000Z"),
    },
};

const createCache = () => {
    let current = new Date("2026-08-17T10:00:00.000Z");
    const cache = createSessionCache({
        config: { ttl: 60 },
        now: () => new Date(current),
        secret,
        session: resolveSessionConfig({ validation: ["ip", "agent"] }),
    });

    return {
        advance: (seconds: number) => {
            current = new Date(current.getTime() + seconds * 1000);
        },
        cache,
    };
};

describe("signed session cache", () => {
    it("resolves an authentic cache bound to the token and client", () => {
        const { cache } = createCache();
        const cached = cache.create({ resolved, token });
        const separator = cached.value.indexOf(".");

        assert.notEqual(separator, -1);

        const body = cached.value.slice(0, separator);
        const payload: unknown = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));

        assert.equal(cached.expires_at.toISOString(), "2026-08-17T10:01:00.000Z");
        assert.deepEqual(payload, {
            acc: {
                email: resolved.account.email,
                id: resolved.account.id,
                name: resolved.account.name,
                role: resolved.account.role,
                status: resolved.account.status,
                timezone: resolved.account.timezone,
                user: resolved.account.user,
            },
            exp: cached.expires_at.getTime(),
            ses: {
                client: resolved.session.client,
                created_at: resolved.session.created_at.getTime(),
                exp: resolved.session.expires_at.getTime(),
                id: resolved.session.id,
                ren: resolved.session.renew_at.getTime(),
            },
        });
        assert.deepEqual(cache.resolve({ client, token, value: cached.value }), resolved);
        assert.equal(
            cache.resolve({ client, token: "b".repeat(43), value: cached.value }),
            null,
        );
    });

    it("rejects expired, altered, and mismatched cache values", () => {
        const harness = createCache();
        const cached = harness.cache.create({ resolved, token });
        const altered = `${cached.value.slice(0, -1)}x`;

        assert.equal(harness.cache.resolve({ client, token, value: altered }), null);
        assert.equal(
            harness.cache.resolve({
                client: { ...client, ip: "192.0.2.11" },
                token,
                value: cached.value,
            }),
            null,
        );

        harness.advance(60);
        assert.equal(harness.cache.resolve({ client, token, value: cached.value }), null);
    });

    it("rejects cache data beyond the configured maximum lifetime", () => {
        const now = () => new Date("2026-08-17T10:00:00.000Z");
        const old = createSessionCache({
            config: { ttl: 60 },
            now,
            secret,
            session: resolveSessionConfig({
                maxLifetime: 3_600,
                renewInterval: 60,
                ttl: 300,
                validation: ["ip", "agent"],
            }),
        });
        const current = createSessionCache({
            config: { ttl: 60 },
            now,
            secret,
            session: resolveSessionConfig({
                maxLifetime: 300,
                renewInterval: 60,
                ttl: 300,
                validation: ["ip", "agent"],
            }),
        });
        const cached = old.create({ resolved, token });

        assert.equal(current.resolve({ client, token, value: cached.value }), null);
    });

    it("fails fast on weak secrets and invalid TTL values", () => {
        const session = resolveSessionConfig();

        assert.throws(
            () => createSessionCache({ config: { ttl: 60 }, secret: "weak", session }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => createSessionCache({ config: { ttl: 0 }, secret, session }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => createSessionCache({ config: { ttl: session.ttl + 1 }, secret, session }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
