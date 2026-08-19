import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { resolveSessionConfig } from "../src/config.js";
import { isAuthError } from "../src/errors.js";
import { createSessionState, parseSessionState } from "../src/session/state.js";
import type { ResolvedSession } from "../src/session/types.js";

const token = "a".repeat(43);
const secret = "s".repeat(32);
const client = {
    agent: "State Test",
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
        name: "Company",
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

const createState = ({ cache = true }: { cache?: boolean } = {}) => {
    let current = new Date("2026-08-17T10:00:00.000Z");
    const state = createSessionState<typeof account>({
        ...(cache ? { cache: { ttl: 60 } } : {}),
        now: () => new Date(current),
        secret,
        session: resolveSessionConfig({ validation: ["ip", "agent"] }),
    });

    return {
        advance: (seconds: number) => {
            current = new Date(current.getTime() + seconds * 1000);
        },
        state,
    };
};

describe("signed session context", () => {
    it("stores cache and renewal scheduling in one token bound to the session", () => {
        const { state } = createState();
        const cookie = state.create({ resolved, token });
        const separator = cookie.value.indexOf(".");

        assert.notEqual(separator, -1);

        const body = cookie.value.slice(0, separator);
        const payload: unknown = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));

        assert.equal(cookie.expires_at.toISOString(), "2026-08-17T11:00:00.000Z");
        assert.deepEqual(payload, {
            cache: {
                data: {
                    account: resolved.account,
                    session: {
                        client: resolved.session.client,
                        created: 1_786_960_800,
                        id: resolved.session.id,
                    },
                },
                exp: 1_786_960_860,
            },
            exp: 1_786_964_400,
            renew: 1_786_962_600,
        });
        assert.deepEqual(state.resolve({ client, token, value: cookie.value }), {
            cache: resolved,
            expires_at: resolved.session.expires_at,
            renew_at: resolved.session.renew_at,
        });
        assert.equal(state.resolve({ client, token: "b".repeat(43), value: cookie.value }), null);
    });

    it("rejects invalid renewal schedules", () => {
        const body = Buffer.from(
            JSON.stringify({ cache: null, exp: 100, renew: 101 }),
        ).toString("base64url");
        const invalid = `${body}.${"s".repeat(43)}`;

        assert.equal(parseSessionState(invalid), null);
    });

    it("keeps renewal scheduling after the short cache expires", () => {
        const harness = createState();
        const cookie = harness.state.create({ resolved, token });

        harness.advance(60);

        assert.deepEqual(harness.state.resolve({ client, token, value: cookie.value }), {
            cache: null,
            expires_at: resolved.session.expires_at,
            renew_at: resolved.session.renew_at,
        });
    });

    it("rejects altered signatures and never serves mismatched cached clients", () => {
        const harness = createState();
        const cookie = harness.state.create({ resolved, token });
        const altered = `${cookie.value.slice(0, -1)}x`;

        assert.equal(harness.state.resolve({ client, token, value: altered }), null);
        assert.deepEqual(
            harness.state.resolve({
                client: { ...client, ip: "192.0.2.11" },
                token,
                value: cookie.value,
            }),
            {
                cache: null,
                expires_at: resolved.session.expires_at,
                renew_at: resolved.session.renew_at,
            },
        );
    });

    it("creates a persistent scheduling token when cache is disabled", () => {
        const { state } = createState({ cache: false });
        const cookie = state.create({ resolved, token });

        assert.deepEqual(state.resolve({ client, token, value: cookie.value }), {
            cache: null,
            expires_at: resolved.session.expires_at,
            renew_at: resolved.session.renew_at,
        });
        assert.deepEqual(parseSessionState(cookie.value), {
            expires_at: resolved.session.expires_at,
            renew_at: resolved.session.renew_at,
        });
    });

    it("exposes an untrusted schedule without accepting it as cache", () => {
        const { state } = createState();
        const cookie = state.create({ resolved, token });
        const altered = `${cookie.value.slice(0, -1)}x`;

        assert.deepEqual(parseSessionState(altered), {
            expires_at: resolved.session.expires_at,
            renew_at: resolved.session.renew_at,
        });
        assert.equal(state.resolve({ client, token, value: altered }), null);
        assert.equal(parseSessionState("invalid"), null);
    });

    it("does not authenticate cache data beyond the configured maximum lifetime", () => {
        const now = () => new Date("2026-08-17T10:00:00.000Z");
        const old = createSessionState<typeof account>({
            cache: { ttl: 60 },
            now,
            secret,
            session: resolveSessionConfig({
                maxLifetime: 3_600,
                renewInterval: 60,
                ttl: 300,
                validation: ["ip", "agent"],
            }),
        });
        const current = createSessionState<typeof account>({
            cache: { ttl: 60 },
            now,
            secret,
            session: resolveSessionConfig({
                maxLifetime: 300,
                renewInterval: 60,
                ttl: 300,
                validation: ["ip", "agent"],
            }),
        });
        const cookie = old.create({ resolved, token });

        assert.deepEqual(current.resolve({ client, token, value: cookie.value }), {
            cache: null,
            expires_at: resolved.session.expires_at,
            renew_at: resolved.session.renew_at,
        });
    });

    it("fails fast on weak secrets and invalid cache TTL values", () => {
        const session = resolveSessionConfig();

        assert.throws(
            () => createSessionState({ secret: "weak", session }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => createSessionState({ cache: { ttl: 0 }, secret, session }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => createSessionState({ cache: { ttl: session.ttl + 1 }, secret, session }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
