import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { Hono } from "hono";

import type { Auth } from "../src/auth.js";
import {
    createHonoAdapter,
    type HonoAuthEnv,
} from "../src/adapters/hono/index.js";
import { createError, isAuthError } from "../src/errors.js";
import { createSessionCookie } from "../src/session/cookie.js";
import type {
    AuthAccount,
    RenewedSession,
    ResolvedSession,
    Session,
} from "../src/session/types.js";

const token = "a".repeat(43);
const account: AuthAccount = {
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
};
const user = account.user;
const session: Session = {
    account_id: account.id,
    client: {
        agent: "Hono Test",
        ip: "192.0.2.10",
        platform: "macOS",
    },
    created_at: new Date("2026-08-15T12:00:00.000Z"),
    expires_at: new Date("2026-08-22T12:00:00.000Z"),
    id: "session-1",
    renew_at: new Date("2026-08-16T12:00:00.000Z"),
};
const resolved: ResolvedSession = { account, session, user };
const cookie = createSessionCookie({ renew_at: session.renew_at, token });

const createMockAuth = (
    resolve: (tokenValue: string) => Promise<ResolvedSession | null>,
): Auth => ({
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
        async renew(input): Promise<RenewedSession | null> {
            const value = await resolve(input.token);
            return value ? { renewed: true, session: value.session } : null;
        },
        async resolve(input) {
            return resolve(input.token);
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
    },
});

const createApp = ({ auth }: { auth: Auth }) => {
    const adapter = createHonoAdapter({
        auth,
        cookie: {
            name: "session",
            secure: false,
        },
        getIp: (c) => c.req.header("x-forwarded-for"),
    });
    const app = new Hono<HonoAuthEnv>();

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
            accountId: c.get("session").account_id,
            user: c.get("user"),
        }),
    );
    app.post("/renew", async (c) => {
        await adapter.renewSession(c);
        return c.body(null, 204);
    });

    return { adapter, app };
};

describe("Hono adapter", () => {
    it("reads token.renewAt without writing a cookie during resolution", async () => {
        const { app } = createApp({
            auth: createMockAuth(async () => resolved),
        });
        const response = await app.request("/protected", {
            headers: {
                Cookie: `session=${cookie}`,
                "User-Agent": "Hono Test",
                "X-Forwarded-For": "192.0.2.10",
            },
        });

        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            account,
            accountId: "account-1",
            user,
        });
        assert.equal(response.headers.get("Set-Cookie"), null);
    });

    it("renews the cookie only through renewSession", async () => {
        const auth = createMockAuth(async () => resolved);
        let renewCalls = 0;
        auth.session.renew = async (input) => {
            renewCalls += 1;
            assert.equal(input.token, token);
            return { renewed: true, session };
        };
        const { app } = createApp({ auth });
        const response = await app.request("/renew", {
            method: "POST",
            headers: { Cookie: `session=${cookie}` },
        });
        const value = response.headers.get("Set-Cookie") ?? "";

        assert.equal(response.status, 204);
        assert.equal(renewCalls, 1);
        assert.match(value, new RegExp(`^session=${cookie};`));
        assert.match(value, /HttpOnly/);
        assert.match(value, /SameSite=Lax/);
        assert.match(value, /Expires=/);
    });

    it("clears malformed, invalid, and mismatched sessions", async () => {
        const malformed = createApp({
            auth: createMockAuth(async () => resolved),
        });
        const malformedResponse = await malformed.app.request("/protected", {
            headers: { Cookie: `session=${token}` },
        });
        assert.equal(malformedResponse.status, 401);
        assert.match(malformedResponse.headers.get("Set-Cookie") ?? "", /^session=;/);

        const invalid = createApp({ auth: createMockAuth(async () => null) });
        const invalidResponse = await invalid.app.request("/protected", {
            headers: { Cookie: `session=${cookie}` },
        });
        assert.equal(invalidResponse.status, 401);
        assert.match(invalidResponse.headers.get("Set-Cookie") ?? "", /^session=;/);

        const mismatch = createApp({
            auth: createMockAuth(async () => {
                throw createError({
                    code: "SESSION_CLIENT_MISMATCH",
                    message: "Mismatch.",
                });
            }),
        });
        const mismatchResponse = await mismatch.app.request("/protected", {
            headers: { Cookie: `session=${cookie}` },
        });
        assert.equal(mismatchResponse.status, 403);
        assert.match(mismatchResponse.headers.get("Set-Cookie") ?? "", /^session=;/);
    });

    it("creates and revokes browser sessions without exposing token wiring", async () => {
        const auth = createMockAuth(async () => resolved);
        auth.session.create = async (input) => {
            assert.deepEqual(input, {
                account_id: account.id,
                client: {
                    agent: "Hono Test",
                    ip: "192.0.2.10",
                    platform: '"macOS"',
                },
            });
            return { session, token };
        };
        auth.session.revokeToken = async (value) => {
            assert.equal(value, token);
            return [session.id];
        };

        const { adapter } = createApp({ auth });
        const app = new Hono();

        app.get("/set", async (c) => {
            const created = await adapter.createSession({
                account_id: account.id,
                context: c,
            });
            return c.json({ account_id: created.account_id });
        });
        app.get("/revoke", async (c) => {
            const revoked = await adapter.revokeSession(c);
            return c.json({ revoked });
        });

        const setResponse = await app.request("/set", {
            headers: {
                "Sec-CH-UA-Platform": '"macOS"',
                "User-Agent": "Hono Test",
                "X-Forwarded-For": "192.0.2.10",
            },
        });
        const revokeResponse = await app.request("/revoke", {
            headers: { Cookie: `session=${cookie}` },
        });

        assert.deepEqual(await setResponse.json(), {
            account_id: account.id,
        });
        assert.match(
            setResponse.headers.get("Set-Cookie") ?? "",
            new RegExp(`^session=${cookie};`),
        );
        assert.deepEqual(await revokeResponse.json(), { revoked: [session.id] });
        assert.match(revokeResponse.headers.get("Set-Cookie") ?? "", /^session=;/);
    });

    it("keeps the browser cookie when database revocation fails", async () => {
        const auth = createMockAuth(async () => resolved);
        auth.session.revokeToken = async () => {
            throw createError({ code: "DB_UNAVAILABLE", message: "Offline." });
        };
        const { adapter } = createApp({ auth });
        const app = new Hono();

        app.onError((_error, c) => c.body(null, 503));
        app.get("/revoke", async (c) => {
            await adapter.revokeSession(c);
            return c.body(null, 204);
        });

        const response = await app.request("/revoke", {
            headers: { Cookie: `session=${cookie}` },
        });

        assert.equal(response.status, 503);
        assert.equal(response.headers.get("Set-Cookie"), null);
    });

    it("validates the IP callback and secure cookie prefixes", () => {
        const auth = createMockAuth(async () => resolved);

        assert.throws(
            () =>
                createHonoAdapter({
                    auth,
                    getIp: null as never,
                }),
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
