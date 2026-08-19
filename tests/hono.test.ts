import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hono } from "hono";
import { createHonoAdapter, type HonoAuthEnv } from "../src/adapters/hono/index.js";
import type { Auth } from "../src/auth.js";
import { createError, isAuthError } from "../src/errors.js";
import type { RenewedSession, ResolvedSession, Session } from "../src/session/types.js";

const token = "a".repeat(43);
const secret = "s".repeat(32);
const testNow = Date.now();

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

const session: Session = {
    account_id: account.id,
    client: {
        agent: "Hono Test",
        ip: "192.0.2.10",
        platform: "macOS",
    },
    created_at: new Date(testNow),
    expires_at: new Date(testNow + 7 * 24 * 60 * 60 * 1000),
    id: "session-1",
    renew_at: new Date(testNow + 24 * 60 * 60 * 1000),
};

const resolved: ResolvedSession<typeof account> = { account, session };
const renewAt = Math.floor(session.renew_at.getTime() / 1000).toString();

const getSetCookies = (response: Response): string[] => {
    const headers = response.headers as Headers & { getSetCookie?: () => string[] };
    const values = headers.getSetCookie?.();

    if (values?.length) {
        return values;
    }

    const value = response.headers.get("set-cookie");
    return value ? [value] : [];
};

const getCookiePair = (response: Response, name: string): string | null => {
    const value = getSetCookies(response).find((cookie) => cookie.startsWith(`${name}=`));
    return value?.split(";", 1)[0] ?? null;
};

const createMockAuth = (
    resolve: (tokenValue: string) => Promise<ResolvedSession<typeof account> | null>,
): Auth<typeof account> => ({
    config: {
        session: {
            maxLifetime: 30 * 24 * 60 * 60,
            renewInterval: 24 * 60 * 60,
            ttl: 7 * 24 * 60 * 60,
            validation: ["ip", "agent"],
        },
    },
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
            return { account, session, token };
        },
        async list() {
            return [];
        },
        async renew(input): Promise<RenewedSession<typeof account> | null> {
            const value = await resolve(input.token);
            return value ? { ...value, renewed: true } : null;
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

const withoutIpValidation = (auth: Auth<typeof account>): Auth<typeof account> => ({
    ...auth,
    config: {
        session: {
            ...auth.config.session,
            validation: ["agent"],
        },
    },
});

const createApp = ({ auth, cache = false }: { auth: Auth<typeof account>; cache?: boolean }) => {
    const adapter = createHonoAdapter({
        auth,
        cookie: {
            cacheName: "session-cache",
            renewName: "session-renew",
            secure: false,
            sessionName: "session",
        },
        getIp: (c) => c.req.header("x-forwarded-for"),
        ...(cache
            ? {
                  cache: { ttl: 60 },
                  secret,
              }
            : {}),
    });
    const app = new Hono<HonoAuthEnv>();

    app.onError((error, c) => {
        if (isAuthError(error)) {
            return c.json({ code: error.code }, error.code === "SESSION_INVALID" ? 401 : 403);
        }

        return c.json({ code: "INTERNAL" }, 500);
    });
    app.get("/protected", adapter.requireSession, (c) =>
        c.json({
            account: c.get("account"),
            accountId: c.get("session").account_id,
        }),
    );
    app.post("/protected", adapter.requireSession, (c) => c.body(null, 204));
    app.post("/renew", async (c) => {
        await adapter.renewSession(c);
        return c.body(null, 204);
    });

    return { adapter, app };
};

const identityHeaders = {
    "Sec-CH-UA-Platform": "macOS",
    "User-Agent": "Hono Test",
    "X-Forwarded-For": "192.0.2.10",
};

describe("Hono adapter", () => {
    it("exposes the resolved cookie names", () => {
        const auth = createMockAuth(async () => resolved);
        const defaults = createHonoAdapter({ auth: withoutIpValidation(auth) });
        const { adapter } = createApp({ auth });

        assert.deepEqual(defaults.cookie, {
            cacheName: "__cac",
            renewName: "__ren",
            sessionName: "__ses",
        });
        assert.deepEqual(adapter.cookie, {
            cacheName: "session-cache",
            renewName: "session-renew",
            sessionName: "session",
        });
    });

    it("uses a null IP when getIp is omitted", async () => {
        const auth = withoutIpValidation(createMockAuth(async () => resolved));
        let client: unknown;

        auth.session.resolve = async (input) => {
            client = input.client;
            return resolved;
        };

        const adapter = createHonoAdapter({ auth });
        const app = new Hono();

        app.get("/protected", adapter.requireSession, (c) => c.body(null, 204));

        const response = await app.request("/protected", {
            headers: {
                Cookie: `__ses=${token}`,
                ...identityHeaders,
            },
        });

        assert.equal(response.status, 204);
        assert.deepEqual(client, {
            agent: "Hono Test",
            ip: null,
            platform: "macOS",
        });
    });

    it("resolves through the database without cookie writes when cache is disabled", async () => {
        const { app } = createApp({
            auth: createMockAuth(async () => resolved),
        });
        const response = await app.request("/protected", {
            headers: {
                Cookie: `session=${token}`,
                ...identityHeaders,
            },
        });

        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            account,
            accountId: "account-1",
        });
        assert.deepEqual(getSetCookies(response), []);
    });

    it("serves safe requests from a valid signed cache", async () => {
        let resolveCalls = 0;
        const auth = createMockAuth(async () => {
            resolveCalls += 1;
            return resolved;
        });
        const { app } = createApp({ auth, cache: true });
        const first = await app.request("/protected", {
            headers: { Cookie: `session=${token}`, ...identityHeaders },
        });
        const cached = getCookiePair(first, "session-cache");

        assert.equal(first.status, 200);
        assert.ok(cached);
        assert.equal(resolveCalls, 1);

        const second = await app.request("/protected", {
            headers: {
                Cookie: `session=${token}; ${cached}; session-renew=${renewAt}`,
                ...identityHeaders,
            },
        });

        assert.equal(second.status, 200);
        assert.equal(resolveCalls, 1);
        assert.deepEqual(getSetCookies(second), []);
    });

    it("limits stale revocation data to safe cached requests", async () => {
        let active = true;
        let resolveCalls = 0;
        const auth = createMockAuth(async () => {
            resolveCalls += 1;
            return active ? resolved : null;
        });
        const { app } = createApp({ auth, cache: true });
        const first = await app.request("/protected", {
            headers: { Cookie: `session=${token}`, ...identityHeaders },
        });
        const cached = getCookiePair(first, "session-cache");

        assert.ok(cached);
        active = false;

        const safe = await app.request("/protected", {
            headers: {
                Cookie: `session=${token}; ${cached}`,
                ...identityHeaders,
            },
        });
        const unsafe = await app.request("/protected", {
            method: "POST",
            headers: {
                Cookie: `session=${token}; ${cached}`,
                ...identityHeaders,
            },
        });

        assert.equal(safe.status, 200);
        assert.equal(unsafe.status, 401);
        assert.equal(resolveCalls, 2);
        assert.match(getCookiePair(unsafe, "session") ?? "", /^session=$/);
    });

    it("bypasses and clears the cache for unsafe methods", async () => {
        let resolveCalls = 0;
        const auth = createMockAuth(async () => {
            resolveCalls += 1;
            return resolved;
        });
        const { app } = createApp({ auth, cache: true });
        const first = await app.request("/protected", {
            headers: { Cookie: `session=${token}`, ...identityHeaders },
        });
        const cached = getCookiePair(first, "session-cache");

        assert.ok(cached);

        const response = await app.request("/protected", {
            method: "POST",
            headers: {
                Cookie: `session=${token}; ${cached}; session-renew=${renewAt}`,
                ...identityHeaders,
            },
        });

        assert.equal(response.status, 204);
        assert.equal(resolveCalls, 2);
        assert.match(getCookiePair(response, "session-cache") ?? "", /^session-cache=$/);
        assert.equal(getCookiePair(response, "session"), null);
        assert.equal(getCookiePair(response, "session-renew"), null);
    });

    it("falls through to database validation for altered or mismatched cache data", async () => {
        let resolveCalls = 0;
        const auth = createMockAuth(async () => {
            resolveCalls += 1;
            return resolved;
        });
        const { app } = createApp({ auth, cache: true });
        const first = await app.request("/protected", {
            headers: { Cookie: `session=${token}`, ...identityHeaders },
        });
        const cached = getCookiePair(first, "session-cache");

        assert.ok(cached);

        const altered = await app.request("/protected", {
            headers: {
                Cookie: `session=${token}; ${cached}x`,
                ...identityHeaders,
            },
        });
        const changedIp = await app.request("/protected", {
            headers: {
                Cookie: `session=${token}; ${cached}`,
                "User-Agent": "Hono Test",
                "X-Forwarded-For": "192.0.2.11",
            },
        });

        assert.equal(altered.status, 200);
        assert.equal(changedIp.status, 200);
        assert.equal(resolveCalls, 3);
    });

    it("renews the session, marker, and cache only through renewSession", async () => {
        const auth = createMockAuth(async () => resolved);
        let renewCalls = 0;
        auth.session.renew = async (input) => {
            renewCalls += 1;
            assert.equal(input.token, token);
            return { ...resolved, renewed: true };
        };
        const { app } = createApp({ auth, cache: true });
        const response = await app.request("/renew", {
            method: "POST",
            headers: { Cookie: `session=${token}`, ...identityHeaders },
        });

        assert.equal(response.status, 204);
        assert.equal(renewCalls, 1);
        assert.equal(getCookiePair(response, "session"), `session=${token}`);
        assert.equal(getCookiePair(response, "session-renew"), `session-renew=${renewAt}`);
        assert.match(getCookiePair(response, "session-cache") ?? "", /^session-cache=.+/);

        const cookies = getSetCookies(response);
        const sessionCookie = cookies.find((cookie) => cookie.startsWith("session="));
        const renewCookie = cookies.find((cookie) => cookie.startsWith("session-renew="));

        assert.match(
            sessionCookie ?? "",
            new RegExp(`Expires=${session.expires_at.toUTCString()}`),
        );
        assert.match(renewCookie ?? "", new RegExp(`Expires=${session.expires_at.toUTCString()}`));

        for (const cookie of cookies) {
            assert.match(cookie, /HttpOnly/);
            assert.match(cookie, /SameSite=Lax/);
            assert.match(cookie, /Expires=/);
        }
    });

    it("clears all browser cookies for malformed, invalid, and mismatched sessions", async () => {
        const malformed = createApp({
            auth: createMockAuth(async () => resolved),
            cache: true,
        });
        const malformedResponse = await malformed.app.request("/protected", {
            headers: { Cookie: "session=invalid" },
        });
        assert.equal(malformedResponse.status, 401);

        const invalid = createApp({ auth: createMockAuth(async () => null), cache: true });
        const invalidResponse = await invalid.app.request("/protected", {
            headers: { Cookie: `session=${token}`, ...identityHeaders },
        });
        assert.equal(invalidResponse.status, 401);

        const mismatch = createApp({
            auth: createMockAuth(async () => {
                throw createError({
                    code: "SESSION_CLIENT_MISMATCH",
                    message: "Mismatch.",
                });
            }),
            cache: true,
        });
        const mismatchResponse = await mismatch.app.request("/protected", {
            headers: { Cookie: `session=${token}`, ...identityHeaders },
        });
        assert.equal(mismatchResponse.status, 403);

        for (const response of [malformedResponse, invalidResponse, mismatchResponse]) {
            assert.match(getCookiePair(response, "session") ?? "", /^session=$/);
            assert.match(getCookiePair(response, "session-cache") ?? "", /^session-cache=$/);
            assert.match(getCookiePair(response, "session-renew") ?? "", /^session-renew=$/);
        }
    });

    it("creates and revokes all three browser cookies without exposing token wiring", async () => {
        const auth = createMockAuth(async () => resolved);
        auth.session.create = async (input) => {
            assert.deepEqual(input, {
                account_id: account.id,
                client: {
                    agent: "Hono Test",
                    ip: "192.0.2.10",
                    platform: "macOS",
                },
                country: "PT",
            });
            return { account, session, token };
        };
        auth.session.revokeToken = async (value) => {
            assert.equal(value, token);
            return [session.id];
        };

        const { adapter } = createApp({ auth, cache: true });
        const app = new Hono();

        app.get("/set", async (c) => {
            const created = await adapter.createSession({
                account_id: account.id,
                context: c,
                country: "PT",
            });
            return c.json({ account_id: created.account_id });
        });
        app.get("/revoke", async (c) => {
            const revoked = await adapter.revokeSession(c);
            return c.json({ revoked });
        });

        const setResponse = await app.request("/set", { headers: identityHeaders });
        const revokeResponse = await app.request("/revoke", {
            headers: { Cookie: `session=${token}` },
        });

        assert.deepEqual(await setResponse.json(), { account_id: account.id });
        assert.equal(getCookiePair(setResponse, "session"), `session=${token}`);
        assert.equal(getCookiePair(setResponse, "session-renew"), `session-renew=${renewAt}`);
        assert.match(getCookiePair(setResponse, "session-cache") ?? "", /^session-cache=.+/);
        assert.deepEqual(await revokeResponse.json(), { revoked: [session.id] });
        assert.match(getCookiePair(revokeResponse, "session") ?? "", /^session=$/);
        assert.match(getCookiePair(revokeResponse, "session-cache") ?? "", /^session-cache=$/);
        assert.match(getCookiePair(revokeResponse, "session-renew") ?? "", /^session-renew=$/);
    });

    it("keeps browser cookies when database revocation fails", async () => {
        const auth = createMockAuth(async () => resolved);
        auth.session.revokeToken = async () => {
            throw createError({ code: "DB_UNAVAILABLE", message: "Offline." });
        };
        const { adapter } = createApp({ auth, cache: true });
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
        assert.deepEqual(getSetCookies(response), []);
    });

    it("validates IP, cookie, cache, and secret configuration", () => {
        const auth = createMockAuth(async () => resolved);

        assert.throws(
            () => createHonoAdapter({ auth }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => createHonoAdapter({ auth, getIp: null as never }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createHonoAdapter({
                    auth,
                    cookie: { secure: false, sessionName: "__Host-session" },
                    getIp: () => null,
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createHonoAdapter({
                    auth,
                    cache: { ttl: 60 },
                    getIp: () => null,
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createHonoAdapter({
                    auth,
                    cache: { ttl: 60 },
                    getIp: () => null,
                    secret: "weak",
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
