import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hono } from "hono";
import { createHonoAdapter, type HonoAuthEnv } from "../src/adapters/hono/index.js";
import type { Auth } from "../src/auth.js";
import { createError, isAuthError } from "../src/errors.js";
import { createSessionState } from "../src/session/state.js";
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

const createContext = ({
    cache = true,
    value = resolved,
}: {
    cache?: boolean;
    value?: ResolvedSession<typeof account>;
} = {}) => {
    return createSessionState<typeof account>({
        ...(cache ? { cache: { ttl: 60 } } : {}),
        secret,
        session: {
            maxLifetime: 30 * 24 * 60 * 60,
            renewInterval: 24 * 60 * 60,
            ttl: 7 * 24 * 60 * 60,
            validation: ["ip", "agent"],
        },
    }).create({ resolved: value, token }).value;
};

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
            contextName: "session-context",
            secure: false,
            sessionName: "session",
        },
        getIp: (c) => c.req.header("x-forwarded-for"),
        ...(cache ? { cache: { ttl: 60 } } : {}),
        secret,
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
        const defaults = createHonoAdapter({ auth: withoutIpValidation(auth), secret });
        const { adapter } = createApp({ auth });

        assert.deepEqual(defaults.cookie, {
            contextName: "__ctx",
            sessionName: "__ses",
        });
        assert.deepEqual(adapter.cookie, {
            contextName: "session-context",
            sessionName: "session",
        });
    });

    it("uses a null IP when getIp is omitted", async () => {
        const auth = withoutIpValidation(createMockAuth(async () => resolved));
        let client: unknown;

        auth.session.renew = async (input) => {
            client = input.client;
            return { ...resolved, renewed: false };
        };

        const adapter = createHonoAdapter({ auth, secret });
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
        assert.equal(getCookiePair(response, "__ses"), `__ses=${token}`);
        assert.match(getCookiePair(response, "__ctx") ?? "", /^__ctx=.+/);
    });

    it("resolves through the database without cookie writes when context is valid and cache is disabled", async () => {
        const { app } = createApp({
            auth: createMockAuth(async () => resolved),
        });
        const response = await app.request("/protected", {
            headers: {
                Cookie: `session=${token}; session-context=${createContext({ cache: false })}`,
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
        const cached = getCookiePair(first, "session-context");

        assert.equal(first.status, 200);
        assert.ok(cached);
        assert.equal(resolveCalls, 1);

        const second = await app.request("/protected", {
            headers: {
                Cookie: `session=${token}; ${cached}`,
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
        const cached = getCookiePair(first, "session-context");

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

    it("bypasses cache for unsafe methods while preserving signed scheduling", async () => {
        let resolveCalls = 0;
        const auth = createMockAuth(async () => {
            resolveCalls += 1;
            return resolved;
        });
        const { app } = createApp({ auth, cache: true });
        const first = await app.request("/protected", {
            headers: { Cookie: `session=${token}`, ...identityHeaders },
        });
        const cached = getCookiePair(first, "session-context");

        assert.ok(cached);

        const response = await app.request("/protected", {
            method: "POST",
            headers: {
                Cookie: `session=${token}; ${cached}`,
                ...identityHeaders,
            },
        });

        assert.equal(response.status, 204);
        assert.equal(resolveCalls, 2);
        assert.match(getCookiePair(response, "session-context") ?? "", /^session-context=.+/);
        assert.equal(getCookiePair(response, "session"), null);
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
        const cached = getCookiePair(first, "session-context");

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

    it("renews explicitly and writes the session and context cookies", async () => {
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
        assert.match(getCookiePair(response, "session-context") ?? "", /^session-context=.+/);

        const cookies = getSetCookies(response);
        const sessionCookie = cookies.find((cookie) => cookie.startsWith("session="));
        const contextCookie = cookies.find((cookie) => cookie.startsWith("session-context="));

        assert.match(
            sessionCookie ?? "",
            new RegExp(`Expires=${session.expires_at.toUTCString()}`),
        );
        assert.match(contextCookie ?? "", new RegExp(`Expires=${session.expires_at.toUTCString()}`));

        for (const cookie of cookies) {
            assert.match(cookie, /HttpOnly/);
            assert.match(cookie, /SameSite=Lax/);
            assert.match(cookie, /Expires=/);
        }
    });

    it("renews automatically through requireSession when the signed schedule is due", async () => {
        const due: ResolvedSession<typeof account> = {
            account,
            session: {
                ...session,
                renew_at: new Date(testNow - 1_000),
            },
        };
        const auth = createMockAuth(async () => resolved);
        let renewCalls = 0;

        auth.session.renew = async () => {
            renewCalls += 1;
            return { ...resolved, renewed: true };
        };

        const { app } = createApp({ auth, cache: true });
        const response = await app.request("/protected", {
            headers: {
                Cookie: `session=${token}; session-context=${createContext({ value: due })}`,
                ...identityHeaders,
            },
        });

        assert.equal(response.status, 200);
        assert.equal(renewCalls, 1);
        assert.equal(getCookiePair(response, "session"), `session=${token}`);
        assert.match(getCookiePair(response, "session-context") ?? "", /^session-context=.+/);
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
            assert.match(getCookiePair(response, "session-context") ?? "", /^session-context=$/);
        }
    });

    it("creates and revokes both browser cookies without exposing token wiring", async () => {
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
        assert.match(getCookiePair(setResponse, "session-context") ?? "", /^session-context=.+/);
        assert.deepEqual(await revokeResponse.json(), { revoked: [session.id] });
        assert.match(getCookiePair(revokeResponse, "session") ?? "", /^session=$/);
        assert.match(getCookiePair(revokeResponse, "session-context") ?? "", /^session-context=$/);
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
            () => createHonoAdapter({ auth, secret }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => createHonoAdapter({ auth, getIp: null as never, secret }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createHonoAdapter({
                    auth,
                    cookie: { secure: false, sessionName: "__Host-session" },
                    getIp: () => null,
                    secret,
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createHonoAdapter({
                    auth,
                    cache: { ttl: 60 },
                    getIp: () => null,
                    secret: undefined as never,
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
