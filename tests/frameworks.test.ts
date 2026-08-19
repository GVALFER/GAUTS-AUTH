import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";
import express, { type ErrorRequestHandler } from "express";
import Fastify from "fastify";
import {
    createExpressAdapter,
    createExpressAuth,
    type ExpressAuthLocals,
} from "../src/adapters/express/index.js";
import {
    createFastifyAdapter,
    createFastifyAuth,
} from "../src/adapters/fastify/index.js";
import type { Auth } from "../src/auth.js";
import { isAuthError } from "../src/errors.js";
import type { DbAdapter, ResolvedSession, Session } from "../src/session/types.js";
import type { SocialDbAdapter, SocialProvider } from "../src/social/types.js";

const token = "a".repeat(43);
const now = Date.now();

const account = {
    email: "owner@example.com",
    id: "account-1",
    user: {
        id: "user-1",
        name: "Company",
    },
} as const;

const session: Session = {
    account_id: account.id,
    client: {
        agent: "Framework Test",
        ip: null,
        platform: "macOS",
    },
    created_at: new Date(now),
    expires_at: new Date(now + 7 * 24 * 60 * 60 * 1000),
    id: "session-1",
    renew_at: new Date(now + 24 * 60 * 60 * 1000),
};

const resolved: ResolvedSession<typeof account> = { account, session };
const headers = {
    "Sec-CH-UA-Platform": "macOS",
    "User-Agent": "Framework Test",
};

const createMockAuth = (): Auth<typeof account> => ({
    config: {
        session: {
            maxLifetime: 30 * 24 * 60 * 60,
            renewInterval: 24 * 60 * 60,
            ttl: 7 * 24 * 60 * 60,
            validation: ["agent"],
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
        async create(input) {
            assert.deepEqual(input.client, {
                agent: "Framework Test",
                ip: null,
                platform: "macOS",
            });
            return { account, session, token };
        },
        async list() {
            return [];
        },
        async renew() {
            return { ...resolved, renewed: true };
        },
        async resolve(input) {
            return input.token === token ? resolved : null;
        },
        async revoke() {
            return [];
        },
        async revokeAccount() {
            return [];
        },
        async revokeToken(value) {
            return value === token ? [session.id] : [];
        },
    },
});

const createSocialDb = (): DbAdapter<typeof account> & SocialDbAdapter<typeof account> => ({
    async create() {
        return;
    },
    async createAccount() {
        return account.id;
    },
    async createSocial() {
        return;
    },
    async find() {
        return null;
    },
    async findAccount() {
        return { account, allowed: true };
    },
    async findActive() {
        return [];
    },
    async findEmail() {
        return null;
    },
    async findSocial() {
        return null;
    },
    async findToken() {
        return null;
    },
    async revoke() {
        return;
    },
    async updateExpiry() {
        return;
    },
});

const provider: SocialProvider = {
    callbackUrl: "https://app.example.com/auth/social/google/callback",
    getAuthorizationUrl: ({ codeChallenge, state }) => {
        return `https://provider.example/authorize?state=${state}&challenge=${codeChallenge}`;
    },
    async getIdentity() {
        throw new Error("Not used by this test.");
    },
    id: "google",
};

const getSetCookies = (value: Headers): string[] => {
    const header = value as Headers & { getSetCookie?: () => string[] };
    return header.getSetCookie?.() ?? [];
};

describe("Express adapter", () => {
    it("creates, resolves, exposes, and revokes a session", async () => {
        const auth = createExpressAdapter({
            auth: createMockAuth(),
            cookie: { secure: false },
        });
        const app = express();

        app.get("/login", async (request, response) => {
            await auth.createSession({
                account_id: account.id,
                request,
                response,
            });
            response.sendStatus(204);
        });
        app.get("/account", auth.requireSession, (_request, response) => {
            const locals = response.locals as ExpressAuthLocals<typeof account>;
            response.json({
                account: locals.account,
                sessionId: locals.session.id,
                user: locals.user,
            });
        });
        app.get("/logout", async (request, response) => {
            const revoked = await auth.revokeSession({ request, response });
            response.json({ revoked });
        });

        const errorHandler: ErrorRequestHandler = (error, _request, response, next) => {
            void next;
            response.status(isAuthError(error) ? 401 : 500).json({ error: true });
        };
        app.use(errorHandler);

        const server = app.listen(0, "127.0.0.1");
        await new Promise<void>((resolve) => server.once("listening", resolve));
        const address = server.address() as AddressInfo;
        const base = `http://127.0.0.1:${String(address.port)}`;

        try {
            const login = await fetch(`${base}/login`, { headers });
            const loginCookies = getSetCookies(login.headers);

            assert.equal(login.status, 204);
            assert.equal(loginCookies.length, 2);
            assert.ok(loginCookies.some((value) => value.startsWith(`__ses=${token}`)));
            assert.ok(loginCookies.some((value) => value.startsWith("__ren=")));

            const protectedResponse = await fetch(`${base}/account`, {
                headers: { ...headers, Cookie: `__ses=${token}` },
            });

            assert.equal(protectedResponse.status, 200);
            assert.deepEqual(await protectedResponse.json(), {
                account,
                sessionId: session.id,
                user: account.user,
            });

            const logout = await fetch(`${base}/logout`, {
                headers: { Cookie: `__ses=${token}` },
            });

            assert.deepEqual(await logout.json(), { revoked: [session.id] });
            assert.equal(getSetCookies(logout.headers).length, 3);

            const invalid = await fetch(`${base}/account`, {
                headers: { ...headers, Cookie: `__ses=${"b".repeat(43)}` },
            });

            assert.equal(invalid.status, 401);
            assert.equal(getSetCookies(invalid.headers).length, 3);
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()));
            });
        }
    });
});

describe("Fastify adapter", () => {
    it("creates, resolves, exposes, and revokes a session", async () => {
        const auth = createFastifyAdapter({
            auth: createMockAuth(),
            cookie: { secure: false },
        });
        const app = Fastify();

        auth.decorate(app);
        app.get("/login", async (request, reply) => {
            await auth.createSession({
                account_id: account.id,
                reply,
                request,
            });
            reply.code(204);
        });
        app.get("/account", { preHandler: auth.requireSession }, async (request) => ({
            account: request.getDecorator<typeof account>("account"),
            sessionId: request.getDecorator<Session>("session").id,
            user: request.getDecorator<typeof account.user>("user"),
        }));
        app.get("/logout", async (request, reply) => ({
            revoked: await auth.revokeSession({ reply, request }),
        }));
        app.setErrorHandler((error, _request, reply) => {
            reply.code(isAuthError(error) ? 401 : 500).send({ error: true });
        });

        const login = await app.inject({ headers, method: "GET", url: "/login" });

        assert.equal(login.statusCode, 204);
        assert.equal(login.cookies.length, 2);
        assert.ok(login.cookies.some((value) => value.name === "__ses" && value.value === token));
        assert.ok(login.cookies.some((value) => value.name === "__ren"));

        const protectedResponse = await app.inject({
            headers: { ...headers, cookie: `__ses=${token}` },
            method: "GET",
            url: "/account",
        });

        assert.equal(protectedResponse.statusCode, 200);
        assert.deepEqual(protectedResponse.json(), {
            account,
            sessionId: session.id,
            user: account.user,
        });

        const logout = await app.inject({
            headers: { cookie: `__ses=${token}` },
            method: "GET",
            url: "/logout",
        });

        assert.deepEqual(logout.json(), { revoked: [session.id] });
        assert.equal(logout.cookies.length, 3);

        const invalid = await app.inject({
            headers: { ...headers, cookie: `__ses=${"b".repeat(43)}` },
            method: "GET",
            url: "/account",
        });

        assert.equal(invalid.statusCode, 401);
        assert.equal(invalid.cookies.length, 3);
        await app.close();
    });
});

describe("framework social adapters", () => {
    it("starts OAuth through Express without framework-owned routes", async () => {
        const auth = createExpressAuth({
            cookie: { secure: false },
            db: createSocialDb(),
            secret: "s".repeat(32),
            social: { providers: [provider] },
        });
        const app = express();

        app.get("/auth/social/:provider/:action", auth.social.handle, (_request, response) => {
            response.sendStatus(204);
        });

        const server = app.listen(0, "127.0.0.1");
        await new Promise<void>((resolve) => server.once("listening", resolve));
        const address = server.address() as AddressInfo;

        try {
            const response = await fetch(
                `http://127.0.0.1:${String(address.port)}/auth/social/google/start?returnTo=/&errorTo=/auth/login`,
                { redirect: "manual" },
            );

            assert.equal(response.status, 302);
            assert.match(response.headers.get("location") ?? "", /^https:\/\/provider\.example/);
            assert.ok(getSetCookies(response.headers).some((value) => value.startsWith("__soc=")));
        } finally {
            await new Promise<void>((resolve, reject) => {
                server.close((error) => (error ? reject(error) : resolve()));
            });
        }
    });

    it("starts OAuth through Fastify and registers the social decorator", async () => {
        const auth = createFastifyAuth({
            cookie: { secure: false },
            db: createSocialDb(),
            secret: "s".repeat(32),
            social: { providers: [provider] },
        });
        const app = Fastify();

        auth.decorate(app);
        assert.equal(app.hasRequestDecorator("social"), true);

        app.get(
            "/auth/social/:provider/:action",
            { preHandler: auth.social.handle },
            async (_request, reply) => reply.code(204).send(),
        );

        const response = await app.inject({
            method: "GET",
            url: "/auth/social/google/start?returnTo=/&errorTo=/auth/login",
        });

        assert.equal(response.statusCode, 302);
        assert.match(response.headers.location ?? "", /^https:\/\/provider\.example/);
        assert.ok(response.cookies.some((value) => value.name === "__soc"));
        await app.close();
    });
});
