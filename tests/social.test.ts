import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { Hono } from "hono";

import { createHonoAuth } from "../src/adapters/hono/index.js";
import { isAuthError } from "../src/errors.js";
import { createSocialService } from "../src/social/service.js";
import {
    createOAuthState,
    createRegistrationState,
    resolveOAuthState,
    resolveRegistrationState,
} from "../src/social/state.js";
import type {
    CreateSocialRecord,
    SocialDbAdapter,
    SocialIdentity,
    SocialProvider,
} from "../src/social/types.js";
import type {
    AuthAccount,
    AuthSessionRecord,
    CreateSessionRecord,
    DbAdapter,
    SessionRecord,
} from "../src/session/types.js";

const secret = "s".repeat(32);
const identity: SocialIdentity = {
    avatarUrl: "https://images.example/avatar.png",
    email: "new@example.com",
    name: "New Company",
    provider: "google",
    providerId: "google-1",
    username: null,
};

const createAccount = ({
    email = "owner@example.com",
    id = "account-1",
    name = "Company",
}: {
    email?: string;
    id?: string;
    name?: string;
} = {}): AuthAccount => ({
    email,
    id,
    user: {
        id: `user-${id}`,
        name,
    },
});

type SocialHarness = {
    account: AuthAccount;
    db: SocialDbAdapter;
    links: CreateSocialRecord[];
    setAccount(account: AuthAccount): void;
};

const createSocialDb = ({
    account: initial = createAccount(),
    emailMatch = false,
}: {
    account?: AuthAccount;
    emailMatch?: boolean;
} = {}): SocialHarness => {
    let account = initial;
    const links: CreateSocialRecord[] = [];
    const db: SocialDbAdapter = {
        createAccount: async ({ email, name }) => {
            account = createAccount({ email, id: "account-new", name });
            return account.id;
        },
        createSocial: async (record) => {
            links.push(record);
        },
        findAccount: async (account_id) => {
            return account.id === account_id ? { account, allowed: true } : null;
        },
        findEmail: async (email) => {
            return emailMatch && account.email === email ? { account, allowed: true } : null;
        },
        findSocial: async ({ provider, provider_id }) => {
            const linked = links.some(
                (value) => value.provider === provider && value.provider_id === provider_id,
            );
            return linked ? { account, allowed: true } : null;
        },
    };

    return {
        get account() {
            return account;
        },
        db,
        links,
        setAccount: (value) => {
            account = value;
        },
    };
};

const createDb = () => {
    const social = createSocialDb();
    let session: SessionRecord | null = null;
    const sessions: DbAdapter = {
        create: async (record: CreateSessionRecord) => {
            session = {
                ...record,
                revoked_at: null,
                updated_at: null,
            };
        },
        find: async () => session,
        findActive: async () => (session ? [session] : []),
        findToken: async (token_hash): Promise<AuthSessionRecord | null> => {
            return session?.token_hash === token_hash
                ? {
                      ...session,
                      account: social.account,
                      allowed: true,
                  }
                : null;
        },
        revoke: async ({ revoked_at }) => {
            if (session) {
                session = { ...session, revoked_at, updated_at: revoked_at };
            }
        },
        updateExpiry: async ({ expires_at, updated_at }) => {
            if (session) {
                session = { ...session, expires_at, updated_at };
            }
        },
    };

    return {
        ...social,
        db: { ...sessions, ...social.db },
    };
};

const provider: SocialProvider = {
    callbackUrl: "https://app.example.com/proxy/auth/social/google/callback",
    getAuthorizationUrl: ({ codeChallenge, state }) => {
        const url = new URL("https://provider.example.com/authorize");
        url.searchParams.set("code_challenge", codeChallenge);
        url.searchParams.set("state", state);
        return url.toString();
    },
    getIdentity: async ({ code, codeVerifier }) => {
        assert.equal(code, "valid-code");
        assert.match(codeVerifier, /^[A-Za-z0-9_-]{43}$/);
        return identity;
    },
    id: "google",
};

const getSetCookies = (response: Response): string[] => {
    const headers = response.headers as Headers & { getSetCookie?: () => string[] };
    return headers.getSetCookie?.() ?? [response.headers.get("set-cookie") ?? ""];
};

const getCookie = ({ name, response }: { name: string; response: Response }): string => {
    const value = getSetCookies(response).find((cookie) => cookie.startsWith(`${name}=`));
    assert.ok(value);
    return value.split(";", 1)[0] ?? "";
};

const beginSocial = async ({ app, intent }: { app: Hono; intent: string }) => {
    const response = await app.request(`/auth/social/google/start?intent=${intent}`);
    const location = response.headers.get("location");
    assert.equal(response.status, 302);
    assert.ok(location);

    const state = new URL(location).searchParams.get("state");
    assert.ok(state);

    return {
        cookie: getCookie({ name: "__soc", response }),
        state,
    };
};

describe("social state", () => {
    it("binds OAuth state, provider, intent, verifier, and expiry", () => {
        const now = new Date("2026-08-18T10:00:00.000Z");
        const created = createOAuthState({
            intent: "register",
            now: () => now,
            provider: "google",
            secret,
        });
        const resolved = resolveOAuthState({
            now: () => new Date("2026-08-18T10:09:59.000Z"),
            provider: "google",
            secret,
            state: created.state,
            value: created.value,
        });

        assert.equal(created.expires_at.toISOString(), "2026-08-18T10:10:00.000Z");
        assert.equal(resolved?.intent, "register");
        assert.match(resolved?.verifier ?? "", /^[A-Za-z0-9_-]{43}$/);
        assert.match(created.codeChallenge, /^[A-Za-z0-9_-]{43}$/);
    });

    it("rejects altered, mismatched, and expired OAuth state", () => {
        const created = createOAuthState({
            intent: "login",
            now: () => new Date("2026-08-18T10:00:00.000Z"),
            provider: "google",
            secret,
        });
        const base = {
            now: () => new Date("2026-08-18T10:01:00.000Z"),
            provider: "google" as const,
            secret,
            state: created.state,
            value: created.value,
        };

        assert.equal(resolveOAuthState({ ...base, state: "a".repeat(43) }), null);
        assert.equal(resolveOAuthState({ ...base, provider: "github" }), null);
        assert.equal(resolveOAuthState({ ...base, value: `${created.value}x` }), null);
        assert.equal(
            resolveOAuthState({
                ...base,
                now: () => new Date("2026-08-18T10:10:00.000Z"),
            }),
            null,
        );
    });

    it("signs and expires a pending registration identity", () => {
        const created = createRegistrationState({
            identity,
            now: () => new Date("2026-08-18T10:00:00.000Z"),
            secret,
        });

        assert.deepEqual(
            resolveRegistrationState({
                now: () => new Date("2026-08-18T10:09:59.000Z"),
                secret,
                value: created.value,
            }),
            identity,
        );
        assert.equal(
            resolveRegistrationState({
                now: () => new Date("2026-08-18T10:10:00.000Z"),
                secret,
                value: created.value,
            }),
            null,
        );
    });
});

describe("social service", () => {
    it("links a verified provider identity to an existing email account", async () => {
        const harness = createSocialDb({
            account: createAccount({ email: identity.email }),
            emailMatch: true,
        });
        const service = createSocialService({ db: harness.db, registration: null });

        const account = await service.find(identity);

        assert.equal(account?.email, identity.email);
        assert.equal(harness.links.length, 1);
        assert.equal(harness.links[0]?.provider_id, identity.providerId);
    });

    it("creates the default user/account structure when registration is enabled", async () => {
        const harness = createSocialDb();
        const service = createSocialService({ db: harness.db, registration: {} });

        const account = await service.register({ data: undefined, identity });

        assert.equal(account.email, identity.email);
        assert.equal(account.user.name, identity.name);
        assert.equal(harness.links.length, 1);
    });

    it("uses custom application data only through createAccount", async () => {
        const harness = createSocialDb();
        const service = createSocialService({
            db: harness.db,
            registration: {
                createAccount: async ({ data, identity: verified }) => {
                    assert.deepEqual(data, { companyNumber: "PT123" });
                    const account = createAccount({
                        email: verified.email,
                        id: "account-custom",
                        name: verified.name,
                    });
                    harness.setAccount(account);
                    return { accountId: account.id };
                },
            },
        });

        const account = await service.register({
            data: { companyNumber: "PT123" },
            identity,
        });

        assert.equal(account.id, "account-custom");
    });

    it("does not register when registration is disabled", async () => {
        const harness = createSocialDb();
        const service = createSocialService({ db: harness.db, registration: null });

        await assert.rejects(
            () => service.register({ data: undefined, identity }),
            (error: unknown) =>
                isAuthError(error) && error.code === "SOCIAL_ACCOUNT_NOT_FOUND",
        );
    });
});

describe("Hono social adapter", () => {
    it("accepts only start and callback actions", async () => {
        const harness = createDb();
        const auth = createHonoAuth({
            cookie: { secure: false },
            db: harness.db,
            secret,
            session: { validation: [] },
            social: {
                errorUrl: "https://app.example.com/auth/login",
                providers: [provider],
                successUrl: "https://app.example.com/dashboard",
            },
        });
        const app = new Hono();

        app.get("/auth/social/:provider/:action", auth.social.handle);

        const response = await app.request("/auth/social/google/invalid");

        assert.equal(response.status, 404);
    });

    it("registers directly, creates a session, and clears the social transaction", async () => {
        const harness = createDb();
        const auth = createHonoAuth({
            cookie: { secure: false },
            db: harness.db,
            secret,
            session: { validation: [] },
            social: {
                errorUrl: "https://app.example.com/auth/login",
                providers: [provider],
                registration: {},
                successUrl: "https://app.example.com/dashboard",
            },
        });
        const app = new Hono();
        app.get("/auth/social/:provider/:action", auth.social.handle);

        const started = await beginSocial({ app, intent: "register" });
        const response = await app.request(
            `/auth/social/google/callback?code=valid-code&state=${started.state}`,
            { headers: { cookie: started.cookie } },
        );

        assert.equal(response.status, 302);
        assert.equal(response.headers.get("location"), "https://app.example.com/dashboard");
        assert.ok(getSetCookies(response).some((cookie) => cookie.startsWith("__ses=")));
        assert.ok(
            getSetCookies(response).some(
                (cookie) => cookie.startsWith("__soc=") && cookie.includes("Max-Age=0"),
            ),
        );
        assert.equal(harness.links.length, 1);
    });

    it("defers custom registration and exposes only the verified identity", async () => {
        const harness = createDb();
        let createCalls = 0;
        const auth = createHonoAuth({
            cookie: { secure: false },
            db: harness.db,
            secret,
            session: { validation: [] },
            social: {
                errorUrl: "https://app.example.com/auth/login",
                providers: [provider],
                registration: {
                    createAccount: async ({ data, identity: verified }) => {
                        createCalls += 1;
                        assert.deepEqual(data, { companyNumber: "PT123" });
                        const account = createAccount({
                            email: verified.email,
                            id: "account-custom",
                            name: verified.name,
                        });
                        harness.setAccount(account);
                        return { accountId: account.id };
                    },
                    registerUrl: "https://app.example.com/auth/register/social",
                },
                successUrl: "https://app.example.com/dashboard",
            },
        });
        const app = new Hono();
        app.get("/auth/social/:provider/:action", auth.social.handle);
        app.get("/auth/register/social", (c) => c.json(auth.social.getRegistration(c)));
        app.post("/auth/register/social", async (c) => {
            const data = await c.req.json<{ companyNumber: string }>();
            await auth.social.completeRegistration({ context: c, data });
            return c.json({ registered: true });
        });

        const started = await beginSocial({ app, intent: "register" });
        const callback = await app.request(
            `/auth/social/google/callback?code=valid-code&state=${started.state}`,
            { headers: { cookie: started.cookie } },
        );
        const pendingCookie = getCookie({ name: "__soc", response: callback });

        assert.equal(callback.headers.get("location"), "https://app.example.com/auth/register/social");
        assert.equal(createCalls, 0);

        const pending = await app.request("/auth/register/social", {
            headers: { cookie: pendingCookie },
        });
        assert.deepEqual(await pending.json(), identity);

        const completed = await app.request("/auth/register/social", {
            body: JSON.stringify({ companyNumber: "PT123" }),
            headers: {
                "content-type": "application/json",
                cookie: pendingCookie,
            },
            method: "POST",
        });

        assert.equal(completed.status, 200);
        assert.equal(createCalls, 1);
        assert.ok(getSetCookies(completed).some((cookie) => cookie.startsWith("__ses=")));
    });

    it("redirects login failures without creating a session", async () => {
        const harness = createDb();
        const auth = createHonoAuth({
            cookie: { secure: false },
            db: harness.db,
            secret,
            session: { validation: [] },
            social: {
                errorUrl: "https://app.example.com/auth/login",
                providers: [provider],
                successUrl: "https://app.example.com/dashboard",
            },
        });
        const app = new Hono();
        app.get("/auth/social/:provider/:action", auth.social.handle);

        const started = await beginSocial({ app, intent: "login" });
        const response = await app.request(
            `/auth/social/google/callback?code=valid-code&state=${started.state}`,
            { headers: { cookie: started.cookie } },
        );
        const location = new URL(response.headers.get("location") ?? "");

        assert.equal(location.pathname, "/auth/login");
        assert.equal(location.searchParams.get("error"), "SOCIAL_ACCOUNT_NOT_FOUND");
        assert.equal(harness.links.length, 0);
    });

    it("rejects weak secrets, Strict SameSite, and colliding cookie names", () => {
        const harness = createDb();
        const base = {
            db: harness.db,
            session: { validation: [] as const },
            social: {
                errorUrl: "https://app.example.com/auth/login",
                providers: [provider],
                successUrl: "https://app.example.com/dashboard",
            },
        };

        assert.throws(
            () => createHonoAuth({ ...base, secret: "weak" }),
            (error: unknown) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createHonoAuth({
                    ...base,
                    cookie: { sameSite: "Strict" },
                    secret,
                }),
            (error: unknown) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createHonoAuth({
                    ...base,
                    secret,
                    social: { ...base.social, cookieName: "__ses" },
                }),
            (error: unknown) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
