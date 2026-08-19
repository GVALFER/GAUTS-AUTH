import {
    isAuthError,
    type DbAdapter,
    type SocialDbAdapter,
    type SocialRegistrationInput,
} from "@gauts/auth";
import {
    createHonoAuth,
    type HonoAuthVariables,
    type HonoGetIp,
    type HonoSocialVariables,
} from "@gauts/auth/hono";
import { github, google, x } from "@gauts/auth/providers";
import { Hono, type Context } from "hono";

type LoginAccount = {
    id: string;
    passwordHash: string;
};

type ProviderConfig = {
    callbackUrl: string;
    clientId: string;
    clientSecret: string;
};

type RegisterData = {
    companyNumber: string;
};

type AdvancedDeps = {
    cookieDomain?: string;
    createAccount: (input: {
        companyNumber: string;
        email: string;
        name: string;
    }) => Promise<string>;
    db: DbAdapter & SocialDbAdapter;
    findAccount: (email: string) => Promise<LoginAccount | null>;
    getCountry: (c: Context) => Promise<string | null> | string | null;
    getIp: HonoGetIp;
    providers: {
        github: ProviderConfig;
        google: ProviderConfig;
        x: ProviderConfig;
    };
    secret: string;
    secure: boolean;
};

type AdvancedEnv = {
    Variables: HonoAuthVariables & HonoSocialVariables;
};

export const createApp = (deps: AdvancedDeps) => {
    const auth = createHonoAuth({
        cache: { ttl: 60 },
        cookie: {
            contextName: "__app_ctx",
            ...(deps.cookieDomain ? { domain: deps.cookieDomain } : {}),
            sameSite: "Lax",
            secure: deps.secure,
            sessionName: "__app_ses",
        },
        db: deps.db,
        getIp: deps.getIp,
        password: {
            algorithm: "bcrypt",
            rounds: 12,
        },
        secret: deps.secret,
        session: {
            maxLifetime: 60 * 60 * 24 * 30,
            renewInterval: 60 * 60 * 24,
            ttl: 60 * 60 * 24 * 7,
            validation: ["agent", "ip", "platform"],
        },
        social: {
            cookieName: "__app_soc",
            providers: [
                google(deps.providers.google),
                github(deps.providers.github),
                x(deps.providers.x),
            ],
            registration: {
                createAccount: async ({
                    data,
                    identity,
                }: SocialRegistrationInput<RegisterData>) => ({
                    accountId: await deps.createAccount({
                        companyNumber: data.companyNumber,
                        email: identity.email,
                        name: identity.name,
                    }),
                }),
            },
        },
    });

    const app = new Hono<AdvancedEnv>();

    app.onError((error, c) => {
        if (!isAuthError(error)) {
            return c.json({ error: "Internal server error." }, 500);
        }

        const status = error.code === "DB_UNAVAILABLE" ? 503 : 401;
        return c.json({ error: error.message }, status);
    });

    app.post("/auth/login", async (c) => {
        const body = await c.req.json<{
            email: string;
            password: string;
        }>();

        const account = await deps.findAccount(body.email);
        const passwordValid = await auth.password.verify({
            password: body.password,
            storedHash: account?.passwordHash,
        });

        if (!account || !passwordValid) {
            return c.json({ error: "Invalid credentials." }, 401);
        }

        await auth.createSession({
            account_id: account.id,
            context: c,
            country: await deps.getCountry(c),
        });

        return c.json({ authenticated: true });
    });

    app.post("/auth/logout", async (c) => {
        await auth.revokeSession(c);
        return c.body(null, 204);
    });

    app.post("/auth/renew", async (c) => {
        await auth.renewSession(c);
        return c.body(null, 204);
    });

    app.get("/auth/social/:provider/:action", auth.social.handle, async (c) => {
        const social = c.get("social");

        await auth.createSession({
            account_id: social.account.id,
            context: c,
            country: await deps.getCountry(c),
        });

        return c.redirect(social.returnTo);
    });

    app.get("/auth/register/social", (c) => {
        return c.json(auth.social.getRegistration(c));
    });

    app.post("/auth/register/social", async (c) => {
        const data = await c.req.json<RegisterData>();
        const social = await auth.social.completeRegistration({ context: c, data });

        await auth.createSession({
            account_id: social.account.id,
            context: c,
            country: await deps.getCountry(c),
        });

        return c.json({ registered: true, returnTo: social.returnTo });
    });

    app.get("/account", auth.requireSession, (c) => {
        return c.json({
            account: c.get("account"),
            session: c.get("session"),
            user: c.get("user"),
        });
    });

    app.get("/account/sessions", auth.requireSession, async (c) => {
        return c.json(await auth.session.list(c.get("account").id));
    });

    app.delete("/account/sessions/:sessionId", auth.requireSession, async (c) => {
        const revoked = await auth.session.revoke({
            account_id: c.get("account").id,
            session_id: c.req.param("sessionId"),
        });

        return c.json({ revoked });
    });

    app.delete("/account/sessions", auth.requireSession, async (c) => {
        const revoked = await auth.session.revokeAccount(c.get("account").id);
        auth.clearSession(c);
        return c.json({ revoked });
    });

    return app;
};
