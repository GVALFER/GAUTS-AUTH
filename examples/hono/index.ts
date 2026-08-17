import { Hono } from "hono";
import { isAuthError, type DbAdapter } from "@gauts/auth";
import { createHonoAuth, type HonoAuthEnv } from "@gauts/auth/hono";

type LoginAccount = {
    id: string;
    passwordHash: string;
};

type ExampleDeps = {
    db: DbAdapter;
    findAccount: (email: string) => Promise<LoginAccount | null>;
    secret: string;
};

const DUMMY_PASSWORD_HASH =
    "$argon2id$v=19$m=65536,p=4,t=3$PUotpfVXonc0VRFuV1pKZQ$oxxA8DMvGRTSbZvh2Dkokeyih9sbKeodWYROqVxP9BI";

export const createApp = ({ db, findAccount, secret }: ExampleDeps) => {
    const auth = createHonoAuth({
        cache: { ttl: 60 },
        db,
        secret,
    });

    const app = new Hono<HonoAuthEnv>();

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

        const account = await findAccount(body.email);

        const passwordValid = await auth.password.verify({
            password: body.password,
            storedHash: account?.passwordHash ?? DUMMY_PASSWORD_HASH,
        });

        if (!account || !passwordValid) {
            return c.json({ error: "Invalid credentials." }, 401);
        }

        await auth.createSession({
            account_id: account.id,
            context: c,
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

    app.get("/account", auth.requireSession, (c) => {
        return c.json({
            account: c.get("account"),
        });
    });

    return app;
};
