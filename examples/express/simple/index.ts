import { isAuthError, type DbAdapter } from "@gauts/auth";
import { createExpressAuth, type ExpressAuthLocals } from "@gauts/auth/express";
import express, { type ErrorRequestHandler } from "express";

type LoginAccount = {
    id: string;
    passwordHash: string;
};

type SimpleDeps = {
    db: DbAdapter;
    findAccount: (email: string) => Promise<LoginAccount | null>;
    secret: string;
};

export const createApp = ({ db, findAccount, secret }: SimpleDeps) => {
    const auth = createExpressAuth({ db, secret });
    const app = express();

    app.use(express.json());

    app.post("/auth/login", async (request, response) => {
        const body = request.body as { email: string; password: string };

        const account = await findAccount(body.email);

        const passwordValid = await auth.password.verify({
            password: body.password,
            storedHash: account?.passwordHash,
        });

        if (!account || !passwordValid) {
            response.status(401).json({ error: "Invalid credentials." });
            return;
        }

        await auth.createSession({
            account_id: account.id,
            request,
            response,
        });

        response.json({ authenticated: true });
    });

    app.post("/auth/renew", async (request, response) => {
        await auth.renewSession({ request, response });
        response.sendStatus(204);
    });

    app.post("/auth/logout", async (request, response) => {
        await auth.revokeSession({ request, response });
        response.sendStatus(204);
    });

    app.get("/account", auth.requireSession, (_request, response) => {
        const { account, session, user } = response.locals as ExpressAuthLocals;
        response.json({ account, session, user });
    });

    const onError: ErrorRequestHandler = (error, _request, response, next) => {
        void next;

        if (!isAuthError(error)) {
            response.status(500).json({ error: "Internal server error." });
            return;
        }

        response.status(error.code === "DB_UNAVAILABLE" ? 503 : 401).json({ error: error.message });
    };

    app.use(onError);
    return app;
};
