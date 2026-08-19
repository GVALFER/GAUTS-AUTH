import { isAuthError, type DbAdapter } from "@gauts/auth";
import { createFastifyAuth } from "@gauts/auth/fastify";
import Fastify from "fastify";

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
    const auth = createFastifyAuth({ db, secret });
    const app = Fastify();

    auth.decorate(app);

    app.post("/auth/login", async (request, reply) => {
        const body = request.body as { email: string; password: string };

        const account = await findAccount(body.email);

        const passwordValid = await auth.password.verify({
            password: body.password,
            storedHash: account?.passwordHash,
        });

        if (!account || !passwordValid) {
            return reply.code(401).send({ error: "Invalid credentials." });
        }

        await auth.createSession({
            account_id: account.id,
            reply,
            request,
        });

        return { authenticated: true };
    });

    app.post("/auth/renew", async (request, reply) => {
        await auth.renewSession({ reply, request });
        return reply.code(204).send();
    });

    app.post("/auth/logout", async (request, reply) => {
        await auth.revokeSession({ reply, request });
        return reply.code(204).send();
    });

    app.get("/account", { preHandler: auth.requireSession }, (request) => ({
        account: request.getDecorator("account"),
        session: request.getDecorator("session"),
        user: request.getDecorator("user"),
    }));

    app.setErrorHandler((error, _request, reply) => {
        const status = isAuthError(error) ? (error.code === "DB_UNAVAILABLE" ? 503 : 401) : 500;

        return reply.code(status).send({
            error: isAuthError(error) ? error.message : "Internal server error.",
        });
    });

    return app;
};
