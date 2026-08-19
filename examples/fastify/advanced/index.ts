import {
    isAuthError,
    type DbAdapter,
    type SocialAuthenticated,
    type SocialDbAdapter,
    type SocialRegistrationInput,
} from "@gauts/auth";
import { createFastifyAuth, type FastifyGetIp } from "@gauts/auth/fastify";
import { google } from "@gauts/auth/providers";
import Fastify, { type FastifyRequest } from "fastify";

type LoginAccount = {
    id: string;
    passwordHash: string;
};

type RegisterData = {
    companyNumber: string;
};

type AdvancedDeps = {
    createAccount: (input: {
        companyNumber: string;
        email: string;
        name: string;
    }) => Promise<string>;
    db: DbAdapter & SocialDbAdapter;
    findAccount: (email: string) => Promise<LoginAccount | null>;
    getCountry: (request: FastifyRequest) => Promise<string | null> | string | null;
    getIp: FastifyGetIp;
    google: {
        callbackUrl: string;
        clientId: string;
        clientSecret: string;
    };
    secret: string;
};

export const createApp = (deps: AdvancedDeps) => {
    const auth = createFastifyAuth({
        cache: {
            ttl: 60,
        },
        db: deps.db,
        getIp: deps.getIp,
        password: {
            algorithm: "bcrypt",
        },
        secret: deps.secret,
        session: {
            validation: ["agent", "ip", "platform"],
        },
        social: {
            providers: [google(deps.google)],
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
    const app = Fastify();

    auth.decorate(app);

    app.post("/auth/login", async (request, reply) => {
        const body = request.body as { email: string; password: string };

        const account = await deps.findAccount(body.email);

        const valid = await auth.password.verify({
            password: body.password,
            storedHash: account?.passwordHash,
        });

        if (!account || !valid) {
            return reply.code(401).send({ error: "Invalid credentials." });
        }

        await auth.createSession({
            account_id: account.id,
            country: await deps.getCountry(request),
            reply,
            request,
        });

        return { authenticated: true };
    });

    app.get(
        "/auth/social/:provider/:action",
        { preHandler: auth.social.handle },
        async (request, reply) => {
            const social = request.getDecorator<SocialAuthenticated>("social");

            await auth.createSession({
                account_id: social.account.id,
                country: await deps.getCountry(request),
                reply,
                request,
            });

            return reply.redirect(social.returnTo);
        },
    );

    app.get("/auth/register/social", async (request, reply) => {
        return auth.social.getRegistration({ reply, request });
    });

    app.post("/auth/register/social", async (request, reply) => {
        const social = await auth.social.completeRegistration({
            data: request.body as RegisterData,
            reply,
            request,
        });

        await auth.createSession({
            account_id: social.account.id,
            country: await deps.getCountry(request),
            reply,
            request,
        });

        return { registered: true, returnTo: social.returnTo };
    });

    app.get("/account", { preHandler: auth.requireSession }, (request) => ({
        account: request.getDecorator("account"),
        session: request.getDecorator("session"),
        user: request.getDecorator("user"),
    }));

    app.setErrorHandler((error, _request, reply) => {
        return reply.code(isAuthError(error) ? 401 : 500).send({ error: "Request failed." });
    });

    return app;
};
