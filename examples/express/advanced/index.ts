import {
    isAuthError,
    type DbAdapter,
    type SocialDbAdapter,
    type SocialRegistrationInput,
} from "@gauts/auth";
import {
    createExpressAuth,
    type ExpressAuthLocals,
    type ExpressGetIp,
    type ExpressSocialLocals,
} from "@gauts/auth/express";
import { google } from "@gauts/auth/providers";
import express, { type ErrorRequestHandler, type Request } from "express";

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
    getCountry: (request: Request) => Promise<string | null> | string | null;
    getIp: ExpressGetIp;
    google: {
        callbackUrl: string;
        clientId: string;
        clientSecret: string;
    };
    secret: string;
};

export const createApp = (deps: AdvancedDeps) => {
    const auth = createExpressAuth({
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
    const app = express();

    app.use(express.json());

    app.post("/auth/login", async (request, response) => {
        const body = request.body as { email: string; password: string };
        const account = await deps.findAccount(body.email);

        const valid = await auth.password.verify({
            password: body.password,
            storedHash: account?.passwordHash,
        });

        if (!account || !valid) {
            response.status(401).json({ error: "Invalid credentials." });
            return;
        }

        await auth.createSession({
            account_id: account.id,
            country: await deps.getCountry(request),
            request,
            response,
        });

        response.json({ authenticated: true });
    });

    app.get("/auth/social/:provider/:action", auth.social.handle, async (request, response) => {
        const { social } = response.locals as ExpressSocialLocals;

        await auth.createSession({
            account_id: social.account.id,
            country: await deps.getCountry(request),
            request,
            response,
        });

        response.redirect(social.returnTo);
    });

    app.get("/auth/register/social", (request, response) => {
        response.json(auth.social.getRegistration({ request, response }));
    });

    app.post("/auth/register/social", async (request, response) => {
        const social = await auth.social.completeRegistration({
            data: request.body as RegisterData,
            request,
            response,
        });

        await auth.createSession({
            account_id: social.account.id,
            country: await deps.getCountry(request),
            request,
            response,
        });

        response.json({ registered: true, returnTo: social.returnTo });
    });

    app.get("/account", auth.requireSession, (_request, response) => {
        const { account, session, user } = response.locals as ExpressAuthLocals;
        response.json({ account, session, user });
    });

    const onError: ErrorRequestHandler = (error, _request, response, next) => {
        void next;
        response.status(isAuthError(error) ? 401 : 500).json({ error: "Request failed." });
    };

    app.use(onError);
    return app;
};
