import type { DbAdapter, SocialDbAdapter, SocialRegistrationInput } from "@gauts/auth";
import { createHonoAuth } from "@gauts/auth/hono";
import { google } from "@gauts/auth/providers";
import { Hono } from "hono";

type RegisterData = {
    companyNumber: string;
};

type SocialExampleDeps = {
    callbackUrl: string;
    clientId: string;
    clientSecret: string;
    createAccount: (input: {
        companyNumber: string;
        email: string;
        name: string;
    }) => Promise<string>;
    db: DbAdapter & SocialDbAdapter;
    errorUrl: string;
    registerUrl: string;
    secret: string;
    successUrl: string;
};

export const createSocialApp = (deps: SocialExampleDeps) => {
    const auth = createHonoAuth({
        db: deps.db,
        secret: deps.secret,
        social: {
            errorUrl: deps.errorUrl,
            providers: [
                google({
                    callbackUrl: deps.callbackUrl,
                    clientId: deps.clientId,
                    clientSecret: deps.clientSecret,
                }),
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
                registerUrl: deps.registerUrl,
            },
            successUrl: deps.successUrl,
        },
    });
    const app = new Hono();

    app.get("/auth/social/:provider/:action", async (c) => {
        return auth.social.handle(c);
    });

    app.get("/auth/register/social", (c) => {
        return c.json(auth.social.getRegistration(c));
    });

    app.post("/auth/register/social", async (c) => {
        const data = await c.req.json<RegisterData>();
        await auth.social.completeRegistration({ context: c, data });
        return c.json({ registered: true });
    });

    return app;
};
