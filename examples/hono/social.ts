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
    secret: string;
};

export const createSocialApp = (deps: SocialExampleDeps) => {
    const auth = createHonoAuth({
        db: deps.db,
        secret: deps.secret,
        social: {
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
            },
        },
    });
    const app = new Hono();

    app.get("/auth/social/:provider/:action", auth.social.handle, async (c) => {
        const social = c.get("social");
        await auth.createSession({ account_id: social.account.id, context: c });
        return c.redirect(social.returnTo);
    });

    app.get("/auth/register/social", (c) => {
        return c.json(auth.social.getRegistration(c));
    });

    app.post("/auth/register/social", async (c) => {
        const data = await c.req.json<RegisterData>();
        const social = await auth.social.completeRegistration({ context: c, data });
        await auth.createSession({ account_id: social.account.id, context: c });
        return c.json({ registered: true, returnTo: social.returnTo });
    });

    return app;
};
