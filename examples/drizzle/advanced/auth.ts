import { createDrizzleAdapter } from "@gauts/auth/drizzle";
import { createHonoAuth } from "@gauts/auth/hono";
import { google } from "@gauts/auth/providers";
import type { MySql2Database } from "drizzle-orm/mysql2";

import { accountSessions, socialAccounts, userAccounts, users } from "./schema.js";

type Schema = {
    accountSessions: typeof accountSessions;
    socialAccounts: typeof socialAccounts;
    userAccounts: typeof userAccounts;
    users: typeof users;
};

type AuthConfig = {
    callbackUrl: string;
    client: MySql2Database<Schema>;
    clientId: string;
    clientSecret: string;
    secret: string;
};

export const createAuth = (config: AuthConfig) => {
    return createHonoAuth({
        cache: { ttl: 60 },
        db: createDrizzleAdapter({
            client: config.client,
            models: {
                accounts: {
                    access: {
                        role: ["OWNER", "ADMIN"],
                        status: ["ACTIVE"],
                    },
                    select: ["role", "status", "timezone"],
                    table: userAccounts,
                },
                sessions: { table: accountSessions },
                socials: { table: socialAccounts },
                users: {
                    access: { status: ["ACTIVE", "PENDING"] },
                    select: ["status"],
                    table: users,
                },
            },
        }),
        secret: config.secret,
        social: {
            providers: [
                google({
                    callbackUrl: config.callbackUrl,
                    clientId: config.clientId,
                    clientSecret: config.clientSecret,
                }),
            ],
            registration: {},
        },
    });
};
