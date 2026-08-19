import { createDrizzleAdapter } from "@gauts/auth/drizzle";
import { createHonoAuth } from "@gauts/auth/hono";
import type { MySql2Database } from "drizzle-orm/mysql2";
import { accountSessions, userAccounts, users } from "../../../src/adapters/drizzle/schema.js";

type Schema = {
    accountSessions: typeof accountSessions;
    userAccounts: typeof userAccounts;
    users: typeof users;
};

export const createAuth = (client: MySql2Database<Schema>) => {
    return createHonoAuth({
        db: createDrizzleAdapter({
            client,
            models: {
                accounts: { table: userAccounts },
                sessions: { table: accountSessions },
                users: { table: users },
            },
        }),
    });
};
