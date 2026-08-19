import { index, mysqlTable, text, timestamp, uniqueIndex, varchar } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
    id: varchar("id", { length: 255 }).primaryKey(),
    name: varchar("name", { length: 255 }).notNull(),
});

export const userAccounts = mysqlTable(
    "user_accounts",
    {
        email: varchar("email", { length: 255 }).notNull(),
        id: varchar("id", { length: 255 }).primaryKey(),
        password_hash: varchar("password_hash", { length: 255 }),
        user_id: varchar("user_id", { length: 255 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
    },
    (table) => [
        uniqueIndex("user_accounts_email_key").on(table.email),
        index("user_accounts_user_id_idx").on(table.user_id),
    ],
);

export const accountSessions = mysqlTable(
    "account_sessions",
    {
        account_id: varchar("account_id", { length: 255 })
            .notNull()
            .references(() => userAccounts.id, { onDelete: "cascade" }),
        agent: text("agent"),
        country: varchar("country", { length: 2 }),
        created_at: timestamp("created_at", { mode: "date" }).defaultNow().notNull(),
        expires_at: timestamp("expires_at", { mode: "date" }).notNull(),
        id: varchar("id", { length: 255 }).primaryKey(),
        ip: varchar("ip", { length: 45 }),
        platform: varchar("platform", { length: 255 }),
        revoked_at: timestamp("revoked_at", { mode: "date" }),
        token_hash: varchar("token_hash", { length: 64 }).notNull(),
        updated_at: timestamp("updated_at", { mode: "date" }),
    },
    (table) => [
        index("account_sessions_account_id_idx").on(table.account_id),
        index("account_sessions_expires_at_idx").on(table.expires_at),
        index("account_sessions_revoked_at_idx").on(table.revoked_at),
        uniqueIndex("account_sessions_token_hash_key").on(table.token_hash),
    ],
);
