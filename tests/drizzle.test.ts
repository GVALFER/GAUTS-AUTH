import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { drizzle } from "drizzle-orm/mysql-proxy";
import { mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";

import { createDrizzleAdapter } from "../src/adapters/drizzle/index.js";
import { createHonoAuth } from "../src/adapters/hono/index.js";
import { isAuthError } from "../src/errors.js";

const users = mysqlTable("users", {
    id: varchar("id", { length: 255 }).primaryKey(),
    name: varchar("name", { length: 255 }).notNull(),
    role: varchar("role", { enum: ["ADMIN", "USER"], length: 16 }).notNull(),
    status: varchar("status", { enum: ["ACTIVE", "INACTIVE"], length: 16 }).notNull(),
});

const accounts = mysqlTable("user_accounts", {
    email: varchar("email", { length: 255 }).notNull(),
    id: varchar("id", { length: 255 }).primaryKey(),
    password_hash: varchar("password_hash", { length: 255 }),
    role: varchar("role", { enum: ["ADMIN", "OWNER"], length: 16 }).notNull(),
    status: varchar("status", { enum: ["ACTIVE", "INACTIVE"], length: 16 }).notNull(),
    user_id: varchar("user_id", { length: 255 }).notNull(),
});

const sessions = mysqlTable("account_sessions", {
    account_id: varchar("account_id", { length: 255 }).notNull(),
    agent: text("agent"),
    country: varchar("country", { length: 2 }),
    created_at: timestamp("created_at", { fsp: 3, mode: "date" }).notNull(),
    expires_at: timestamp("expires_at", { fsp: 3, mode: "date" }).notNull(),
    id: varchar("id", { length: 255 }).primaryKey(),
    ip: varchar("ip", { length: 45 }),
    platform: varchar("platform", { length: 255 }),
    revoked_at: timestamp("revoked_at", { fsp: 3, mode: "date" }),
    token_hash: varchar("token_hash", { length: 64 }).notNull(),
    updated_at: timestamp("updated_at", { fsp: 3, mode: "date" }),
});

const socials = mysqlTable("social_accounts", {
    account_id: varchar("account_id", { length: 255 }).notNull(),
    created_at: timestamp("created_at", { fsp: 3, mode: "date" }).notNull(),
    id: varchar("id", { length: 255 }).primaryKey(),
    provider: varchar("provider", { length: 32 }).notNull(),
    provider_id: varchar("provider_id", { length: 255 }).notNull(),
});

const session = {
    account_id: "account-1",
    agent: "Test Agent",
    created_at: new Date("2026-08-16T12:00:00.000Z"),
    expires_at: new Date("2026-08-23T12:00:00.000Z"),
    id: "session-1",
    ip: "192.0.2.10",
    platform: "macOS",
    revoked_at: null,
    token_hash: "a".repeat(64),
    updated_at: null,
};

const account = {
    email: "owner@example.com",
    id: "account-1",
    role: "OWNER" as const,
    status: "ACTIVE" as const,
};

const user = {
    id: "user-1",
    name: "Company",
    role: "ADMIN" as const,
    status: "ACTIVE" as const,
};

type QueryCall = {
    method: "all" | "execute";
    params: unknown[];
    sql: string;
};

const createClient = () => {
    const calls: QueryCall[] = [];
    const responses: unknown[][][] = [];
    const client = drizzle(async (sql, params, method) => {
        calls.push({ method, params, sql });

        if (method === "execute") {
            return { rows: [{ affectedRows: 1, insertId: 0 }] };
        }

        return { rows: responses.shift() ?? [] };
    });

    return {
        calls,
        client,
        respond: (...rows: unknown[][]) => responses.push(rows),
    };
};

const createModels = () => ({
    accounts: {
        access: { status: ["ACTIVE"] as const },
        select: ["role", "status"] as const,
        table: accounts,
    },
    sessions: { table: sessions },
    users: {
        access: { status: ["ACTIVE"] as const },
        select: ["role", "status"] as const,
        table: users,
    },
});

const assertTypes = () => {
    const { client } = createClient();
    const db = createDrizzleAdapter({ client, models: createModels() });
    const auth = createHonoAuth({ db });
    type Account = NonNullable<Awaited<ReturnType<typeof db.findToken>>>["account"];
    type AuthData = NonNullable<Awaited<ReturnType<typeof auth.session.resolve>>>["account"];
    const typed = null as unknown as Account;
    const authData = null as unknown as AuthData;
    const accountRole: "ADMIN" | "OWNER" = typed.role;
    const userRole: "ADMIN" | "USER" = typed.user.role;
    const authRole: "ADMIN" | "OWNER" = authData.role;
    void accountRole;
    void userRole;
    void authRole;
    void auth;

    // @ts-expect-error Social methods are absent when the social table is omitted.
    void db.findSocial;

    const socialDb = createDrizzleAdapter({
        client,
        models: {
            ...createModels(),
            socials: { table: socials },
        },
    });
    type FindSocial = typeof socialDb.findSocial;
    const findSocial = null as unknown as FindSocial;
    void findSocial;
    void socialDb;

    createDrizzleAdapter({
        client,
        models: {
            ...createModels(),
            // @ts-expect-error Password hashes can never enter the auth payload.
            accounts: { select: ["password_hash"], table: accounts },
        },
    });
};

void assertTypes;

describe("Drizzle MySQL database adapter", () => {
    it("resolves a session with selected account and user fields", async () => {
        const harness = createClient();
        const db = createDrizzleAdapter({
            client: harness.client,
            models: createModels(),
        });

        harness.respond([
            account.id,
            account.email,
            account.role,
            account.status,
            session.account_id,
            session.agent,
            "2026-08-16 12:00:00.000",
            "2026-08-23 12:00:00.000",
            session.id,
            session.ip,
            session.platform,
            null,
            session.token_hash,
            null,
            user.id,
            user.name,
            user.role,
            user.status,
        ]);

        const resolved = await db.findToken(session.token_hash);

        assert.equal(resolved?.allowed, true);
        assert.deepEqual(resolved?.account, {
            ...account,
            user,
        });
        assert.match(harness.calls[0]!.sql, /inner join `user_accounts`/);
        assert.match(harness.calls[0]!.sql, /inner join `users`/);
        assert.deepEqual(harness.calls[0]!.params, [session.token_hash, 1]);
    });

    it("returns allowed=false when an access condition fails", async () => {
        const harness = createClient();
        const db = createDrizzleAdapter({
            client: harness.client,
            models: createModels(),
        });

        harness.respond([
            account.id,
            account.email,
            account.role,
            "INACTIVE",
            session.account_id,
            session.agent,
            "2026-08-16 12:00:00.000",
            "2026-08-23 12:00:00.000",
            session.id,
            session.ip,
            session.platform,
            null,
            session.token_hash,
            null,
            user.id,
            user.name,
            user.role,
            user.status,
        ]);

        assert.equal((await db.findToken(session.token_hash))?.allowed, false);
    });

    it("implements session persistence with Drizzle queries", async () => {
        const harness = createClient();
        const db = createDrizzleAdapter({
            client: harness.client,
            models: createModels(),
        });
        const now = new Date("2026-08-17T12:00:00.000Z");

        await db.create({
            account_id: session.account_id,
            agent: session.agent,
            country: "PT",
            created_at: session.created_at,
            expires_at: session.expires_at,
            id: session.id,
            ip: session.ip,
            platform: session.platform,
            token_hash: session.token_hash,
        });

        harness.respond([
            session.account_id,
            session.agent,
            "2026-08-16 12:00:00.000",
            "2026-08-23 12:00:00.000",
            session.id,
            session.ip,
            session.platform,
            null,
            session.token_hash,
            null,
        ]);
        assert.equal(
            (await db.find({ account_id: account.id, session_id: session.id }))?.id,
            session.id,
        );

        harness.respond([
            session.account_id,
            session.agent,
            "2026-08-16 12:00:00.000",
            "2026-08-23 12:00:00.000",
            session.id,
            session.ip,
            session.platform,
            null,
            session.token_hash,
            null,
        ]);
        assert.equal((await db.findActive({ account_id: account.id, now })).length, 1);

        await db.updateExpiry({
            expires_at: session.expires_at,
            session_id: session.id,
            updated_at: now,
        });
        await db.revoke({ revoked_at: now, session_ids: [session.id] });

        assert.equal(harness.calls.filter((call) => call.method === "execute").length, 3);
        assert.ok(
            harness.calls.some((call) => call.sql.startsWith("insert into `account_sessions`")),
        );
        assert.ok(harness.calls.some((call) => call.sql.startsWith("update `account_sessions`")));
    });

    it("adds social persistence only when the social table is configured", async () => {
        const harness = createClient();
        Object.defineProperty(harness.client, "transaction", {
            value: async (run: (transaction: typeof harness.client) => Promise<unknown>) =>
                run(harness.client),
        });
        const db = createDrizzleAdapter({
            client: harness.client,
            models: {
                ...createModels(),
                socials: { table: socials },
            },
        });

        const accountId = await db.createAccount({
            email: "new@example.com",
            name: "New Company",
        });
        await db.createSocial({
            account_id: accountId,
            created_at: new Date("2026-08-18T10:00:00.000Z"),
            id: "social-1",
            provider: "google",
            provider_id: "google-1",
        });

        harness.respond([
            account.id,
            account.email,
            account.role,
            account.status,
            user.id,
            user.name,
            user.role,
            user.status,
        ]);
        const linked = await db.findSocial({
            provider: "google",
            provider_id: "google-1",
        });

        assert.equal(linked?.account.email, account.email);
        assert.match(accountId, /^[0-9a-f-]{36}$/);
        assert.equal(harness.calls.filter((call) => call.method === "execute").length, 3);
    });

    it("rejects missing required columns during initialization", () => {
        const harness = createClient();
        const invalidSessions = mysqlTable("invalid_sessions", {
            id: varchar("id", { length: 255 }).primaryKey(),
        });

        assert.throws(
            () =>
                createDrizzleAdapter({
                    client: harness.client,
                    models: {
                        ...createModels(),
                        sessions: { table: invalidSessions },
                    },
                } as never),
            (error: unknown) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });

    it("rejects private payload fields and omits social methods by default", () => {
        const harness = createClient();
        const db = createDrizzleAdapter({
            client: harness.client,
            models: createModels(),
        });

        assert.equal("findSocial" in db, false);
        assert.throws(
            () =>
                createDrizzleAdapter({
                    client: harness.client,
                    models: {
                        ...createModels(),
                        accounts: {
                            select: ["password_hash"],
                            table: accounts,
                        },
                    },
                } as never),
            (error: unknown) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
