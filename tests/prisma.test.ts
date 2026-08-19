import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
    createPrismaAdapter,
    type PrismaAccountModel,
    type PrismaSessionModel,
    type PrismaSocialModel,
    type PrismaUserModel,
} from "../src/adapters/prisma/index.js";
import { createHonoAuth } from "../src/adapters/hono/index.js";
import { isAuthError } from "../src/errors.js";
import type { SessionRecord } from "../src/session/types.js";

const meta = Symbol("Prisma delegate metadata");

type Delegate<Row> = {
    [meta]: {
        types: {
            payload: {
                scalars: Row;
            };
        };
    };
    create(args: unknown): Promise<unknown>;
    findFirst(args: unknown): Promise<unknown>;
    findMany(args: unknown): Promise<unknown>;
    findUnique(args: unknown): Promise<unknown>;
    update(args: unknown): Promise<unknown>;
    updateMany(args: unknown): Promise<unknown>;
};

type UserRow = {
    id: string;
    name: string;
    role: "ADMIN" | "USER";
    status: "ACTIVE" | "INACTIVE";
};

type AccountRow = {
    email: string;
    id: string;
    name: string;
    password_hash: string;
    role: "ADMIN" | "OWNER";
    status: "ACTIVE" | "INACTIVE";
    timezone: string | null;
    user_id: string;
};

type SocialRow = {
    account_id: string;
    created_at: Date;
    id: string;
    provider: string;
    provider_id: string;
};

const row: SessionRecord = {
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

const user: UserRow = {
    id: "user-1",
    name: "Company",
    role: "ADMIN",
    status: "ACTIVE",
};

const account: AccountRow = {
    email: "owner@example.com",
    id: "account-1",
    name: "Owner",
    password_hash: "secret",
    role: "OWNER",
    status: "ACTIVE",
    timezone: "Europe/Lisbon",
    user_id: user.id,
};

type DelegateHandlers = Partial<{
    create(args: unknown): Promise<unknown>;
    findFirst(args: unknown): Promise<unknown>;
    findMany(args: unknown): Promise<unknown>;
    findUnique(args: unknown): Promise<unknown>;
    update(args: unknown): Promise<unknown>;
    updateMany(args: unknown): Promise<unknown>;
}>;

const createDelegate = <Row>(handlers: DelegateHandlers = {}): Delegate<Row> => ({
    [meta]: null as never,
    create: handlers.create ?? (async () => null),
    findFirst: handlers.findFirst ?? (async () => null),
    findMany: handlers.findMany ?? (async () => []),
    findUnique: handlers.findUnique ?? (async () => null),
    update: handlers.update ?? (async () => null),
    updateMany: handlers.updateMany ?? (async () => ({ count: 0 })),
});

const createClient = ({ allowed = true }: { allowed?: boolean } = {}) => {
    const calls: Record<string, unknown> = {};
    const resolvedAccount = {
        ...account,
        status: allowed ? account.status : "INACTIVE",
        user,
    };
    const client = {
        account_sessions: createDelegate<SessionRecord>({
            create: async (args) => {
                calls.sessionCreate = args;
                return row;
            },
            findFirst: async (args) => {
                calls.sessionFindFirst = args;
                return row;
            },
            findMany: async (args) => {
                calls.sessionFindMany = args;
                return [row];
            },
            findUnique: async (args) => {
                calls.sessionFindUnique = args;
                return { ...row, account: resolvedAccount };
            },
            update: async (args) => {
                calls.sessionUpdate = args;
                return row;
            },
            updateMany: async (args) => {
                calls.sessionUpdateMany = args;
                return { count: 1 };
            },
        }),
        social_accounts: createDelegate<SocialRow>({
            create: async (args) => {
                calls.socialCreate = args;
                return null;
            },
            findFirst: async (args) => {
                calls.socialFindFirst = args;
                return { account: resolvedAccount };
            },
        }),
        user_accounts: createDelegate<AccountRow>({
            create: async (args) => {
                calls.accountCreate = args;
                return { id: account.id };
            },
            findUnique: async (args) => {
                calls.accountFindUnique = args;
                return resolvedAccount;
            },
        }),
        users: createDelegate<UserRow>(),
    };

    return { calls, client };
};

const assertTypes = () => {
    const { client } = createClient();
    const accountModel: PrismaAccountModel<typeof client> = "user_accounts";
    const sessionModel: PrismaSessionModel<typeof client> = "account_sessions";
    const socialModel: PrismaSocialModel<typeof client> = "social_accounts";
    const userModel: PrismaUserModel<typeof client> = "users";
    void accountModel;
    void sessionModel;
    void socialModel;
    void userModel;

    // @ts-expect-error Accounts are not session models.
    const invalidSession: PrismaSessionModel<typeof client> = "user_accounts";
    void invalidSession;

    const db = createPrismaAdapter({
        client,
        models: {
            accounts: {
                access: { status: ["ACTIVE"] },
                select: ["name", "role", "status", "timezone"],
            },
            users: {
                access: { status: ["ACTIVE"] },
                select: ["role", "status"],
            },
        },
    });
    void db;
    type Account = NonNullable<Awaited<ReturnType<typeof db.findToken>>>["account"];
    const typed = null as unknown as Account;
    const email: string = typed.email;
    const role: "ADMIN" | "OWNER" = typed.role;
    const userName: string = typed.user.name;
    const userRole: "ADMIN" | "USER" = typed.user.role;
    void email;
    void role;
    void userName;
    void userRole;

    const inline = createHonoAuth({
        cookie: { secure: false },
        db: createPrismaAdapter({
            client,
            models: {
                accounts: {
                    select: ["role"],
                },
                users: {
                    select: ["role"],
                },
            },
        }),
        secret: "s".repeat(32),
        session: { validation: [] },
    });
    type InlineAccount = NonNullable<Awaited<ReturnType<typeof inline.session.resolve>>>["account"];
    const inlineAccount = null as unknown as InlineAccount;
    const inlineRole: "ADMIN" | "OWNER" = inlineAccount.role;
    const inlineUserRole: "ADMIN" | "USER" = inlineAccount.user.role;
    void inlineRole;
    void inlineUserRole;
    void inline;

    const defaults = createPrismaAdapter({ client });
    void defaults;
    type DefaultAccount = NonNullable<Awaited<ReturnType<typeof defaults.findToken>>>["account"];
    const defaultAccount = null as unknown as DefaultAccount;
    const defaultEmail: string = defaultAccount.email;
    const defaultName: string = defaultAccount.user.name;
    void defaultEmail;
    void defaultName;

    // @ts-expect-error Role is not part of the default account payload.
    void defaultAccount.role;

    const { social_accounts: socialDelegate, ...sessionClient } = client;
    const sessionsOnly = createPrismaAdapter({ client: sessionClient });
    void socialDelegate;
    void sessionsOnly;

    // @ts-expect-error Social methods are absent when the Prisma model is absent.
    void sessionsOnly.findSocial;

    // @ts-expect-error Unknown account fields are rejected.
    createPrismaAdapter({ client, models: { accounts: { select: ["missing"] } } });

    // @ts-expect-error Password hashes can never enter the auth payload.
    createPrismaAdapter({ client, models: { accounts: { select: ["password_hash"] } } });
};

void assertTypes;

describe("Prisma database adapter", () => {
    it("resolves a session with the fixed account and user relations", async () => {
        const { calls, client } = createClient();
        const db = createPrismaAdapter({
            client,
            models: {
                accounts: {
                    access: { status: ["ACTIVE"] },
                    select: ["name", "role", "status", "timezone"],
                },
                users: {
                    access: { status: ["ACTIVE"] },
                    select: ["role", "status"],
                },
            },
        });

        const resolved = await db.findToken(row.token_hash);

        assert.equal(resolved?.allowed, true);
        assert.deepEqual(resolved?.account, {
            email: account.email,
            id: account.id,
            name: account.name,
            role: account.role,
            status: account.status,
            timezone: account.timezone,
            user,
        });
        assert.deepEqual(calls.sessionFindUnique, {
            select: {
                account: {
                    select: {
                        email: true,
                        id: true,
                        name: true,
                        role: true,
                        status: true,
                        timezone: true,
                        user: {
                            select: {
                                id: true,
                                name: true,
                                role: true,
                                status: true,
                            },
                        },
                    },
                },
                account_id: true,
                agent: true,
                created_at: true,
                expires_at: true,
                id: true,
                ip: true,
                platform: true,
                revoked_at: true,
                token_hash: true,
                updated_at: true,
            },
            where: { token_hash: row.token_hash },
        });
    });

    it("returns allowed=false when an access condition fails", async () => {
        const { client } = createClient({ allowed: false });
        const db = createPrismaAdapter({
            client,
            models: {
                accounts: { access: { status: ["ACTIVE"] } },
            },
        });

        const resolved = await db.findToken(row.token_hash);
        assert.equal(resolved?.allowed, false);
    });

    it("implements session persistence", async () => {
        const { calls, client } = createClient();
        const db = createPrismaAdapter({ client });
        const now = new Date("2026-08-17T12:00:00.000Z");

        await db.create({ ...row, revoked_at: undefined, updated_at: undefined } as never);
        await db.find({ account_id: account.id, session_id: row.id });
        await db.findActive({ account_id: account.id, now });
        await db.updateExpiry({ expires_at: row.expires_at, session_id: row.id, updated_at: now });
        await db.revoke({ revoked_at: now, session_ids: [row.id] });

        assert.ok(calls.sessionCreate);
        assert.ok(calls.sessionFindFirst);
        assert.ok(calls.sessionFindMany);
        assert.ok(calls.sessionUpdate);
        assert.ok(calls.sessionUpdateMany);
    });

    it("does not require or expose social persistence when the model is absent", () => {
        const { client } = createClient();
        const { social_accounts: socialDelegate, ...sessionClient } = client;
        const db = createPrismaAdapter({ client: sessionClient });
        void socialDelegate;

        assert.equal("findSocial" in db, false);
        assert.equal("createSocial" in db, false);
    });

    it("implements default account creation and social account linking", async () => {
        const { calls, client } = createClient();
        const db = createPrismaAdapter({ client });
        const createdAt = new Date("2026-08-18T10:00:00.000Z");

        const accountId = await db.createAccount({
            email: "new@example.com",
            name: "New Company",
        });
        await db.createSocial({
            account_id: accountId,
            created_at: createdAt,
            id: "social-1",
            provider: "google",
            provider_id: "google-1",
        });
        const linked = await db.findSocial({
            provider: "google",
            provider_id: "google-1",
        });

        assert.equal(accountId, account.id);
        assert.equal(linked?.account.email, account.email);
        assert.deepEqual(calls.accountCreate, {
            data: {
                email: "new@example.com",
                user: { create: { name: "New Company" } },
            },
            select: { id: true },
        });
        assert.deepEqual(calls.socialCreate, {
            data: {
                account_id: account.id,
                created_at: createdAt,
                id: "social-1",
                provider: "google",
                provider_id: "google-1",
            },
        });
    });

    it("supports explicit table names without relation configuration", () => {
        const { client } = createClient();
        const custom = {
            custom_accounts: client.user_accounts,
            custom_sessions: client.account_sessions,
            custom_socials: client.social_accounts,
            custom_users: client.users,
        };

        assert.doesNotThrow(() =>
            createPrismaAdapter({
                client: custom,
                models: {
                    accounts: { table: "custom_accounts" },
                    sessions: { table: "custom_sessions" },
                    socials: { table: "custom_socials" },
                    users: { table: "custom_users" },
                },
            }),
        );
    });

    it("rejects an invalid model at startup", () => {
        const { client } = createClient();

        assert.throws(
            () =>
                createPrismaAdapter({
                    client: { ...client, social_accounts: {} },
                } as never),
            (error: unknown) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });

    it("rejects private fields at runtime", () => {
        const { client } = createClient();

        assert.throws(
            () =>
                createPrismaAdapter({
                    client,
                    models: {
                        accounts: { select: ["password_hash"] },
                    },
                } as never),
            (error: unknown) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
