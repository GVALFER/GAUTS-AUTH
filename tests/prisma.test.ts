import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
    createPrismaAdapter,
    type PrismaAccountModel,
    type PrismaAdapterInput,
    type PrismaSessionModel,
} from "../src/adapters/prisma/index.js";
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

type AccountRow = {
    email: string;
    id: string;
    name: string;
    password_hash: string;
    role: "ADMIN" | "OWNER";
    status: "ACTIVE" | "INACTIVE" | "PENDING";
    timezone: string | null;
};

type UserRow = {
    id: string;
    role: "ADMIN" | "USER";
    status: "ACTIVE" | "INACTIVE" | "PENDING";
};

type LegacyAccountRow = {
    email: string;
    hash: string;
    id: string;
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

const account: AccountRow = {
    email: "owner@example.com",
    id: "account-1",
    name: "Owner",
    password_hash: "secret",
    role: "OWNER",
    status: "PENDING",
    timezone: "Europe/Lisbon",
};

const user: UserRow = {
    id: "user-1",
    role: "ADMIN",
    status: "PENDING",
};

type CreateDelegateInput = {
    accountRelation?: string;
    userRelation?: string;
};

const createDelegate = ({
    accountRelation = "account",
    userRelation = "user",
}: CreateDelegateInput = {}) => {
    const calls: Record<string, unknown> = {};
    const delegate: Delegate<SessionRecord> = {
        [meta]: null as never,
        create: async (args) => {
            calls.create = args;
            return row;
        },
        findFirst: async (args) => {
            calls.findFirst = args;
            return row;
        },
        findMany: async (args) => {
            calls.findMany = args;
            return [row];
        },
        findUnique: async (args) => {
            calls.findUnique = args;
            return {
                ...row,
                [accountRelation]: {
                    ...account,
                    [userRelation]: user,
                },
            };
        },
        update: async (args) => {
            calls.update = args;
            return row;
        },
        updateMany: async (args) => {
            calls.updateMany = args;
            return { count: 1 };
        },
    };

    return { calls, delegate };
};

const createModelDelegate = <Row>(): Delegate<Row> => ({
    [meta]: null as never,
    create: async () => null,
    findFirst: async () => null,
    findMany: async () => [],
    findUnique: async () => null,
    update: async () => null,
    updateMany: async () => ({ count: 0 }),
});

const createClient = () => {
    const sessions = createDelegate();

    return {
        calls: sessions.calls,
        client: {
            account: createModelDelegate<AccountRow>(),
            legacy_accounts: createModelDelegate<LegacyAccountRow>(),
            sessions: sessions.delegate,
            user: createModelDelegate<UserRow>(),
            user_accounts: createModelDelegate<AccountRow>(),
            users: createModelDelegate<UserRow>(),
        },
    };
};

const assertTypes = () => {
    const { client } = createClient();
    const sessionModel: PrismaSessionModel<typeof client> = "sessions";
    const accountModel: PrismaAccountModel<typeof client> = "user_accounts";
    const legacyAccountModel: PrismaAccountModel<typeof client> = "legacy_accounts";
    void sessionModel;
    void accountModel;
    void legacyAccountModel;

    // @ts-expect-error user_accounts does not implement the session schema.
    const invalidSession: PrismaSessionModel<typeof client> = "user_accounts";
    void invalidSession;

    // @ts-expect-error sessions is a session model, not an account model.
    const invalidAccount: PrismaAccountModel<typeof client> = "sessions";
    void invalidAccount;

    // @ts-expect-error relation models without login credentials are not account models.
    const invalidRelationAccount: PrismaAccountModel<typeof client> = "users";
    void invalidRelationAccount;

    const defaults = { client } satisfies PrismaAdapterInput<typeof client>;
    void defaults;

    const legacy = {
        client,
        models: {
            account: {
                name: "legacy_accounts",
            },
        },
    } satisfies PrismaAdapterInput<
        typeof client,
        {
            account: {
                name: "legacy_accounts";
            };
        }
    >;
    void legacy;

    const defaultDb = createPrismaAdapter({ client });
    void defaultDb;
    type DefaultAccount = NonNullable<
        Awaited<ReturnType<typeof defaultDb.findToken>>
    >["account"];
    const defaultAccount = null as unknown as DefaultAccount;
    const defaultEmail: string = defaultAccount.email;
    void defaultEmail;

    const custom = {
        client,
        models: {
            account: {
                access: { status: ["ACTIVE", "PENDING"] },
                name: "user_accounts",
                relations: {
                    user: {
                        access: { status: "ACTIVE" },
                        name: "users",
                        select: ["id", "role"],
                    },
                },
                select: ["id", "email", "role"],
            },
        },
    } satisfies PrismaAdapterInput<
        typeof client,
        {
            account: {
                access: { status: readonly ["ACTIVE", "PENDING"] };
                name: "user_accounts";
                relations: {
                    user: {
                        access: { status: "ACTIVE" };
                        name: "users";
                        select: readonly ["id", "role"];
                    };
                };
                select: readonly ["id", "email", "role"];
            };
        }
    >;
    void custom;

    const typedDb = createPrismaAdapter({
        client,
        models: {
            account: {
                name: "user_accounts",
                relations: {
                    user: {
                        name: "users",
                        select: ["id", "role"],
                    },
                },
                select: ["id", "email"],
            },
        },
    });
    void typedDb;
    type TypedAccount = NonNullable<
        Awaited<ReturnType<typeof typedDb.findToken>>
    >["account"];
    const typedAccount = null as unknown as TypedAccount;
    const email: string = typedAccount.email;
    const role: string = typedAccount.user.role;
    void email;
    void role;

    // @ts-expect-error name was not selected for the account payload.
    void typedAccount.name;

    // @ts-expect-error status was not selected for the nested user payload.
    void typedAccount.user.status;

    // @ts-expect-error unknown account fields are rejected.
    createPrismaAdapter({
        client,
        models: { account: { select: ["missing"] } },
    });
};

void assertTypes;

describe("Prisma database adapter", () => {
    it("uses the default models and exposes account id and email", async () => {
        const { calls, client } = createClient();
        const db = createPrismaAdapter({ client });

        await db.create({
            account_id: row.account_id,
            agent: row.agent,
            created_at: row.created_at,
            expires_at: row.expires_at,
            id: row.id,
            ip: row.ip,
            platform: row.platform,
            token_hash: row.token_hash,
        });

        assert.deepEqual(await db.findToken(row.token_hash), {
            ...row,
            account: { email: account.email, id: account.id },
            allowed: true,
        });
        assert.deepEqual(calls.findUnique, {
            select: {
                ...Object.fromEntries(Object.keys(row).map((field) => [field, true])),
                account: {
                    select: { email: true, id: true },
                },
            },
            where: { token_hash: row.token_hash },
        });
    });

    it("selects custom account data and applies hidden access fields", async () => {
        const { calls, client } = createClient();
        const db = createPrismaAdapter({
            client,
            models: {
                account: {
                    access: {
                        role: ["OWNER", "ADMIN"],
                        status: ["ACTIVE", "PENDING"],
                    },
                    name: "user_accounts",
                    select: ["id", "email", "name"],
                },
            },
        });

        assert.deepEqual((await db.findToken(row.token_hash))?.account, {
            email: account.email,
            id: account.id,
            name: account.name,
        });
        assert.deepEqual(calls.findUnique, {
            select: {
                ...Object.fromEntries(Object.keys(row).map((field) => [field, true])),
                account: {
                    select: {
                        email: true,
                        id: true,
                        name: true,
                        role: true,
                        status: true,
                    },
                },
            },
            where: { token_hash: row.token_hash },
        });
    });

    it("loads configured nested relations into the account payload", async () => {
        const { client } = createClient();
        const db = createPrismaAdapter({
            client,
            models: {
                account: {
                    name: "user_accounts",
                    relations: {
                        user: {
                            access: { status: ["ACTIVE", "PENDING"] },
                            name: "users",
                            select: ["id", "role"],
                        },
                    },
                    select: ["id", "email"],
                },
            },
        });

        assert.deepEqual(await db.findToken(row.token_hash), {
            ...row,
            account: {
                email: account.email,
                id: account.id,
                user: {
                    id: user.id,
                    role: user.role,
                },
            },
            allowed: true,
        });
    });

    it("returns allowed=false when an access condition does not match", async () => {
        const { client } = createClient();
        const db = createPrismaAdapter({
            client,
            models: {
                account: {
                    access: { status: ["ACTIVE"] },
                    name: "user_accounts",
                },
            },
        });

        assert.equal((await db.findToken(row.token_hash))?.allowed, false);
    });

    it("uses a custom session model", async () => {
        const sessions = createDelegate();
        const custom = {
            admin_sessions: sessions.delegate,
            user_accounts: createModelDelegate<AccountRow>(),
        };
        const db = createPrismaAdapter({
            client: custom,
            models: {
                account: { name: "user_accounts" },
                sessions: { name: "admin_sessions" },
            },
        });

        assert.deepEqual(await db.find({ account_id: row.account_id, session_id: row.id }), row);
    });

    it("rejects invalid runtime models and configuration", () => {
        const { client } = createClient();

        assert.throws(
            () =>
                createPrismaAdapter({
                    client: { ...client, sessions: {} as Delegate<SessionRecord> },
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );

        assert.throws(
            () =>
                createPrismaAdapter({
                    client,
                    models: {
                        account: {
                            access: { status: [] },
                        },
                    },
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );

    });
});
