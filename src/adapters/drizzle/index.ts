import { randomUUID } from "node:crypto";
import { and, desc, eq, getTableColumns, gt, inArray, isNull, type SQL } from "drizzle-orm";
import type { AnyMySqlTable, MySqlColumn } from "drizzle-orm/mysql-core";
import { createError } from "../../errors.js";
import { isRecord } from "../../session/guards.js";
import type { AuthAccount, AuthSessionRecord, DbAdapter } from "../../session/types.js";
import type { SocialDbAdapter } from "../../social/types.js";
import { DRIZZLE_FIELDS, resolveDrizzleModels } from "./config.js";
import {
    createModelSelect,
    createSessionSelect,
    readAccount,
    requireAuthRow,
    requireRow,
    requireRows,
} from "./model.js";
import type {
    CreateDrizzleAdapter,
    DrizzleAccount,
    DrizzleAdapterInput,
    DrizzleClient,
    DrizzleDb,
    DrizzleModelsConfig,
} from "./types.js";

export type {
    DrizzleAccount,
    DrizzleAdapterInput,
    DrizzleDataModelConfig,
    DrizzleModelsConfig,
    DrizzleTableModelConfig,
    DrizzleUser,
} from "./types.js";

const requireClient = (value: unknown): DrizzleClient => {
    if (
        !isRecord(value) ||
        typeof value.insert !== "function" ||
        typeof value.select !== "function" ||
        typeof value.transaction !== "function" ||
        typeof value.update !== "function"
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Drizzle MySQL client is invalid.",
        });
    }

    return value as unknown as DrizzleClient;
};

const getColumns = <const Fields extends readonly string[]>({
    fields,
    table,
}: {
    fields: Fields;
    table: AnyMySqlTable;
}): Record<Fields[number], MySqlColumn> => {
    const columns = getTableColumns(table);

    return Object.fromEntries(fields.map((field) => [field, columns[field]])) as Record<
        Fields[number],
        MySqlColumn
    >;
};

export const createDrizzleAdapter: CreateDrizzleAdapter = <
    const Models extends DrizzleModelsConfig,
>(
    input: DrizzleAdapterInput<Models>,
): DrizzleDb<Models> => {
    type AccountData = DrizzleAccount<Models> & AuthAccount;

    const client = requireClient(input.client);
    const models = resolveDrizzleModels(input.models);
    const accountColumns = getColumns({
        fields: DRIZZLE_FIELDS.accounts,
        table: models.accounts.table,
    });
    const sessionColumns = getColumns({
        fields: DRIZZLE_FIELDS.sessions,
        table: models.sessions,
    });
    const userColumns = getColumns({
        fields: DRIZZLE_FIELDS.users,
        table: models.users.table,
    });
    const accountSelect = createModelSelect({ model: models.accounts });
    const sessionSelect = createSessionSelect(models);
    const userSelect = createModelSelect({ model: models.users });

    const readSocialAccount = (value: unknown) => {
        const resolved = readAccount({ models, value });

        return {
            account: resolved.account as AccountData,
            allowed: resolved.allowed,
        };
    };

    const findAccount = async (where: SQL) => {
        const rows = await client
            .select({ account: accountSelect, user: userSelect })
            .from(models.accounts.table)
            .innerJoin(models.users.table, eq(accountColumns.user_id, userColumns.id))
            .where(where)
            .limit(1);

        return rows[0] === undefined ? null : readSocialAccount(rows[0]);
    };

    const db: DbAdapter<AccountData> = {
        create: async (session) => {
            await client.insert(models.sessions).values(session);
        },

        find: async ({ account_id, session_id }) => {
            const rows = await client
                .select(sessionSelect)
                .from(models.sessions)
                .where(
                    and(
                        eq(sessionColumns.account_id, account_id),
                        eq(sessionColumns.id, session_id),
                    ),
                )
                .limit(1);

            return rows[0] === undefined ? null : requireRow(rows[0]);
        },

        findActive: async ({ account_id, now }) => {
            const rows = await client
                .select(sessionSelect)
                .from(models.sessions)
                .where(
                    and(
                        eq(sessionColumns.account_id, account_id),
                        gt(sessionColumns.expires_at, now),
                        isNull(sessionColumns.revoked_at),
                    ),
                )
                .orderBy(desc(sessionColumns.created_at));

            return requireRows(rows);
        },

        findToken: async (token_hash) => {
            const rows = await client
                .select({
                    account: accountSelect,
                    session: sessionSelect,
                    user: userSelect,
                })
                .from(models.sessions)
                .innerJoin(models.accounts.table, eq(sessionColumns.account_id, accountColumns.id))
                .innerJoin(models.users.table, eq(accountColumns.user_id, userColumns.id))
                .where(eq(sessionColumns.token_hash, token_hash))
                .limit(1);

            return rows[0] === undefined
                ? null
                : (requireAuthRow({ models, value: rows[0] }) as AuthSessionRecord<AccountData>);
        },

        revoke: async ({ revoked_at, session_ids }) => {
            if (session_ids.length === 0) {
                return;
            }

            await client
                .update(models.sessions)
                .set({
                    revoked_at,
                    updated_at: revoked_at,
                })
                .where(
                    and(inArray(sessionColumns.id, session_ids), isNull(sessionColumns.revoked_at)),
                );
        },

        updateExpiry: async ({ expires_at, session_id, updated_at }) => {
            await client
                .update(models.sessions)
                .set({ expires_at, updated_at })
                .where(eq(sessionColumns.id, session_id));
        },
    };

    const socialTable = models.socials;

    if (socialTable === null) {
        return db as DrizzleDb<Models>;
    }

    const socialColumns = getColumns({
        fields: DRIZZLE_FIELDS.socials,
        table: socialTable,
    });
    const social: SocialDbAdapter<AccountData> = {
        createAccount: async ({ email, name }) => {
            return client.transaction(async (transaction) => {
                const accountId = randomUUID();
                const userId = randomUUID();

                await transaction.insert(models.users.table).values({
                    id: userId,
                    name,
                });
                await transaction.insert(models.accounts.table).values({
                    email,
                    id: accountId,
                    user_id: userId,
                });

                return accountId;
            });
        },

        createSocial: async (socialRecord) => {
            await client.insert(socialTable).values(socialRecord);
        },

        findAccount: async (account_id) => findAccount(eq(accountColumns.id, account_id)),

        findEmail: async (email) => findAccount(eq(accountColumns.email, email)),

        findSocial: async ({ provider, provider_id }) => {
            const rows = await client
                .select({ account: accountSelect, user: userSelect })
                .from(socialTable)
                .innerJoin(models.accounts.table, eq(socialColumns.account_id, accountColumns.id))
                .innerJoin(models.users.table, eq(accountColumns.user_id, userColumns.id))
                .where(
                    and(
                        eq(socialColumns.provider, provider),
                        eq(socialColumns.provider_id, provider_id),
                    ),
                )
                .limit(1);

            return rows[0] === undefined ? null : readSocialAccount(rows[0]);
        },
    };

    return { ...db, ...social } as unknown as DrizzleDb<Models>;
};
