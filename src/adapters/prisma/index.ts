import { createError } from "../../errors.js";
import { isRecord } from "../../session/guards.js";
import type { AuthSessionRecord } from "../../session/types.js";
import { isPrismaDelegate, resolvePrismaModels } from "./config.js";
import {
    createAuthSelect,
    requireAuthRow,
    requireRow,
    requireRows,
    sessionSelect,
} from "./model.js";
import type { PrismaAccount, PrismaAdapterInput, PrismaDb, PrismaModelsConfig } from "./types.js";

export type {
    PrismaAccount,
    PrismaAccountConfig,
    PrismaAccountModel,
    PrismaAdapterInput,
    PrismaModelsConfig,
    PrismaRelations,
    PrismaSessionConfig,
    PrismaSessionModel,
} from "./types.js";

export const createPrismaAdapter = <
    Client extends object,
    const Models extends PrismaModelsConfig<Client> | undefined = undefined,
>(
    input: PrismaAdapterInput<Client, Models>,
): PrismaDb<Client, Models> => {
    const raw = input as { client: Client; models?: unknown };
    const resolved = resolvePrismaModels({ client: raw.client, input: raw.models });
    const table = isRecord(raw.client) ? raw.client[resolved.sessions] : undefined;
    const authSelect = createAuthSelect(resolved.account);

    if (!isPrismaDelegate(table)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `Prisma session model ${resolved.sessions} is invalid.`,
        });
    }

    return {
        create: async (session) => {
            await table.create({ data: session });
        },

        find: async ({ account_id, session_id }) => {
            const row = await table.findFirst({
                select: sessionSelect,
                where: {
                    account_id,
                    id: session_id,
                },
            });

            return row === null ? null : requireRow(row);
        },

        findActive: async ({ account_id, now }) => {
            const rows = await table.findMany({
                orderBy: { created_at: "desc" },
                select: sessionSelect,
                where: {
                    account_id,
                    expires_at: { gt: now },
                    revoked_at: null,
                },
            });

            return requireRows(rows);
        },

        findToken: async (token_hash) => {
            const row = await table.findUnique({
                select: authSelect,
                where: { token_hash },
            });

            return row === null
                ? null
                : (requireAuthRow({
                      account: resolved.account,
                      value: row,
                  }) as unknown as AuthSessionRecord<PrismaAccount<Client, Models>>);
        },

        revoke: async ({ revoked_at, session_ids }) => {
            if (session_ids.length === 0) {
                return;
            }

            await table.updateMany({
                data: {
                    revoked_at,
                    updated_at: revoked_at,
                },
                where: {
                    id: { in: session_ids },
                    revoked_at: null,
                },
            });
        },

        updateExpiry: async ({ expires_at, session_id, updated_at }) => {
            await table.update({
                data: {
                    expires_at,
                    updated_at,
                },
                where: { id: session_id },
            });
        },
    };
};
