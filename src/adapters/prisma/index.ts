import { createError } from "../../errors.js";
import { isRecord } from "../../session/guards.js";
import type { AuthSessionRecord } from "../../session/types.js";
import { isPrismaDelegate, resolvePrismaModels } from "./config.js";
import {
    createAccountSelect,
    createAuthSelect,
    readAccount,
    requireAuthRow,
    requireRow,
    requireRows,
    sessionSelect,
} from "./model.js";
import type {
    CreatePrismaAdapter,
    PrismaAccount,
    PrismaAdapterInput,
    PrismaDb,
    PrismaModelsConfig,
} from "./types.js";

export type {
    PrismaAccount,
    PrismaAccountConfig,
    PrismaAccountModel,
    PrismaAdapterInput,
    PrismaModelsConfig,
    PrismaSessionConfig,
    PrismaSessionModel,
    PrismaSocialConfig,
    PrismaSocialModel,
    PrismaUser,
    PrismaUserConfig,
    PrismaUserModel,
} from "./types.js";

export const createPrismaAdapter: CreatePrismaAdapter = <
    Client extends object,
    const Models extends PrismaModelsConfig<Client> | undefined = undefined,
>(
    input: PrismaAdapterInput<Client, Models>,
): PrismaDb<Client, Models> => {
    const raw = input as { client: Client; models?: unknown };
    const resolved = resolvePrismaModels({ client: raw.client, input: raw.models });
    const client: Record<string, unknown> = isRecord(raw.client) ? raw.client : {};

    const accounts = client[resolved.accounts.table];
    const sessions = client[resolved.sessions];
    const socials = client[resolved.socials];
    const users = client[resolved.users.table];

    const accountSelect = createAccountSelect({
        accounts: resolved.accounts,
        users: resolved.users,
    });

    const authSelect = createAuthSelect({
        accounts: resolved.accounts,
        users: resolved.users,
    });

    if (
        !isPrismaDelegate(accounts) ||
        !isPrismaDelegate(sessions) ||
        !isPrismaDelegate(socials) ||
        !isPrismaDelegate(users)
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Prisma authentication models are invalid.",
        });
    }

    const readSocialAccount = (value: unknown) => {
        if (!isRecord(value)) {
            throw new Error("Prisma social relation returned invalid data.");
        }

        const resolvedAccount = readAccount({
            accounts: resolved.accounts,
            users: resolved.users,
            value: value.account,
        });

        return {
            account: resolvedAccount.account as PrismaAccount<Client, Models> & {
                email: string;
                id: string;
                user: { id: string; name: string };
            },
            allowed: resolvedAccount.allowed,
        };
    };

    const findAccount = async (where: Record<string, string>) => {
        const value = await accounts.findUnique({ select: accountSelect, where });

        if (value === null) {
            return null;
        }

        const resolvedAccount = readAccount({
            accounts: resolved.accounts,
            users: resolved.users,
            value,
        });

        return {
            account: resolvedAccount.account as PrismaAccount<Client, Models> & {
                email: string;
                id: string;
                user: { id: string; name: string };
            },
            allowed: resolvedAccount.allowed,
        };
    };

    return {
        create: async (session) => {
            await sessions.create({ data: session });
        },

        createAccount: async ({ email, name }) => {
            const value = await accounts.create({
                data: {
                    email,
                    user: { create: { name } },
                },
                select: { id: true },
            });

            if (!isRecord(value) || typeof value.id !== "string") {
                throw new Error("Prisma account model returned invalid data.");
            }

            return value.id;
        },

        createSocial: async (social) => {
            await socials.create({ data: social });
        },

        find: async ({ account_id, session_id }) => {
            const row = await sessions.findFirst({
                select: sessionSelect,
                where: {
                    account_id,
                    id: session_id,
                },
            });

            return row === null ? null : requireRow(row);
        },

        findAccount: async (account_id) => findAccount({ id: account_id }),

        findActive: async ({ account_id, now }) => {
            const rows = await sessions.findMany({
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

        findEmail: async (email) => findAccount({ email }),

        findSocial: async ({ provider, provider_id }) => {
            const value = await socials.findFirst({
                select: {
                    account: { select: accountSelect },
                },
                where: { provider, provider_id },
            });

            return value === null ? null : readSocialAccount(value);
        },

        findToken: async (token_hash) => {
            const row = await sessions.findUnique({
                select: authSelect,
                where: { token_hash },
            });

            return row === null
                ? null
                : (requireAuthRow({
                      accounts: resolved.accounts,
                      users: resolved.users,
                      value: row,
                  }) as unknown as AuthSessionRecord<
                      PrismaAccount<Client, Models> & {
                          email: string;
                          id: string;
                          user: { id: string; name: string };
                      }
                  >);
        },

        revoke: async ({ revoked_at, session_ids }) => {
            if (session_ids.length === 0) {
                return;
            }

            await sessions.updateMany({
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
            await sessions.update({
                data: {
                    expires_at,
                    updated_at,
                },
                where: { id: session_id },
            });
        },
    };
};
