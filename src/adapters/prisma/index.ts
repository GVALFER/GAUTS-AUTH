import { createError } from "../../errors.js";
import type { DbAdapter, SessionRecord } from "../../session/types.js";

const DEFAULT_TABLE = "auth_sessions";

type DelegateMeta<T> = T[Extract<keyof T, symbol>];

type DelegateRow<T> =
    DelegateMeta<T> extends {
        types: {
            payload: { scalars: infer Result };
        };
    }
        ? Result
        : never;

type IsSessionTable<T> = [DelegateRow<T>] extends [never]
    ? false
    : DelegateRow<T> extends SessionRecord
      ? true
      : false;

export type PrismaSessionTable<Client> = {
    [Key in keyof Client]: IsSessionTable<Client[Key]> extends true ? Key : never;
}[keyof Client] &
    string;

export type PrismaAdapterConfig<Client> = {
    table?: PrismaSessionTable<Client>;
};

type DefaultPrismaAdapterInput<Client extends object> = {
    client: Client;
    config?: PrismaAdapterConfig<Client>;
};

type CustomPrismaAdapterInput<Client extends object> = {
    client: Client;
    config: PrismaAdapterConfig<Client> & {
        table: PrismaSessionTable<Client>;
    };
};

export type PrismaAdapterInput<Client extends object> =
    typeof DEFAULT_TABLE extends PrismaSessionTable<Client>
        ? DefaultPrismaAdapterInput<Client>
        : CustomPrismaAdapterInput<Client>;

type Delegate = {
    create(args: unknown): Promise<unknown>;
    findFirst(args: unknown): Promise<unknown>;
    findMany(args: unknown): Promise<unknown>;
    update(args: unknown): Promise<unknown>;
    updateMany(args: unknown): Promise<unknown>;
};

const select = {
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
} as const;

const isRecord = (value: unknown): value is Record<string, unknown> => {
    return typeof value === "object" && value !== null && !Array.isArray(value);
};

const isNullableString = (value: unknown): value is string | null => {
    return typeof value === "string" || value === null;
};

const isNullableDate = (value: unknown): value is Date | null => {
    return value instanceof Date || value === null;
};

const isDelegate = (value: unknown): value is Delegate => {
    return (
        isRecord(value) &&
        typeof value.create === "function" &&
        typeof value.findFirst === "function" &&
        typeof value.findMany === "function" &&
        typeof value.update === "function" &&
        typeof value.updateMany === "function"
    );
};

const isSessionRecord = (value: unknown): value is SessionRecord => {
    return (
        isRecord(value) &&
        typeof value.account_id === "string" &&
        isNullableString(value.agent) &&
        value.created_at instanceof Date &&
        value.expires_at instanceof Date &&
        typeof value.id === "string" &&
        isNullableString(value.ip) &&
        isNullableString(value.platform) &&
        isNullableDate(value.revoked_at) &&
        typeof value.token_hash === "string" &&
        isNullableDate(value.updated_at)
    );
};

const requireRow = (value: unknown): SessionRecord => {
    if (!isSessionRecord(value)) {
        throw new Error("Prisma session table returned invalid data.");
    }

    return value;
};

const requireRows = (value: unknown): SessionRecord[] => {
    if (!Array.isArray(value)) {
        throw new Error("Prisma session table returned invalid data.");
    }

    return value.map(requireRow);
};

export const createDbAdapter = <Client extends object>(
    input: PrismaAdapterInput<Client>,
): DbAdapter => {
    const config = "config" in input ? input.config : undefined;
    const table_name = config?.table ?? DEFAULT_TABLE;
    const table = isRecord(input.client) ? input.client[table_name] : undefined;

    if (!isDelegate(table)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `Prisma session table ${table_name} is invalid.`,
        });
    }

    return {
        create: async (session) => {
            await table.create({ data: session });
        },

        find: async ({ account_id, session_id }) => {
            const row = await table.findFirst({
                select,
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
                select,
                where: {
                    account_id,
                    expires_at: { gt: now },
                    revoked_at: null,
                },
            });

            return requireRows(rows);
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
