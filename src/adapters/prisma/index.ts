import { createError } from "../../errors.js";
import { isAuthAccount, isNullableString, isRecord } from "../../session/guards.js";
import type { AuthSessionRecord, DbAdapter, SessionRecord } from "../../session/types.js";

const DEFAULT_TABLE = "account_sessions";

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

export type PrismaAccessConfig = {
    role?: readonly string[];
    status: readonly string[];
};

type PrismaAuthConfig = {
    account: PrismaAccessConfig;
    user: PrismaAccessConfig;
};

export type PrismaAdapterConfig<Client> = PrismaAuthConfig & {
    table?: PrismaSessionTable<Client>;
};

type DefaultPrismaAdapterInput<Client extends object> = {
    client: Client;
    config: PrismaAdapterConfig<Client>;
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
    findUnique(args: unknown): Promise<unknown>;
    update(args: unknown): Promise<unknown>;
    updateMany(args: unknown): Promise<unknown>;
};

type ResolvedAccess = {
    role: readonly string[] | null;
    status: readonly string[];
};

type AccessRules = {
    account: ResolvedAccess;
    user: ResolvedAccess;
};

type ResolveValuesInput = {
    input: unknown;
    name: string;
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

const authSelect = {
    ...select,
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
                    role: true,
                    status: true,
                },
            },
        },
    },
} as const;

const isNullableDate = (value: unknown): value is Date | null => {
    return value instanceof Date || value === null;
};

const isStringArray = (value: unknown): value is string[] => {
    return (
        Array.isArray(value) &&
        value.every((item: unknown) => typeof item === "string" && item.length > 0)
    );
};

const isDelegate = (value: unknown): value is Delegate => {
    return (
        isRecord(value) &&
        typeof value.create === "function" &&
        typeof value.findFirst === "function" &&
        typeof value.findMany === "function" &&
        typeof value.findUnique === "function" &&
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

const resolveValues = ({ input, name }: ResolveValuesInput): readonly string[] => {
    if (!isStringArray(input) || input.length === 0 || new Set(input).size !== input.length) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${name} must contain unique non-empty strings.`,
        });
    }

    return input;
};

const resolveAccess = (config: unknown): AccessRules => {
    if (!isRecord(config) || !isRecord(config.account) || !isRecord(config.user)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Prisma account and user access rules are required.",
        });
    }

    return {
        account: {
            role:
                config.account.role === undefined
                    ? null
                    : resolveValues({ input: config.account.role, name: "account.role" }),
            status: resolveValues({ input: config.account.status, name: "account.status" }),
        },
        user: {
            role:
                config.user.role === undefined
                    ? null
                    : resolveValues({ input: config.user.role, name: "user.role" }),
            status: resolveValues({ input: config.user.status, name: "user.status" }),
        },
    };
};

const resolveTable = (config: unknown): string => {
    if (!isRecord(config) || config.table === undefined) {
        return DEFAULT_TABLE;
    }

    if (typeof config.table !== "string" || !config.table) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Prisma session table name is invalid.",
        });
    }

    return config.table;
};

const matchesAccess = (value: { role: string; status: string }, rule: ResolvedAccess) => {
    return rule.status.includes(value.status) && (!rule.role || rule.role.includes(value.role));
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

const requireAuthRow = (value: unknown, access: AccessRules): AuthSessionRecord => {
    const row = requireRow(value);

    if (!isRecord(value) || !isAuthAccount(value.account)) {
        throw new Error("Prisma account relation returned invalid data.");
    }

    return {
        ...row,
        account: value.account,
        allowed:
            matchesAccess(value.account, access.account) &&
            matchesAccess(value.account.user, access.user),
    };
};

export const createPrismaAdapter = <Client extends object>(
    input: PrismaAdapterInput<Client>,
): DbAdapter => {
    const config: unknown = input.config;
    const table_name = resolveTable(config);
    const table = isRecord(input.client) ? input.client[table_name] : undefined;
    const access = resolveAccess(config);

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

        findToken: async (token_hash) => {
            const row = await table.findUnique({
                select: authSelect,
                where: { token_hash },
            });

            return row === null ? null : requireAuthRow(row, access);
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
