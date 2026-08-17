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

export type PrismaAccessRules = {
    allowedRoles?: readonly string[];
    allowedStatuses: readonly string[];
};

export type PrismaRelationsConfig = {
    account?: string;
    user?: string;
};

export type PrismaSessionConfig<Client> = {
    relations?: PrismaRelationsConfig;
    table?: PrismaSessionTable<Client>;
};

export type PrismaAdapterConfig<Client> = {
    access: {
        account: PrismaAccessRules;
        user: PrismaAccessRules;
    };
    session?: PrismaSessionConfig<Client>;
};

type DefaultPrismaAdapterInput<Client extends object> = {
    client: Client;
    config: PrismaAdapterConfig<Client>;
};

type CustomPrismaAdapterInput<Client extends object> = {
    client: Client;
    config: PrismaAdapterConfig<Client> & {
        session: PrismaSessionConfig<Client> & {
            table: PrismaSessionTable<Client>;
        };
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
    roles: readonly string[] | null;
    statuses: readonly string[];
};

type AccessRules = {
    account: ResolvedAccess;
    user: ResolvedAccess;
};

type ResolveValuesInput = {
    input: unknown;
    name: string;
};

type Relations = {
    account: string;
    user: string;
};

type ResolvedConfig = {
    access: AccessRules;
    relations: Relations;
    table: string;
};

type RequireAuthRowInput = {
    access: AccessRules;
    relations: Relations;
    value: unknown;
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
    if (
        !isRecord(config) ||
        !isRecord(config.access) ||
        !isRecord(config.access.account) ||
        !isRecord(config.access.user)
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Prisma account and user access rules are required.",
        });
    }

    return {
        account: {
            roles:
                config.access.account.allowedRoles === undefined
                    ? null
                    : resolveValues({
                          input: config.access.account.allowedRoles,
                          name: "access.account.allowedRoles",
                      }),
            statuses: resolveValues({
                input: config.access.account.allowedStatuses,
                name: "access.account.allowedStatuses",
            }),
        },
        user: {
            roles:
                config.access.user.allowedRoles === undefined
                    ? null
                    : resolveValues({
                          input: config.access.user.allowedRoles,
                          name: "access.user.allowedRoles",
                      }),
            statuses: resolveValues({
                input: config.access.user.allowedStatuses,
                name: "access.user.allowedStatuses",
            }),
        },
    };
};

const resolveName = ({ input, name }: ResolveValuesInput): string => {
    if (typeof input !== "string" || !input) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${name} must be a non-empty string.`,
        });
    }

    return input;
};

const resolveConfig = (config: unknown): ResolvedConfig => {
    if (!isRecord(config)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Prisma configuration is required.",
        });
    }

    if (config.session !== undefined && !isRecord(config.session)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Prisma session configuration is invalid.",
        });
    }

    const session = isRecord(config.session) ? config.session : {};

    if (session.relations !== undefined && !isRecord(session.relations)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Prisma session relations are invalid.",
        });
    }

    const relations = isRecord(session.relations) ? session.relations : {};

    return {
        access: resolveAccess(config),
        relations: {
            account:
                relations.account === undefined
                    ? "account"
                    : resolveName({
                          input: relations.account,
                          name: "session.relations.account",
                      }),
            user:
                relations.user === undefined
                    ? "user"
                    : resolveName({ input: relations.user, name: "session.relations.user" }),
        },
        table:
            session.table === undefined
                ? DEFAULT_TABLE
                : resolveName({ input: session.table, name: "session.table" }),
    };
};

const matchesAccess = (value: { role: string; status: string }, rule: ResolvedAccess) => {
    return rule.statuses.includes(value.status) && (!rule.roles || rule.roles.includes(value.role));
};

const createAuthSelect = (relations: Relations) => ({
    ...select,
    [relations.account]: {
        select: {
            email: true,
            id: true,
            name: true,
            role: true,
            status: true,
            timezone: true,
            [relations.user]: {
                select: {
                    id: true,
                    role: true,
                    status: true,
                },
            },
        },
    },
});

const requireRow = (value: unknown): SessionRecord => {
    if (!isSessionRecord(value)) {
        throw new Error("Prisma session table returned invalid data.");
    }

    return {
        account_id: value.account_id,
        agent: value.agent,
        created_at: value.created_at,
        expires_at: value.expires_at,
        id: value.id,
        ip: value.ip,
        platform: value.platform,
        revoked_at: value.revoked_at,
        token_hash: value.token_hash,
        updated_at: value.updated_at,
    };
};

const requireRows = (value: unknown): SessionRecord[] => {
    if (!Array.isArray(value)) {
        throw new Error("Prisma session table returned invalid data.");
    }

    return value.map(requireRow);
};

const requireAuthRow = ({ access, relations, value }: RequireAuthRowInput): AuthSessionRecord => {
    const row = requireRow(value);

    if (!isRecord(value)) {
        throw new Error("Prisma account relation returned invalid data.");
    }

    const relation = value[relations.account];

    if (!isRecord(relation)) {
        throw new Error("Prisma account relation returned invalid data.");
    }

    const account = {
        email: relation.email,
        id: relation.id,
        name: relation.name,
        role: relation.role,
        status: relation.status,
        timezone: relation.timezone,
        user: relation[relations.user],
    };

    if (!isAuthAccount(account)) {
        throw new Error("Prisma account relation returned invalid data.");
    }

    return {
        ...row,
        account,
        allowed: matchesAccess(account, access.account) && matchesAccess(account.user, access.user),
    };
};

export const createPrismaAdapter = <Client extends object>(
    input: PrismaAdapterInput<Client>,
): DbAdapter => {
    const config: unknown = input.config;
    const resolved = resolveConfig(config);
    const table_name = resolved.table;
    const table = isRecord(input.client) ? input.client[table_name] : undefined;
    const authSelect = createAuthSelect(resolved.relations);

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

            return row === null
                ? null
                : requireAuthRow({
                      access: resolved.access,
                      relations: resolved.relations,
                      value: row,
                  });
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
