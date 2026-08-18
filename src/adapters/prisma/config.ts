import { createError } from "../../errors.js";
import { isRecord } from "../../session/guards.js";
import type { AuthScalar } from "../../session/types.js";
import type {
    PrismaAccessValue,
    PrismaDelegate,
    ResolvedPrismaDataModel,
    ResolvedPrismaModels,
} from "./types.js";

const PRISMA_DEFAULTS = {
    accounts: {
        select: ["id", "email"],
        table: "user_accounts",
    },
    sessions: {
        table: "account_sessions",
    },
    socials: {
        table: "social_accounts",
    },
    users: {
        select: ["id", "name"],
        table: "users",
    },
    privateFields: ["hash", "password", "password_hash", "passwordHash"],
} as const;

const isPrivateField = (value: string): boolean => {
    return PRISMA_DEFAULTS.privateFields.some((field) => field === value);
};

type ResolveDataModelInput = {
    client: object;
    defaultSelect: readonly string[];
    defaultTable: string;
    input: unknown;
    path: string;
};

type ResolveSelectInput = {
    defaultSelect: readonly string[];
    input: unknown;
    path: string;
};

export const isPrismaDelegate = (value: unknown): value is PrismaDelegate => {
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

const isAuthScalar = (value: unknown): value is AuthScalar => {
    return (
        value === null ||
        typeof value === "boolean" ||
        typeof value === "string" ||
        (typeof value === "number" && Number.isFinite(value))
    );
};

const resolveTable = ({ input, path }: { input: unknown; path: string }): string => {
    if (typeof input !== "string" || !input.trim()) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.table must be a non-empty string.`,
        });
    }

    return input;
};

const requireDelegate = ({ client, table }: { client: object; table: string }): void => {
    const delegate = isRecord(client) ? client[table] : undefined;

    if (!isPrismaDelegate(delegate)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `Prisma model ${table} is invalid.`,
        });
    }
};

const resolveSelect = ({ defaultSelect, input, path }: ResolveSelectInput): readonly string[] => {
    if (input === undefined) {
        return defaultSelect;
    }

    if (
        !Array.isArray(input) ||
        input.some((field) => typeof field !== "string" || !field.trim()) ||
        new Set(input).size !== input.length ||
        input.some((field) => typeof field === "string" && isPrivateField(field))
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.select must contain unique non-empty field names.`,
        });
    }

    return [...new Set([...defaultSelect, ...(input as string[])])];
};

const isAccessValue = (value: unknown): value is PrismaAccessValue => {
    return Array.isArray(value)
        ? value.length > 0 && value.every(isAuthScalar)
        : isAuthScalar(value);
};

const resolveAccess = ({ input, path }: { input: unknown; path: string }) => {
    if (input === undefined) {
        return {};
    }

    if (
        !isRecord(input) ||
        Object.keys(input).some(isPrivateField) ||
        Object.values(input).some((value) => !isAccessValue(value))
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.access contains an invalid condition.`,
        });
    }

    return input as Record<string, PrismaAccessValue>;
};

const resolveDataModel = ({
    client,
    defaultSelect,
    defaultTable,
    input,
    path,
}: ResolveDataModelInput): ResolvedPrismaDataModel => {
    if (input !== undefined && !isRecord(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path} model configuration is invalid.`,
        });
    }

    const config = isRecord(input) ? input : {};
    const table =
        config.table === undefined ? defaultTable : resolveTable({ input: config.table, path });

    requireDelegate({ client, table });

    return {
        access: resolveAccess({ input: config.access, path }),
        select: resolveSelect({ defaultSelect, input: config.select, path }),
        table,
    };
};

const resolveTableModel = ({
    client,
    defaultTable,
    input,
    path,
}: Omit<ResolveDataModelInput, "defaultSelect">): string => {
    if (input !== undefined && !isRecord(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path} model configuration is invalid.`,
        });
    }

    const config = isRecord(input) ? input : {};
    const table =
        config.table === undefined ? defaultTable : resolveTable({ input: config.table, path });

    requireDelegate({ client, table });
    return table;
};

export const resolvePrismaModels = ({
    client,
    input,
}: {
    client: object;
    input: unknown;
}): ResolvedPrismaModels => {
    if (input !== undefined && !isRecord(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Prisma models configuration is invalid.",
        });
    }

    const models = isRecord(input) ? input : {};

    return {
        accounts: resolveDataModel({
            client,
            defaultSelect: PRISMA_DEFAULTS.accounts.select,
            defaultTable: PRISMA_DEFAULTS.accounts.table,
            input: models.accounts,
            path: "models.accounts",
        }),
        sessions: resolveTableModel({
            client,
            defaultTable: PRISMA_DEFAULTS.sessions.table,
            input: models.sessions,
            path: "models.sessions",
        }),
        socials: resolveTableModel({
            client,
            defaultTable: PRISMA_DEFAULTS.socials.table,
            input: models.socials,
            path: "models.socials",
        }),
        users: resolveDataModel({
            client,
            defaultSelect: PRISMA_DEFAULTS.users.select,
            defaultTable: PRISMA_DEFAULTS.users.table,
            input: models.users,
            path: "models.users",
        }),
    };
};
