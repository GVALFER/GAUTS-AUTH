import { getTableColumns, getTableName, isTable } from "drizzle-orm";
import type { AnyMySqlTable } from "drizzle-orm/mysql-core";
import { createError } from "../../errors.js";
import { isRecord } from "../../session/guards.js";
import type { AuthScalar } from "../../session/types.js";
import { isPrivateField, type AdapterAccessValue } from "../model.js";
import type { ResolvedDrizzleDataModel, ResolvedDrizzleModels } from "./types.js";

type RequireTableInput = {
    fields: readonly string[];
    input: unknown;
    path: string;
};

type ResolveSelectInput = {
    columns: Record<string, unknown>;
    defaults: readonly string[];
    input: unknown;
    path: string;
};

type ResolveAccessInput = {
    columns: Record<string, unknown>;
    input: unknown;
    path: string;
};

type ResolveDataModelInput = {
    defaults: readonly string[];
    fields: readonly string[];
    input: unknown;
    path: string;
};

type ResolveTableModelInput = {
    fields: readonly string[];
    input: unknown;
    path: string;
};

export const DRIZZLE_FIELDS = {
    accounts: ["id", "email", "user_id"],
    sessions: [
        "account_id",
        "agent",
        "country",
        "created_at",
        "expires_at",
        "id",
        "ip",
        "platform",
        "revoked_at",
        "token_hash",
        "updated_at",
    ],
    socials: ["account_id", "created_at", "id", "provider", "provider_id"],
    users: ["id", "name"],
} as const;

const DRIZZLE_SELECT = {
    accounts: ["id", "email"],
    users: ["id", "name"],
} as const;

const isAuthScalar = (value: unknown): value is AuthScalar => {
    return (
        value === null ||
        typeof value === "boolean" ||
        typeof value === "string" ||
        (typeof value === "number" && Number.isFinite(value))
    );
};

const isAccessValue = (value: unknown): boolean => {
    return Array.isArray(value)
        ? value.length > 0 && value.every(isAuthScalar)
        : isAuthScalar(value);
};

const requireTable = ({ fields, input, path }: RequireTableInput): AnyMySqlTable => {
    if (!isTable(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.table must be a Drizzle MySQL table.`,
        });
    }

    const columns = getTableColumns(input);
    const missing = fields.filter((field) => !(field in columns));

    if (missing.length > 0) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.table is missing required columns: ${missing.join(", ")}.`,
        });
    }

    return input as AnyMySqlTable;
};

const resolveSelect = ({
    columns,
    defaults,
    input,
    path,
}: ResolveSelectInput): readonly string[] => {
    if (input === undefined) {
        return defaults;
    }

    if (
        !Array.isArray(input) ||
        input.some((field) => typeof field !== "string" || !field.trim()) ||
        new Set(input).size !== input.length ||
        input.some((field) => typeof field === "string" && isPrivateField(field)) ||
        input.some((field) => typeof field === "string" && !(field in columns))
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.select must contain unique public scalar column names.`,
        });
    }

    return [...new Set([...defaults, ...(input as string[])])];
};

const resolveAccess = ({
    columns,
    input,
    path,
}: ResolveAccessInput): Record<string, AdapterAccessValue> => {
    if (input === undefined) {
        return {};
    }

    if (
        !isRecord(input) ||
        Object.keys(input).some(isPrivateField) ||
        Object.keys(input).some((field) => !(field in columns)) ||
        Object.values(input).some((value) => !isAccessValue(value))
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.access contains an invalid condition.`,
        });
    }

    return input as Record<string, AdapterAccessValue>;
};

const resolveDataModel = ({
    defaults,
    fields,
    input,
    path,
}: ResolveDataModelInput): ResolvedDrizzleDataModel => {
    if (!isRecord(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path} model configuration is invalid.`,
        });
    }

    const table = requireTable({ fields, input: input.table, path });
    const columns = getTableColumns(table);

    return {
        access: resolveAccess({ columns, input: input.access, path }),
        select: resolveSelect({ columns, defaults, input: input.select, path }),
        table,
    };
};

const resolveTableModel = ({ fields, input, path }: ResolveTableModelInput): AnyMySqlTable => {
    if (!isRecord(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path} model configuration is invalid.`,
        });
    }

    return requireTable({ fields, input: input.table, path });
};

export const resolveDrizzleModels = (input: unknown): ResolvedDrizzleModels => {
    if (!isRecord(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Drizzle models configuration is invalid.",
        });
    }

    return {
        accounts: resolveDataModel({
            defaults: DRIZZLE_SELECT.accounts,
            fields: DRIZZLE_FIELDS.accounts,
            input: input.accounts,
            path: "models.accounts",
        }),
        sessions: resolveTableModel({
            fields: DRIZZLE_FIELDS.sessions,
            input: input.sessions,
            path: "models.sessions",
        }),
        socials:
            input.socials === undefined
                ? null
                : resolveTableModel({
                      fields: DRIZZLE_FIELDS.socials,
                      input: input.socials,
                      path: "models.socials",
                  }),
        users: resolveDataModel({
            defaults: DRIZZLE_SELECT.users,
            fields: DRIZZLE_FIELDS.users,
            input: input.users,
            path: "models.users",
        }),
    };
};

export const getDrizzleSource = (table: AnyMySqlTable): string => {
    return getTableName(table);
};
