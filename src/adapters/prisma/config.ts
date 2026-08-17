import { createError } from "../../errors.js";
import { isRecord } from "../../session/guards.js";
import type { AuthScalar } from "../../session/types.js";
import type {
    PrismaAccessValue,
    PrismaDelegate,
    ResolvedPrismaModel,
    ResolvedPrismaModels,
} from "./types.js";

const PRISMA_DEFAULTS = {
    account: {
        name: "account",
        select: ["id", "email"],
    },
    relation: {
        select: ["id"],
    },
    sessions: {
        name: "sessions",
    },
} as const;

type ResolveModelInput = {
    client: object;
    defaultName: string;
    defaultSelect: readonly string[];
    input: unknown;
    path: string;
    relation: string;
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

const resolveName = ({ input, path }: { input: unknown; path: string }): string => {
    if (typeof input !== "string" || !input.trim()) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path} must be a non-empty string.`,
        });
    }

    return input;
};

const resolveSelect = ({
    defaultSelect,
    input,
    path,
}: {
    defaultSelect: readonly string[];
    input: unknown;
    path: string;
}): readonly string[] => {
    if (input === undefined) {
        return defaultSelect;
    }

    if (!Array.isArray(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.select must contain unique non-empty field names.`,
        });
    }

    const fields: unknown[] = input;

    if (
        fields.some((field) => typeof field !== "string" || !field.trim()) ||
        new Set(fields).size !== fields.length
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.select must contain unique non-empty field names.`,
        });
    }

    const names = fields as string[];

    return names.includes("id") ? names : ["id", ...names];
};

const isAccessValue = (value: unknown): value is PrismaAccessValue => {
    if (Array.isArray(value)) {
        return value.length > 0 && value.every(isAuthScalar);
    }

    return isAuthScalar(value);
};

const resolveAccess = ({ input, path }: { input: unknown; path: string }) => {
    if (input === undefined) {
        return {};
    }

    if (!isRecord(input) || Object.values(input).some((value) => !isAccessValue(value))) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.access contains an invalid condition.`,
        });
    }

    return input as Record<string, PrismaAccessValue>;
};

const resolveModel = ({
    client,
    defaultName,
    defaultSelect,
    input,
    path,
    relation,
}: ResolveModelInput): ResolvedPrismaModel => {
    if (input !== undefined && !isRecord(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path} model configuration is invalid.`,
        });
    }

    const config = isRecord(input) ? input : {};

    const name =
        config.name === undefined
            ? defaultName
            : resolveName({ input: config.name, path: `${path}.name` });

    const delegate = isRecord(client) ? client[name] : undefined;

    if (!isPrismaDelegate(delegate)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `Prisma model ${name} is invalid.`,
        });
    }

    if (config.relations !== undefined && !isRecord(config.relations)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${path}.relations is invalid.`,
        });
    }

    const relations = Object.fromEntries(
        Object.entries(isRecord(config.relations) ? config.relations : {}).map(
            ([relationName, relationConfig]) => [
                relationName,
                resolveModel({
                    client,
                    defaultName: relationName,
                    defaultSelect: PRISMA_DEFAULTS.relation.select,
                    input: relationConfig,
                    path: `${path}.relations.${relationName}`,
                    relation: relationName,
                }),
            ],
        ),
    );

    return {
        access: resolveAccess({ input: config.access, path }),
        name,
        relation,
        relations,
        select: resolveSelect({ defaultSelect, input: config.select, path }),
    };
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

    if (models.sessions !== undefined && !isRecord(models.sessions)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Prisma sessions model configuration is invalid.",
        });
    }

    const sessions = isRecord(models.sessions) ? models.sessions : {};
    const sessionName =
        sessions.name === undefined
            ? PRISMA_DEFAULTS.sessions.name
            : resolveName({ input: sessions.name, path: "models.sessions.name" });

    return {
        account: resolveModel({
            client,
            defaultName: PRISMA_DEFAULTS.account.name,
            defaultSelect: PRISMA_DEFAULTS.account.select,
            input: models.account,
            path: "models.account",
            relation: "account",
        }),
        sessions: sessionName,
    };
};
