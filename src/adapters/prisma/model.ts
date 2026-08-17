import { isAuthValue, isNullableString, isRecord } from "../../session/guards.js";
import type {
    AuthAccount,
    AuthSessionRecord,
    AuthValue,
    SessionRecord,
} from "../../session/types.js";
import type { PrismaAccessValue, ResolvedPrismaModel } from "./types.js";

type ReadModelResult = {
    allowed: boolean;
    data: AuthAccount;
};

export const sessionSelect = {
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

const createModelSelect = (model: ResolvedPrismaModel): Record<string, unknown> => {
    const fields = new Set([...model.select, ...Object.keys(model.access)]);
    const select: Record<string, unknown> = Object.fromEntries(
        [...fields].map((field) => [field, true]),
    );

    for (const relation of Object.values(model.relations)) {
        select[relation.relation] = { select: createModelSelect(relation) };
    }

    return select;
};

export const createAuthSelect = (account: ResolvedPrismaModel) => ({
    ...sessionSelect,
    [account.relation]: {
        select: createModelSelect(account),
    },
});

const matchesAccess = ({
    access,
    value,
}: {
    access: Record<string, PrismaAccessValue>;
    value: Record<string, unknown>;
}): boolean => {
    return Object.entries(access).every(([field, expected]) => {
        const current = value[field];
        return Array.isArray(expected)
            ? expected.some((allowed) => Object.is(allowed, current))
            : Object.is(expected, current);
    });
};

const readModel = ({
    model,
    value,
}: {
    model: ResolvedPrismaModel;
    value: unknown;
}): ReadModelResult => {
    if (!isRecord(value)) {
        throw new Error(`Prisma relation ${model.relation} returned invalid data.`);
    }

    const data: Record<string, AuthValue> = {};

    for (const field of model.select) {
        const fieldValue = value[field];

        if (!isAuthValue(fieldValue) || isRecord(fieldValue) || Array.isArray(fieldValue)) {
            throw new Error(`Prisma field ${model.name}.${field} returned invalid payload data.`);
        }

        data[field] = fieldValue;
    }

    if (typeof data.id !== "string") {
        throw new Error(`Prisma model ${model.name} must return a string id.`);
    }

    let allowed = matchesAccess({ access: model.access, value });

    for (const relation of Object.values(model.relations)) {
        const nested = readModel({ model: relation, value: value[relation.relation] });
        data[relation.relation] = nested.data;
        allowed &&= nested.allowed;
    }

    return { allowed, data: data as AuthAccount };
};

export const requireRow = (value: unknown): SessionRecord => {
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

export const requireRows = (value: unknown): SessionRecord[] => {
    if (!Array.isArray(value)) {
        throw new Error("Prisma session table returned invalid data.");
    }

    return value.map(requireRow);
};

export const requireAuthRow = ({
    account,
    value,
}: {
    account: ResolvedPrismaModel;
    value: unknown;
}): AuthSessionRecord => {
    const row = requireRow(value);

    if (!isRecord(value)) {
        throw new Error("Prisma account relation returned invalid data.");
    }

    const resolved = readModel({ model: account, value: value[account.relation] });

    return {
        ...row,
        account: resolved.data,
        allowed: resolved.allowed,
    };
};
