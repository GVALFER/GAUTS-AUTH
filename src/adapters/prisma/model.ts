import { isAuthValue, isNullableString, isRecord } from "../../session/guards.js";
import type {
    AuthAccount,
    AuthData,
    AuthSessionRecord,
    AuthValue,
    SessionRecord,
} from "../../session/types.js";
import type { PrismaAccessValue, ResolvedPrismaDataModel } from "./types.js";

type ReadAccountResult = {
    account: AuthAccount;
    allowed: boolean;
};

type ReadDataInput = {
    model: ResolvedPrismaDataModel;
    value: unknown;
};

type ReadAccountInput = {
    accounts: ResolvedPrismaDataModel;
    users: ResolvedPrismaDataModel;
    value: unknown;
};

type RequireAuthRowInput = {
    accounts: ResolvedPrismaDataModel;
    users: ResolvedPrismaDataModel;
    value: unknown;
};

type CreateAuthSelectInput = {
    accounts: ResolvedPrismaDataModel;
    users: ResolvedPrismaDataModel;
};

type MatchesAccessInput = {
    access: Record<string, PrismaAccessValue>;
    value: Record<string, unknown>;
};

type CreateAccountSelectInput = {
    accounts: ResolvedPrismaDataModel;
    users: ResolvedPrismaDataModel;
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

const createModelSelect = (model: ResolvedPrismaDataModel): Record<string, true> => {
    return Object.fromEntries(
        [...new Set([...model.select, ...Object.keys(model.access)])].map((field) => [field, true]),
    );
};

export const createAccountSelect = ({ accounts, users }: CreateAccountSelectInput) => ({
    ...createModelSelect(accounts),
    user: {
        select: createModelSelect(users),
    },
});

export const createAuthSelect = ({ accounts, users }: CreateAuthSelectInput) => ({
    ...sessionSelect,
    account: {
        select: createAccountSelect({ accounts, users }),
    },
});

const matchesAccess = ({ access, value }: MatchesAccessInput): boolean => {
    return Object.entries(access).every(([field, expected]) => {
        const current = value[field];
        return Array.isArray(expected)
            ? expected.some((allowed) => Object.is(allowed, current))
            : Object.is(expected, current);
    });
};

const readData = ({ model, value }: ReadDataInput): AuthData => {
    if (!isRecord(value)) {
        throw new Error(`Prisma model ${model.table} returned invalid data.`);
    }

    const data: Record<string, AuthValue> = {};

    for (const field of model.select) {
        const fieldValue = value[field];

        if (!isAuthValue(fieldValue) || isRecord(fieldValue) || Array.isArray(fieldValue)) {
            throw new Error(`Prisma field ${model.table}.${field} returned invalid payload data.`);
        }

        data[field] = fieldValue;
    }

    return data;
};

export const readAccount = ({ accounts, users, value }: ReadAccountInput): ReadAccountResult => {
    if (!isRecord(value)) {
        throw new Error("Prisma account relation returned invalid data.");
    }

    const userValue = value.user;
    const account: Record<string, AuthValue> & { user: AuthData } = {
        ...readData({ model: accounts, value }),
        user: readData({ model: users, value: userValue }),
    };

    if (
        typeof account.id !== "string" ||
        typeof account.email !== "string" ||
        typeof account.user.id !== "string" ||
        typeof account.user.name !== "string"
    ) {
        throw new Error("Prisma account relation returned invalid data.");
    }

    return {
        account: account as AuthAccount,
        allowed:
            matchesAccess({ access: accounts.access, value }) &&
            isRecord(userValue) &&
            matchesAccess({ access: users.access, value: userValue }),
    };
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
    accounts,
    users,
    value,
}: RequireAuthRowInput): AuthSessionRecord => {
    const row = requireRow(value);

    if (!isRecord(value)) {
        throw new Error("Prisma account relation returned invalid data.");
    }

    const resolved = readAccount({ accounts, users, value: value.account });

    return {
        ...row,
        account: resolved.account,
        allowed: resolved.allowed,
    };
};
