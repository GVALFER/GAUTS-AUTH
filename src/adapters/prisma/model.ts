import { isRecord } from "../../session/guards.js";
import type { AuthSessionRecord } from "../../session/types.js";
import { readAdapterAccount, requireSessionRecord, requireSessionRecords } from "../model.js";
import type { ResolvedPrismaDataModel } from "./types.js";

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

export const readAccount = ({ accounts, users, value }: ReadAccountInput) => {
    if (!isRecord(value)) {
        throw new Error("Prisma account relation returned invalid data.");
    }

    return readAdapterAccount({
        account: value,
        accounts: { ...accounts, source: accounts.table },
        adapter: "Prisma",
        user: value.user,
        users: { ...users, source: users.table },
    });
};

export const requireRow = (value: unknown) => requireSessionRecord({ adapter: "Prisma", value });

export const requireRows = (value: unknown) => requireSessionRecords({ adapter: "Prisma", value });

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
