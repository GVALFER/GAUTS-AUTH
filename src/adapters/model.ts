import { isAuthValue, isNullableString, isRecord } from "../session/guards.js";
import type {
    AuthAccount,
    AuthData,
    AuthScalar,
    AuthValue,
    SessionRecord,
} from "../session/types.js";

export const PRIVATE_FIELDS = ["hash", "password", "password_hash", "passwordHash"] as const;

export type AdapterAccessValue = AuthScalar | readonly AuthScalar[];

export type AdapterDataModel = {
    access: Record<string, AdapterAccessValue>;
    select: readonly string[];
    source: string;
};

type ReadDataInput = {
    adapter: string;
    model: AdapterDataModel;
    value: unknown;
};

type ReadAccountInput = {
    account: unknown;
    accounts: AdapterDataModel;
    adapter: string;
    user: unknown;
    users: AdapterDataModel;
};

type ReadAccountResult = {
    account: AuthAccount;
    allowed: boolean;
};

type MatchesAccessInput = {
    access: Record<string, AdapterAccessValue>;
    value: Record<string, unknown>;
};

type RequireSessionRecordInput = {
    adapter: string;
    value: unknown;
};

type RequireSessionRecordsInput = {
    adapter: string;
    value: unknown;
};

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

const matchesAccess = ({ access, value }: MatchesAccessInput): boolean => {
    return Object.entries(access).every(([field, expected]) => {
        const current = value[field];

        return Array.isArray(expected)
            ? expected.some((allowed) => Object.is(allowed, current))
            : Object.is(expected, current);
    });
};

const readData = ({ adapter, model, value }: ReadDataInput): AuthData => {
    if (!isRecord(value)) {
        throw new Error(`${adapter} model ${model.source} returned invalid data.`);
    }

    const data: Record<string, AuthValue> = {};

    for (const field of model.select) {
        const fieldValue = value[field];

        if (!isAuthValue(fieldValue) || isRecord(fieldValue) || Array.isArray(fieldValue)) {
            throw new Error(
                `${adapter} field ${model.source}.${field} returned invalid payload data.`,
            );
        }

        data[field] = fieldValue;
    }

    return data;
};

export const isPrivateField = (value: string): boolean => {
    return PRIVATE_FIELDS.some((field) => field === value);
};

export const readAdapterAccount = ({
    account,
    accounts,
    adapter,
    user,
    users,
}: ReadAccountInput): ReadAccountResult => {
    if (!isRecord(account) || !isRecord(user)) {
        throw new Error(`${adapter} account relation returned invalid data.`);
    }

    const data: Record<string, AuthValue> & { user: AuthData } = {
        ...readData({ adapter, model: accounts, value: account }),
        user: readData({ adapter, model: users, value: user }),
    };

    if (
        typeof data.id !== "string" ||
        typeof data.email !== "string" ||
        typeof data.user.id !== "string" ||
        typeof data.user.name !== "string"
    ) {
        throw new Error(`${adapter} account relation returned invalid data.`);
    }

    return {
        account: data as AuthAccount,
        allowed:
            matchesAccess({ access: accounts.access, value: account }) &&
            matchesAccess({ access: users.access, value: user }),
    };
};

export const requireSessionRecord = ({
    adapter,
    value,
}: RequireSessionRecordInput): SessionRecord => {
    if (!isSessionRecord(value)) {
        throw new Error(`${adapter} session table returned invalid data.`);
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

export const requireSessionRecords = ({
    adapter,
    value,
}: RequireSessionRecordsInput): SessionRecord[] => {
    if (!Array.isArray(value)) {
        throw new Error(`${adapter} session table returned invalid data.`);
    }

    return value.map((row) => requireSessionRecord({ adapter, value: row }));
};
