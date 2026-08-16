import type { SessionClient } from "../client/index.js";
import { createError } from "../errors.js";
import type { Session, StoredSession } from "./types.js";

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === "object" && value !== null && !Array.isArray(value);

const isNullableString = (value: unknown): value is string | null => {
    return typeof value === "string" || value === null;
};

const isDateString = (value: unknown): value is string => {
    return typeof value === "string" && Number.isFinite(Date.parse(value));
};

const isClient = (value: unknown): value is SessionClient => {
    return (
        isRecord(value) &&
        isNullableString(value.agent) &&
        isNullableString(value.ip) &&
        isNullableString(value.platform)
    );
};

export const encodeSession = <TData extends object>(session: StoredSession<TData>): string => {
    try {
        return JSON.stringify(session);
    } catch (error) {
        throw createError({
            cause: error,
            code: "SESSION_DATA_INVALID",
            message: "Session data must be JSON serializable.",
        });
    }
};

export const parseSession = <TData extends object>(raw: string): StoredSession<TData> | null => {
    let value: unknown;

    try {
        value = JSON.parse(raw) as unknown;
    } catch {
        return null;
    }

    if (
        !isRecord(value) ||
        typeof value.id !== "string" ||
        typeof value.account_id !== "string" ||
        !isRecord(value.data) ||
        !isClient(value.client) ||
        !isDateString(value.created_at) ||
        !isDateString(value.touched_at) ||
        !isDateString(value.expires_at)
    ) {
        return null;
    }

    return value as StoredSession<TData>;
};

export const toSession = <TData extends object>(stored: StoredSession<TData>): Session<TData> => ({
    account_id: stored.account_id,
    client: stored.client,
    created_at: new Date(stored.created_at),
    data: stored.data,
    expires_at: new Date(stored.expires_at),
    id: stored.id,
    touched_at: new Date(stored.touched_at),
});
