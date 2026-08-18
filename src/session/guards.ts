import type { AuthAccount, AuthValue } from "./types.js";

export const isRecord = (value: unknown): value is Record<string, unknown> => {
    return typeof value === "object" && value !== null && !Array.isArray(value);
};

export const isNullableString = (value: unknown): value is string | null => {
    return typeof value === "string" || value === null;
};

export const isAuthValue = (value: unknown): value is AuthValue => {
    if (
        value === null ||
        typeof value === "boolean" ||
        typeof value === "number" ||
        typeof value === "string"
    ) {
        return typeof value !== "number" || Number.isFinite(value);
    }

    if (Array.isArray(value)) {
        return value.every(isAuthValue);
    }

    return isRecord(value) && Object.values(value).every(isAuthValue);
};

export const isAuthAccount = (value: unknown): value is AuthAccount => {
    return (
        isRecord(value) &&
        typeof value.email === "string" &&
        typeof value.id === "string" &&
        isRecord(value.user) &&
        typeof value.user.id === "string" &&
        typeof value.user.name === "string" &&
        Object.values(value).every(isAuthValue)
    );
};
