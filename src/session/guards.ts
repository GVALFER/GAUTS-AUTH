import type { AuthAccount, AuthUser } from "./types.js";

export const isRecord = (value: unknown): value is Record<string, unknown> => {
    return typeof value === "object" && value !== null && !Array.isArray(value);
};

export const isNullableString = (value: unknown): value is string | null => {
    return typeof value === "string" || value === null;
};

export const isAuthUser = (value: unknown): value is AuthUser => {
    return (
        isRecord(value) &&
        typeof value.id === "string" &&
        typeof value.role === "string" &&
        typeof value.status === "string"
    );
};

export const isAuthAccount = (value: unknown): value is AuthAccount => {
    return (
        isRecord(value) &&
        typeof value.email === "string" &&
        typeof value.id === "string" &&
        typeof value.name === "string" &&
        typeof value.role === "string" &&
        typeof value.status === "string" &&
        isNullableString(value.timezone) &&
        isAuthUser(value.user)
    );
};
