import { createError } from "../errors.js";
import { tokenPattern } from "./token.js";

export type SessionCookie = {
    renew_at: Date;
    token: string;
};

const timestampPattern = /^[1-9][0-9]*$/;
const cookieNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export const resolveSessionCookieName = (input?: string): string => {
    const name = input ?? "__Host-session";

    if (!cookieNamePattern.test(name)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie name is invalid.",
        });
    }

    return name;
};

export const createSessionCookie = ({ renew_at, token }: SessionCookie): string => {
    const timestamp = Math.floor(renew_at.getTime() / 1000);

    if (!tokenPattern.test(token) || !Number.isSafeInteger(timestamp) || timestamp < 1) {
        throw createError({
            code: "SESSION_DATA_INVALID",
            message: "Session cookie data is invalid.",
        });
    }

    return `${token}.${String(timestamp)}`;
};

export const parseSessionCookie = (value?: string | null): SessionCookie | null => {
    const [token, timestamp, extra] = value?.trim().split(".") ?? [];

    if (!token || !timestamp || extra !== undefined) {
        return null;
    }

    if (!tokenPattern.test(token) || !timestampPattern.test(timestamp)) {
        return null;
    }

    const seconds = Number(timestamp);
    const renew_at = new Date(seconds * 1000);

    if (!Number.isSafeInteger(seconds) || Number.isNaN(renew_at.getTime())) {
        return null;
    }

    return { renew_at, token };
};
