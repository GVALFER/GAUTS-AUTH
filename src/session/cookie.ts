import { COOKIE_DEFAULTS } from "../config.js";
import { createError } from "../errors.js";
import { tokenPattern } from "./token.js";

export type SessionCookieNamesInput = {
    cacheName?: string;
    renewName?: string;
    sessionName?: string;
};

export type SessionCookieNames = {
    cacheName: string;
    renewName: string;
    sessionName: string;
};

const cookieNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const renewAtPattern = /^[1-9]\d*$/;

export const formatRenewAt = (value: Date): string => {
    const seconds = Math.floor(value.getTime() / 1000);

    if (!Number.isSafeInteger(seconds) || seconds < 1) {
        throw createError({
            code: "SESSION_DATA_INVALID",
            message: "Session renewal date is invalid.",
        });
    }

    return seconds.toString();
};

export const parseRenewAt = (value?: string | null): number | null => {
    const input = value?.trim();

    if (!input || !renewAtPattern.test(input)) {
        return null;
    }

    const seconds = Number(input);
    return Number.isSafeInteger(seconds) ? seconds : null;
};

export const resolveSessionCookieName = (input?: string): string => {
    const name = input ?? COOKIE_DEFAULTS.sessionName;

    if (!cookieNamePattern.test(name)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie name is invalid.",
        });
    }

    return name;
};

export const resolveSessionCookieNames = (
    input: SessionCookieNamesInput = {},
): SessionCookieNames => {
    const cacheName = resolveSessionCookieName(input.cacheName ?? COOKIE_DEFAULTS.cacheName);
    const renewName = resolveSessionCookieName(input.renewName ?? COOKIE_DEFAULTS.renewName);
    const sessionName = resolveSessionCookieName(input.sessionName);

    if (new Set([sessionName, cacheName, renewName]).size !== 3) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie names must be unique.",
        });
    }

    return { cacheName, renewName, sessionName };
};

export const parseSessionToken = (value?: string | null): string | null => {
    const token = value?.trim();
    return token && tokenPattern.test(token) ? token : null;
};
