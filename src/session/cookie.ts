import { createError } from "../errors.js";
import { tokenPattern } from "./token.js";

export type SessionCookieNamesInput = {
    cacheName?: string;
    name?: string;
    renewName?: string;
};

export type SessionCookieNames = {
    cacheName: string;
    name: string;
    renewName: string;
};

export const RENEW_COOKIE_VALUE = "1";

const cookieNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export const resolveSessionCookieName = (input?: string): string => {
    const name = input ?? "__sec";

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
    const name = resolveSessionCookieName(input.name);
    const cacheName = resolveSessionCookieName(input.cacheName ?? "__cac");
    const renewName = resolveSessionCookieName(input.renewName ?? "__ren");

    if (new Set([name, cacheName, renewName]).size !== 3) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie names must be unique.",
        });
    }

    return { cacheName, name, renewName };
};

export const parseSessionToken = (value?: string | null): string | null => {
    const token = value?.trim();
    return token && tokenPattern.test(token) ? token : null;
};
