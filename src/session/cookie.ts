import { COOKIE_DEFAULTS } from "../config.js";
import { createError } from "../errors.js";
import { tokenPattern } from "./token.js";

export type SessionCookieNamesInput = {
    contextName?: string;
    sessionName?: string;
};

export type SessionCookieNames = {
    contextName: string;
    sessionName: string;
};

type ResolveCookieNameInput = {
    input: string;
    label: string;
};

const cookieNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export const resolveCookieName = ({ input, label }: ResolveCookieNameInput): string => {
    const name = input;

    if (!cookieNamePattern.test(name)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${label} cookie name is invalid.`,
        });
    }

    return name;
};

export const resolveSessionCookieName = (input?: string): string => {
    return resolveCookieName({
        input: input ?? COOKIE_DEFAULTS.sessionName,
        label: "Session",
    });
};

export const resolveSessionCookieNames = (
    input: SessionCookieNamesInput = {},
): SessionCookieNames => {
    const contextName = resolveCookieName({
        input: input.contextName ?? COOKIE_DEFAULTS.contextName,
        label: "Context",
    });

    const sessionName = resolveSessionCookieName(input.sessionName);

    if (contextName === sessionName) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie names must be unique.",
        });
    }

    return { contextName, sessionName };
};

export const parseSessionToken = (value?: string | null): string | null => {
    const token = value?.trim();
    return token && tokenPattern.test(token) ? token : null;
};
