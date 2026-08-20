import { createError } from "../../errors.js";
import { resolveSessionCookieNames } from "../../session/cookie.js";
import type { HttpCookieConfig, HttpCookieOptions, ResolvedHttpCookie } from "./types.js";

const domainPattern =
    /^(?:\.?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

const pathPattern = /^[\u0020-\u003A\u003D-\u007E]*$/;

type CookieHeaderInput = {
    expires?: Date;
    maxAge?: number;
    name: string;
    options: HttpCookieOptions;
    value: string;
};

type GetCookieValueInput = {
    header?: string;
    name: string;
};

export const getCookieValue = ({ header, name }: GetCookieValueInput): string | undefined => {
    if (!header) return undefined;

    for (const part of header.split(";")) {
        const separator = part.indexOf("=");

        if (separator < 1 || part.slice(0, separator).trim() !== name) continue;

        const value = part.slice(separator + 1).trim();

        try {
            return decodeURIComponent(value);
        } catch {
            return value;
        }
    }

    return undefined;
};

export const createCookieHeader = ({
    expires,
    maxAge,
    name,
    options,
    value,
}: CookieHeaderInput): string => {
    if (maxAge !== undefined && !Number.isInteger(maxAge)) {
        throw new TypeError(`Cookie Max-Age is invalid: ${String(maxAge)}`);
    }

    if (expires !== undefined && !Number.isFinite(expires.valueOf())) {
        throw new TypeError("Cookie Expires is invalid.");
    }

    const parts = [`${name}=${encodeURIComponent(value)}`];

    if (maxAge !== undefined) {
        parts.push(`Max-Age=${String(maxAge)}`);
    }

    if (options.domain) {
        parts.push(`Domain=${options.domain}`);
    }

    parts.push(`Path=${options.path}`);

    if (expires !== undefined) {
        parts.push(`Expires=${expires.toUTCString()}`);
    }

    parts.push("HttpOnly");

    if (options.secure) {
        parts.push("Secure");
    }

    parts.push(`SameSite=${options.sameSite}`);

    return parts.join("; ");
};

export const resolveHttpCookie = (config: HttpCookieConfig = {}): ResolvedHttpCookie => {
    const names = resolveSessionCookieNames(config);
    const path = config.path ?? "/";
    const sameSite = config.sameSite ?? "Lax";
    const secure = config.secure ?? true;

    if (!path.startsWith("/") || !pathPattern.test(path)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie path is invalid.",
        });
    }

    if (config.domain && !domainPattern.test(config.domain)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie domain is invalid.",
        });
    }

    for (const name of Object.values(names)) {
        if (name.startsWith("__Host-") && (!secure || path !== "/" || config.domain)) {
            throw createError({
                code: "AUTH_CONFIG_INVALID",
                message: "__Host- cookies require secure=true, path=/, and no domain.",
            });
        }

        if (name.startsWith("__Secure-") && !secure) {
            throw createError({
                code: "AUTH_CONFIG_INVALID",
                message: "__Secure- cookies require secure=true.",
            });
        }
    }

    if (sameSite === "None" && !secure) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "SameSite=None cookies require secure=true.",
        });
    }

    return {
        names,
        options: {
            ...(config.domain ? { domain: config.domain } : {}),
            path,
            sameSite,
            secure,
        },
    };
};
