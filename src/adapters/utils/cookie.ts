import { parseCookie, stringifySetCookie } from "cookie";
import { createError } from "../../errors.js";
import { resolveSessionCookieNames } from "../../session/cookie.js";
import type { HttpCookieConfig, HttpCookieOptions, ResolvedHttpCookie } from "./types.js";

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
    return header ? parseCookie(header)[name] : undefined;
};

export const createCookieHeader = ({
    expires,
    maxAge,
    name,
    options,
    value,
}: CookieHeaderInput): string => {
    return stringifySetCookie({
        ...options,
        ...(expires === undefined ? {} : { expires }),
        ...(maxAge === undefined ? {} : { maxAge }),
        name,
        sameSite: options.sameSite.toLowerCase() as "strict" | "lax" | "none",
        value,
    });
};

export const resolveHttpCookie = (config: HttpCookieConfig = {}): ResolvedHttpCookie => {
    const names = resolveSessionCookieNames(config);
    const path = config.path ?? "/";
    const sameSite = config.sameSite ?? "Lax";
    const secure = config.secure ?? true;

    if (!path.startsWith("/")) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie path must start with /.",
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
            httpOnly: true,
            path,
            sameSite,
            secure,
        },
    };
};
