import type { NextRequest, NextResponse } from "next/server.js";
import { createError } from "../../errors.js";
import { parseSessionCookie, resolveSessionCookieName } from "../../session/cookie.js";

export type NextCookieConfig = {
    name?: string;
};

export type NextAuthConfig = {
    cookie?: NextCookieConfig;
    renewUrl: string;
};

export type NextRenewInput = {
    request: NextRequest;
    response: NextResponse;
};

export type NextRenewResult = {
    attempted: boolean;
    response: NextResponse;
    status: number | null;
};

export type NextAuth = {
    renew(input: NextRenewInput): Promise<NextRenewResult>;
};

type ForwardHeadersInput = {
    cookie: string;
    name: string;
    request: NextRequest;
};

const RENEW_TIMEOUT = 5_000;

export const FORWARD_HEADERS = [
    "cf-connecting-ip",
    "origin",
    "referer",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "true-client-ip",
    "user-agent",
    "x-forwarded-for",
    "x-real-ip",
] as const;

const getSetCookies = (headers: Headers): string[] => {
    const cookieHeaders = headers as Headers & {
        getSetCookie?: () => string[];
    };

    if (typeof cookieHeaders.getSetCookie === "function") {
        return cookieHeaders.getSetCookie();
    }

    const cookie = headers.get("set-cookie");
    return cookie ? [cookie] : [];
};

const getForwardHeaders = ({ cookie, name, request }: ForwardHeadersInput): Headers => {
    const headers = new Headers({ cookie: `${name}=${cookie}` });

    for (const header of FORWARD_HEADERS) {
        const value = request.headers.get(header);

        if (value !== null) {
            headers.set(header, value);
        }
    }

    return headers;
};

export const createNextAuth = ({ cookie, renewUrl }: NextAuthConfig): NextAuth => {
    const name = resolveSessionCookieName(cookie?.name);
    let url: URL;

    try {
        url = new URL(renewUrl);
    } catch (error) {
        throw createError({
            cause: error,
            code: "AUTH_CONFIG_INVALID",
            message: "Next renewal URL is invalid.",
        });
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Next renewal URL must use HTTP or HTTPS.",
        });
    }

    return {
        renew: async ({ request, response }) => {
            const cookieValue = request.cookies.get(name)?.value;
            const session = parseSessionCookie(cookieValue);

            if (!session || !cookieValue) {
                return {
                    attempted: false,
                    response,
                    status: 401,
                };
            }

            if (session.renew_at.getTime() > Date.now()) {
                return {
                    attempted: false,
                    response,
                    status: null,
                };
            }

            const renewal = await fetch(url.toString(), {
                cache: "no-store",
                headers: getForwardHeaders({ cookie: cookieValue, name, request }),
                method: "POST",
                redirect: "error",
                signal: AbortSignal.timeout(RENEW_TIMEOUT),
            });

            for (const value of getSetCookies(renewal.headers)) {
                response.headers.append("set-cookie", value);
            }

            return {
                attempted: true,
                response,
                status: renewal.status,
            };
        },
    };
};
