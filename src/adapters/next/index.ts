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

const getForwardHeaders = (request: NextRequest): Headers => {
    const headers = new Headers(request.headers);

    headers.delete("connection");
    headers.delete("content-length");
    headers.delete("host");
    headers.delete("transfer-encoding");

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
            const session = parseSessionCookie(request.cookies.get(name)?.value);

            if (!session) {
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
                headers: getForwardHeaders(request),
                method: "POST",
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
