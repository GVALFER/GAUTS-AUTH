import type { NextRequest, NextResponse } from "next/server.js";

import { createError } from "../../errors.js";
import {
    parseRenewAt,
    parseSessionToken,
    resolveSessionCookieNames,
} from "../../session/cookie.js";

export type NextCookieConfig = {
    renewName?: string;
    sessionName?: string;
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

type RenewHeadersInput = {
    request: NextRequest;
    sessionName: string;
    token: string;
};

export type BuildForwardHeadersInput = {
    extra?: readonly string[];
    headers: Headers;
};

const RENEW_TIMEOUT = 5_000;

export const FORWARD_HEADERS = [
    "accept-language",
    "cf-connecting-ip",
    "origin",
    "referer",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "true-client-ip",
    "user-agent",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-real-ip",
] as const;

export const buildForwardHeaders = ({
    extra = [],
    headers: incoming,
}: BuildForwardHeadersInput): Headers => {
    const headers = new Headers();

    for (const name of [...FORWARD_HEADERS, ...extra]) {
        const value = incoming.get(name);

        if (value?.trim()) {
            headers.set(name, value);
        }
    }

    const origin = headers.get("origin")?.trim();
    const host = headers.get("x-forwarded-host")?.trim();
    const proto = headers.get("x-forwarded-proto")?.trim();

    if (!origin && host && proto) {
        headers.set("origin", `${proto}://${host}`);
    }

    return headers;
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

const getRenewHeaders = ({ request, sessionName, token }: RenewHeadersInput): Headers => {
    const headers = buildForwardHeaders({ headers: request.headers });
    headers.set("cookie", `${sessionName}=${token}`);

    return headers;
};

export const createNextAuth = ({ cookie, renewUrl }: NextAuthConfig): NextAuth => {
    const names = resolveSessionCookieNames(cookie);
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
            const token = parseSessionToken(request.cookies.get(names.sessionName)?.value);

            if (!token) {
                return {
                    attempted: false,
                    response,
                    status: 401,
                };
            }

            const renewAt = parseRenewAt(request.cookies.get(names.renewName)?.value);

            if (renewAt !== null && renewAt > Math.floor(Date.now() / 1000)) {
                return {
                    attempted: false,
                    response,
                    status: null,
                };
            }

            const renewal = await fetch(url.toString(), {
                cache: "no-store",
                headers: getRenewHeaders({ request, sessionName: names.sessionName, token }),
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
