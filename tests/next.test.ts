import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { NextRequest, NextResponse } from "next/server.js";
import {
    buildForwardHeaders,
    createNextAuth,
    FORWARD_HEADERS,
} from "../src/adapters/next/index.js";
import { isAuthError } from "../src/errors.js";

const token = "a".repeat(43);

const createRequest = ({
    renewAt = Math.floor(Date.now() / 1000) + 60,
}: { renewAt?: number | string | null } = {}) => {
    const cookies = [`other=private`, `session=${token}`];
    if (renewAt !== null) cookies.push(`session-renew=${String(renewAt)}`);

    return new NextRequest("https://admin.example.com/account", {
        headers: {
            Authorization: "Bearer private",
            Cookie: cookies.join("; "),
            "CF-Connecting-IP": "192.0.2.10",
            "User-Agent": "Next Test",
            "X-Private-Header": "private",
            "X-Forwarded-Host": "admin.example.com",
            "X-Forwarded-Proto": "https",
        },
    });
};

describe("Next adapter", () => {
    it("exports the controlled forwarding headers", () => {
        assert.deepEqual(FORWARD_HEADERS, [
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
        ]);
    });

    it("builds application forwarding headers with explicit extras", () => {
        const incoming = new Headers({
            Authorization: "Bearer private",
            Cookie: "session=private",
            "Sec-CH-UA": '"Chromium";v="151"',
            "User-Agent": "Next Test",
            "X-Forwarded-Host": "admin.example.com",
            "X-Forwarded-Port": "443",
            "X-Forwarded-Proto": "https",
            "X-Private-Header": "private",
        });
        const headers = buildForwardHeaders({
            extra: ["cookie", "authorization"],
            headers: incoming,
        });

        assert.equal(headers.get("authorization"), "Bearer private");
        assert.equal(headers.get("cookie"), "session=private");
        assert.equal(headers.get("origin"), "https://admin.example.com");
        assert.equal(headers.get("sec-ch-ua"), '"Chromium";v="151"');
        assert.equal(headers.get("user-agent"), "Next Test");
        assert.equal(headers.get("x-forwarded-port"), "443");
        assert.equal(headers.get("x-private-header"), null);
    });

    it("does not call the renewal endpoint before renewAt", async () => {
        const originalFetch = globalThis.fetch;
        let calls = 0;
        globalThis.fetch = async () => {
            calls += 1;
            return new Response(null, { status: 204 });
        };

        try {
            const auth = createNextAuth({
                cookie: { renewName: "session-renew", sessionName: "session" },
                renewUrl: "https://api.example.com/auth/renew",
            });
            const result = await auth.renew({
                request: createRequest(),
                response: NextResponse.next(),
            });

            assert.equal(result.attempted, false);
            assert.equal(result.status, null);
            assert.equal(calls, 0);
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("renews when renewAt is missing and forwards every Set-Cookie", async () => {
        const originalFetch = globalThis.fetch;
        let request: Parameters<typeof fetch>[0] | undefined;
        let init: RequestInit | undefined;
        globalThis.fetch = async (input, options) => {
            request = input;
            init = options;
            const headers = new Headers();
            headers.append("Set-Cookie", "session=updated; Path=/; HttpOnly");
            headers.append("Set-Cookie", "session-renew=1786968000; Path=/; HttpOnly");

            return new Response(null, { headers, status: 204 });
        };

        try {
            const auth = createNextAuth({
                cookie: { renewName: "session-renew", sessionName: "session" },
                renewUrl: "https://api.example.com/auth/renew",
            });
            const result = await auth.renew({
                request: createRequest({ renewAt: null }),
                response: NextResponse.next(),
            });

            assert.equal(result.attempted, true);
            assert.equal(result.status, 204);
            assert.equal(request, "https://api.example.com/auth/renew");
            assert.equal(init?.method, "POST");
            assert.equal(init?.redirect, "error");
            assert.ok(init?.signal instanceof AbortSignal);

            const headers = new Headers(init?.headers);
            assert.equal(headers.get("cookie"), `session=${token}`);
            assert.equal(headers.get("cookie")?.includes("other=private"), false);
            assert.equal(headers.get("authorization"), null);
            assert.equal(headers.get("x-private-header"), null);
            assert.equal(headers.get("cf-connecting-ip"), "192.0.2.10");
            assert.equal(headers.get("origin"), "https://admin.example.com");
            assert.equal(headers.get("user-agent"), "Next Test");
            assert.equal(headers.get("x-forwarded-host"), "admin.example.com");

            const setCookies = (
                result.response.headers as Headers & { getSetCookie: () => string[] }
            ).getSetCookie();
            assert.deepEqual(setCookies, [
                "session=updated; Path=/; HttpOnly",
                "session-renew=1786968000; Path=/; HttpOnly",
            ]);
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("applies renewal cookies to the application unauthorized response", async () => {
        const originalFetch = globalThis.fetch;
        globalThis.fetch = async () => {
            const headers = new Headers();
            headers.append("Set-Cookie", "session=; Max-Age=0; Path=/; HttpOnly");
            headers.append("Set-Cookie", "session-renew=; Max-Age=0; Path=/; HttpOnly");

            return new Response(null, { headers, status: 401 });
        };

        try {
            const auth = createNextAuth({
                cookie: { renewName: "session-renew", sessionName: "session" },
                renewUrl: "https://api.example.com/auth/renew",
            });
            const result = await auth.renew({
                request: createRequest({ renewAt: null }),
                response: NextResponse.next(),
                unauthorizedUrl: "/auth/login",
            });

            assert.equal(result.attempted, true);
            assert.equal(result.status, 401);
            assert.equal(result.response.status, 307);
            assert.equal(
                result.response.headers.get("location"),
                "https://admin.example.com/auth/login",
            );
            assert.deepEqual(
                (
                    result.response.headers as Headers & {
                        getSetCookie: () => string[];
                    }
                ).getSetCookie(),
                [
                    "session=; Max-Age=0; Path=/; HttpOnly",
                    "session-renew=; Max-Age=0; Path=/; HttpOnly",
                ],
            );
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("derives the public origin from the forwarded host", async () => {
        const originalFetch = globalThis.fetch;
        let init: RequestInit | undefined;
        globalThis.fetch = async (_input, options) => {
            init = options;
            return new Response(null, { status: 204 });
        };

        try {
            const auth = createNextAuth({
                cookie: { renewName: "session-renew", sessionName: "session" },
                renewUrl: "http://api:4002/auth/renew",
            });
            const request = new NextRequest("https://0.0.0.0:4001/account", {
                headers: {
                    Cookie: `session=${token}`,
                    "X-Forwarded-Host": "admin.example.com",
                    "X-Forwarded-Proto": "https",
                },
            });

            await auth.renew({
                request,
                response: NextResponse.next(),
            });

            const headers = new Headers(init?.headers);
            assert.equal(headers.get("origin"), "https://admin.example.com");
            assert.equal(headers.get("x-forwarded-host"), "admin.example.com");
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("does not invent missing proxy headers", async () => {
        const originalFetch = globalThis.fetch;
        let init: RequestInit | undefined;
        globalThis.fetch = async (_input, options) => {
            init = options;
            return new Response(null, { status: 204 });
        };

        try {
            const auth = createNextAuth({
                cookie: { renewName: "session-renew", sessionName: "session" },
                renewUrl: "http://api:4002/auth/renew",
            });
            const request = new NextRequest("https://0.0.0.0:4001/account", {
                headers: { Cookie: `session=${token}` },
            });

            await auth.renew({
                request,
                response: NextResponse.next(),
            });

            const headers = new Headers(init?.headers);
            assert.equal(headers.get("origin"), null);
            assert.equal(headers.get("x-forwarded-host"), null);
            assert.equal(headers.get("x-forwarded-proto"), null);
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("renews when renewAt is expired or invalid", async () => {
        const originalFetch = globalThis.fetch;
        let calls = 0;
        globalThis.fetch = async () => {
            calls += 1;
            return new Response(null, { status: 204 });
        };

        try {
            const auth = createNextAuth({
                cookie: { renewName: "session-renew", sessionName: "session" },
                renewUrl: "https://api.example.com/auth/renew",
            });

            for (const renewAt of [Math.floor(Date.now() / 1000) - 1, "invalid", "0"]) {
                const result = await auth.renew({
                    request: createRequest({ renewAt }),
                    response: NextResponse.next(),
                });

                assert.equal(result.attempted, true);
                assert.equal(result.status, 204);
            }

            assert.equal(calls, 3);
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("reports a missing or malformed session cookie without calling the API", async () => {
        const auth = createNextAuth({
            cookie: { renewName: "session-renew", sessionName: "session" },
            renewUrl: "https://api.example.com/auth/renew",
        });
        const missing = await auth.renew({
            request: new NextRequest("https://admin.example.com/account"),
            response: NextResponse.next(),
            unauthorizedUrl: "/auth/login",
        });
        const malformed = await auth.renew({
            request: new NextRequest("https://admin.example.com/account", {
                headers: { Cookie: "session=invalid" },
            }),
            response: NextResponse.next(),
        });

        assert.equal(missing.attempted, false);
        assert.equal(missing.status, 401);
        assert.equal(missing.response.status, 307);
        assert.equal(malformed.attempted, false);
        assert.equal(malformed.status, 401);
    });

    it("rejects invalid configuration", () => {
        assert.throws(
            () => createNextAuth({ renewUrl: "not-a-url" }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createNextAuth({
                    cookie: { sessionName: "invalid cookie" },
                    renewUrl: "https://api.example.com/auth/renew",
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createNextAuth({
                    cookie: { renewName: "session", sessionName: "session" },
                    renewUrl: "https://api.example.com/auth/renew",
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
