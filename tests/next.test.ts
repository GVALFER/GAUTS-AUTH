import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { NextRequest, NextResponse } from "next/server.js";

import { createNextAuth, FORWARD_HEADERS } from "../src/adapters/next/index.js";
import { isAuthError } from "../src/errors.js";

const token = "a".repeat(43);

const createRequest = ({ renewal = true }: { renewal?: boolean } = {}) => {
    const cookies = [`other=private`, `session=${token}`];
    if (renewal) cookies.push("session-renew=1");

    return new NextRequest("https://admin.example.com/account", {
        headers: {
            Authorization: "Bearer private",
            Cookie: cookies.join("; "),
            "CF-Connecting-IP": "192.0.2.10",
            "User-Agent": "Next Test",
            "X-Private-Header": "private",
        },
    });
};

describe("Next adapter", () => {
    it("exports the controlled forwarding headers", () => {
        assert.deepEqual(FORWARD_HEADERS, [
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
        ]);
    });

    it("does not call the renewal endpoint while the marker exists", async () => {
        const originalFetch = globalThis.fetch;
        let calls = 0;
        globalThis.fetch = async () => {
            calls += 1;
            return new Response(null, { status: 204 });
        };

        try {
            const auth = createNextAuth({
                cookie: { name: "session", renewName: "session-renew" },
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

    it("renews when the marker is missing and forwards every Set-Cookie", async () => {
        const originalFetch = globalThis.fetch;
        let request: Parameters<typeof fetch>[0] | undefined;
        let init: RequestInit | undefined;
        globalThis.fetch = async (input, options) => {
            request = input;
            init = options;
            const headers = new Headers();
            headers.append("Set-Cookie", "session=updated; Path=/; HttpOnly");
            headers.append("Set-Cookie", "session-renew=1; Path=/; HttpOnly");

            return new Response(null, { headers, status: 204 });
        };

        try {
            const auth = createNextAuth({
                cookie: { name: "session", renewName: "session-renew" },
                renewUrl: "https://api.example.com/auth/renew",
            });
            const result = await auth.renew({
                request: createRequest({ renewal: false }),
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
            assert.equal(headers.get("user-agent"), "Next Test");

            const setCookies = (
                result.response.headers as Headers & { getSetCookie: () => string[] }
            ).getSetCookie();
            assert.deepEqual(setCookies, [
                "session=updated; Path=/; HttpOnly",
                "session-renew=1; Path=/; HttpOnly",
            ]);
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("reports a missing or malformed session cookie without calling the API", async () => {
        const auth = createNextAuth({
            cookie: { name: "session", renewName: "session-renew" },
            renewUrl: "https://api.example.com/auth/renew",
        });
        const missing = await auth.renew({
            request: new NextRequest("https://admin.example.com/account"),
            response: NextResponse.next(),
        });
        const malformed = await auth.renew({
            request: new NextRequest("https://admin.example.com/account", {
                headers: { Cookie: "session=invalid" },
            }),
            response: NextResponse.next(),
        });

        assert.equal(missing.attempted, false);
        assert.equal(missing.status, 401);
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
                    cookie: { name: "invalid cookie" },
                    renewUrl: "https://api.example.com/auth/renew",
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                createNextAuth({
                    cookie: { name: "session", renewName: "session" },
                    renewUrl: "https://api.example.com/auth/renew",
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
