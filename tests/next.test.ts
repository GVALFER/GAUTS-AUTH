import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { NextRequest, NextResponse } from "next/server.js";

import { createNextAuth, FORWARD_HEADERS } from "../src/adapters/next/index.js";
import { isAuthError } from "../src/errors.js";
import { createSessionCookie } from "../src/session/cookie.js";

const token = "a".repeat(43);

const createRequest = (renew_at: Date) => {
    const cookie = createSessionCookie({ renew_at, token });

    return new NextRequest("https://admin.example.com/account", {
        headers: {
            Authorization: "Bearer private",
            Cookie: `other=private; session=${cookie}`,
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

    it("does not call the renewal endpoint before renewAt", async () => {
        const originalFetch = globalThis.fetch;
        let calls = 0;
        globalThis.fetch = async () => {
            calls += 1;
            return new Response(null, { status: 204 });
        };

        try {
            const auth = createNextAuth({
                cookie: { name: "session" },
                renewUrl: "https://api.example.com/auth/renew",
            });
            const result = await auth.renew({
                request: createRequest(new Date("2100-01-01T00:00:00.000Z")),
                response: NextResponse.next(),
            });

            assert.equal(result.attempted, false);
            assert.equal(result.status, null);
            assert.equal(calls, 0);
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("renews when due and forwards Set-Cookie", async () => {
        const originalFetch = globalThis.fetch;
        let request: Parameters<typeof fetch>[0] | undefined;
        let init: RequestInit | undefined;
        globalThis.fetch = async (input, options) => {
            request = input;
            init = options;
            return new Response(null, {
                headers: {
                    "Set-Cookie": "session=updated; Path=/; HttpOnly",
                },
                status: 204,
            });
        };

        try {
            const auth = createNextAuth({
                cookie: { name: "session" },
                renewUrl: "https://api.example.com/auth/renew",
            });
            const result = await auth.renew({
                request: createRequest(new Date("2020-01-01T00:00:00.000Z")),
                response: NextResponse.next(),
            });

            assert.equal(result.attempted, true);
            assert.equal(result.status, 204);
            assert.equal(request, "https://api.example.com/auth/renew");
            assert.equal(init?.method, "POST");
            assert.equal(init?.redirect, "error");
            assert.ok(init?.signal instanceof AbortSignal);

            const headers = new Headers(init?.headers);
            assert.match(headers.get("cookie") ?? "", /^session=/);
            assert.equal(headers.get("cookie")?.includes("other=private"), false);
            assert.equal(headers.get("authorization"), null);
            assert.equal(headers.get("x-private-header"), null);
            assert.equal(headers.get("cf-connecting-ip"), "192.0.2.10");
            assert.equal(headers.get("user-agent"), "Next Test");
            assert.equal(
                result.response.headers.get("set-cookie"),
                "session=updated; Path=/; HttpOnly",
            );
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("reports an invalid cookie without calling the API", async () => {
        const auth = createNextAuth({
            cookie: { name: "session" },
            renewUrl: "https://api.example.com/auth/renew",
        });
        const result = await auth.renew({
            request: new NextRequest("https://admin.example.com/account"),
            response: NextResponse.next(),
        });

        assert.equal(result.attempted, false);
        assert.equal(result.status, 401);
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
    });
});
