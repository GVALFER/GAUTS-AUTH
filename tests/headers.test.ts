import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { buildForwardHeaders, FORWARD_HEADERS } from "../src/headers/index.js";

describe("Headers", () => {
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
});
