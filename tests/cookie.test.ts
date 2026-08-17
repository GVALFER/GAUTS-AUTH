import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { isAuthError } from "../src/errors.js";
import {
    parseSessionToken,
    RENEW_COOKIE_VALUE,
    resolveSessionCookieName,
    resolveSessionCookieNames,
} from "../src/session/cookie.js";

const token = "a".repeat(43);

describe("session cookies", () => {
    it("accepts only the raw opaque session token", () => {
        assert.equal(parseSessionToken(token), token);
        assert.equal(parseSessionToken(` ${token} `), token);
        assert.equal(parseSessionToken(), null);
        assert.equal(parseSessionToken(`${token}.123`), null);
        assert.equal(parseSessionToken("a".repeat(42)), null);
    });

    it("resolves separate session, cache, and renewal names", () => {
        assert.deepEqual(resolveSessionCookieNames(), {
            cacheName: "__cac",
            name: "__sec",
            renewName: "__ren",
        });
        assert.deepEqual(
            resolveSessionCookieNames({
                cacheName: "__admin_cac",
                name: "__admin_sec",
                renewName: "__admin_ren",
            }),
            {
                cacheName: "__admin_cac",
                name: "__admin_sec",
                renewName: "__admin_ren",
            },
        );
        assert.equal(RENEW_COOKIE_VALUE, "1");
    });

    it("validates cookie names and requires them to be unique", () => {
        assert.equal(resolveSessionCookieName("__admin_sec"), "__admin_sec");
        assert.throws(
            () => resolveSessionCookieName("invalid cookie"),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => resolveSessionCookieNames({ name: "session", cacheName: "session" }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
