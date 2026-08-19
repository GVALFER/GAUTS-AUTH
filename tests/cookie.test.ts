import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { isAuthError } from "../src/errors.js";
import {
    parseSessionToken,
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

    it("resolves separate session and context names", () => {
        assert.deepEqual(resolveSessionCookieNames(), {
            contextName: "__ctx",
            sessionName: "__ses",
        });
        assert.deepEqual(
            resolveSessionCookieNames({
                contextName: "__admin_ctx",
                sessionName: "__admin_sec",
            }),
            {
                contextName: "__admin_ctx",
                sessionName: "__admin_sec",
            },
        );
    });

    it("validates cookie names and requires them to be unique", () => {
        assert.equal(resolveSessionCookieName("__admin_sec"), "__admin_sec");
        assert.throws(
            () => resolveSessionCookieName("invalid cookie"),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () =>
                resolveSessionCookieNames({
                    contextName: "session",
                    sessionName: "session",
                }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
