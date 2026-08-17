import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { isAuthError } from "../src/errors.js";
import {
    formatRenewAt,
    parseRenewAt,
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
    });

    it("formats and parses renewal timestamps in Unix seconds", () => {
        assert.equal(formatRenewAt(new Date("2026-08-17T12:00:00.999Z")), "1786968000");
        assert.equal(parseRenewAt("1786968000"), 1786968000);
        assert.equal(parseRenewAt(" 1786968000 "), 1786968000);
        assert.equal(parseRenewAt(), null);
        assert.equal(parseRenewAt("0"), null);
        assert.equal(parseRenewAt("1.5"), null);
        assert.equal(parseRenewAt("invalid"), null);
        assert.equal(parseRenewAt(Number.MAX_SAFE_INTEGER.toString()), Number.MAX_SAFE_INTEGER);
        assert.equal(parseRenewAt(`${Number.MAX_SAFE_INTEGER.toString()}0`), null);
        assert.throws(
            () => formatRenewAt(new Date("invalid")),
            (error) => isAuthError(error) && error.code === "SESSION_DATA_INVALID",
        );
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
