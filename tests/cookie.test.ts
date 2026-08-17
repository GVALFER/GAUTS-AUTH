import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
    createSessionCookie,
    parseSessionCookie,
    resolveSessionCookieName,
} from "../src/session/cookie.js";
import { isAuthError } from "../src/errors.js";

const token = "a".repeat(43);

describe("session cookie", () => {
    it("serializes one opaque token and one renewal timestamp", () => {
        const value = createSessionCookie({
            renew_at: new Date("2026-08-17T10:00:00.999Z"),
            token,
        });
        const parsed = parseSessionCookie(value);

        assert.equal(value, `${token}.1786960800`);
        assert.equal(parsed?.token, token);
        assert.equal(parsed?.renew_at.toISOString(), "2026-08-17T10:00:00.000Z");
    });

    it("rejects malformed cookie values", () => {
        assert.equal(parseSessionCookie(), null);
        assert.equal(parseSessionCookie(token), null);
        assert.equal(parseSessionCookie(`${token}.invalid`), null);
        assert.equal(parseSessionCookie(`${token}.1.extra`), null);
        assert.equal(parseSessionCookie(`${"a".repeat(42)}.1786960800`), null);
    });

    it("rejects invalid data during serialization", () => {
        assert.throws(() =>
            createSessionCookie({
                renew_at: new Date("invalid"),
                token,
            }),
        );
    });

    it("validates the cookie name", () => {
        assert.equal(resolveSessionCookieName(), "__Host-session");
        assert.equal(resolveSessionCookieName("__admin_sec"), "__admin_sec");
        assert.throws(
            () => resolveSessionCookieName("invalid cookie"),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
