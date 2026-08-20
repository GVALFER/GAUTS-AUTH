import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
    createCookieHeader,
    getCookieValue,
    resolveHttpCookie,
} from "../src/adapters/utils/httpCookie.js";
import { isAuthError } from "../src/errors.js";

const options = {
    domain: ".example.com",
    path: "/",
    sameSite: "Lax",
    secure: true,
} as const;

describe("HTTP cookies", () => {
    it("reads and decodes the first matching cookie", () => {
        assert.equal(
            getCookieValue({
                header: "first=1; session=abc%2E123%3D; session=ignored",
                name: "session",
            }),
            "abc.123=",
        );
    });

    it("keeps malformed encoded values readable", () => {
        assert.equal(getCookieValue({ header: "session=abc%ZZ", name: "session" }), "abc%ZZ");
        assert.equal(
            getCookieValue({ header: "invalid; other=value", name: "session" }),
            undefined,
        );
        assert.equal(getCookieValue({ name: "session" }), undefined);
    });

    it("creates a complete Set-Cookie header", () => {
        const expires = new Date("2030-01-01T00:00:00.000Z");

        assert.equal(
            createCookieHeader({
                expires,
                maxAge: 3600,
                name: "session",
                options,
                value: "abc.123=",
            }),
            "session=abc.123%3D; Max-Age=3600; Domain=.example.com; Path=/; " +
                "Expires=Tue, 01 Jan 2030 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
        );
    });

    it("creates a deletion cookie", () => {
        assert.equal(
            createCookieHeader({
                expires: new Date(0),
                maxAge: 0,
                name: "session",
                options,
                value: "",
            }),
            "session=; Max-Age=0; Domain=.example.com; Path=/; " +
                "Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
        );
    });

    it("rejects invalid cookie attributes", () => {
        assert.throws(
            () => resolveHttpCookie({ domain: "example.com\r\nX-Test: value" }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => resolveHttpCookie({ path: "/; Secure" }),
            (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(() =>
            createCookieHeader({ maxAge: 1.5, name: "session", options, value: "value" }),
        );
        assert.throws(() =>
            createCookieHeader({
                expires: new Date(Number.NaN),
                name: "session",
                options,
                value: "value",
            }),
        );
    });
});
