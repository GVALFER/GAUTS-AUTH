import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { resolvePasswordConfig } from "../src/config.js";
import { isAuthError } from "../src/errors.js";
import { createPassword } from "../src/password/index.js";

describe("password service", () => {
    it("uses Argon2id by default", async () => {
        const password = createPassword(resolvePasswordConfig());
        const hash = await password.hash("correct horse battery staple");

        assert.equal(password.algorithm, "argon2id");
        assert.match(hash, /^\$argon2id\$/);
        assert.equal(
            await password.verify({
                password: "correct horse battery staple",
                storedHash: hash,
            }),
            true,
        );
        assert.equal(
            await password.verify({ password: "wrong password", storedHash: hash }),
            false,
        );
    });

    it("uses bcrypt only when configured", async () => {
        const password = createPassword(resolvePasswordConfig({ algorithm: "bcrypt", rounds: 4 }));
        const hash = await password.hash("bcrypt password");

        assert.equal(password.algorithm, "bcrypt");
        assert.match(hash, /^\$2[aby]\$/);
        assert.equal(
            await password.verify({ password: "bcrypt password", storedHash: hash }),
            true,
        );
        assert.equal(
            await password.verify({ password: "wrong password", storedHash: hash }),
            false,
        );
    });

    it("can verify legacy bcrypt input without allowing oversized new hashes", async () => {
        const password = createPassword(
            resolvePasswordConfig({
                algorithm: "bcrypt",
                rounds: 4,
                verifyMaxBytes: 1024,
            }),
        );
        const hash = await password.hash("a".repeat(72));

        assert.equal(
            await password.verify({
                password: `${"a".repeat(72)}legacy-suffix`,
                storedHash: hash,
            }),
            true,
        );
        await assert.rejects(
            password.hash("a".repeat(73)),
            (error) => isAuthError(error) && error.code === "PASSWORD_INPUT_INVALID",
        );
    });

    it("never falls back to another algorithm", async () => {
        const argon2id = createPassword(resolvePasswordConfig());
        const bcrypt = createPassword(resolvePasswordConfig({ algorithm: "bcrypt", rounds: 4 }));
        const argonHash = await argon2id.hash("password");
        const bcryptHash = await bcrypt.hash("password");

        assert.equal(
            await argon2id.verify({ password: "password", storedHash: bcryptHash }),
            false,
        );
        assert.equal(await bcrypt.verify({ password: "password", storedHash: argonHash }), false);
    });

    it("rejects missing password hashes with the configured algorithm", async () => {
        const argon2id = createPassword(resolvePasswordConfig({ memoryCost: 8192, timeCost: 1 }));
        const bcrypt = createPassword(resolvePasswordConfig({ algorithm: "bcrypt", rounds: 4 }));

        assert.equal(await argon2id.verify({ password: "password", storedHash: null }), false);
        assert.equal(await argon2id.verify({ password: "password", storedHash: undefined }), false);
        assert.equal(await bcrypt.verify({ password: "password", storedHash: null }), false);
        assert.equal(await bcrypt.verify({ password: "password", storedHash: undefined }), false);
    });

    it("rejects empty and oversized password input", async () => {
        const password = createPassword(resolvePasswordConfig({ maxBytes: 8 }));

        await assert.rejects(password.hash(""), isAuthError);
        await assert.rejects(password.hash("123456789"), isAuthError);
        await assert.rejects(password.hash("€€€"), isAuthError);
    });

    it("rejects invalid password configuration", () => {
        assert.throws(
            () => resolvePasswordConfig({ algorithm: "bcrypt", maxBytes: 73 }),
            isAuthError,
        );
        assert.throws(() => resolvePasswordConfig({ memoryCost: 1 }), isAuthError);
        assert.throws(() => resolvePasswordConfig({ algorithm: "scrypt" } as never), isAuthError);
    });
});
