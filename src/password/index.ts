import * as argon2 from "argon2";
import { compare as compareBcrypt, hash as hashBcrypt } from "bcryptjs";
import type { ResolvedPasswordConfig } from "../config.js";
import { createError } from "../errors.js";

export type PasswordService = {
    algorithm: "argon2id" | "bcrypt";
    hash(password: string): Promise<string>;
    verify(input: { password: string; storedHash: string }): Promise<boolean>;
};

type RequirePasswordProps = {
    password: string;
    maxBytes: number;
};

const BCRYPT_PATTERN = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

const requirePassword = ({ password, maxBytes }: RequirePasswordProps) => {
    const bytes = Buffer.byteLength(password, "utf8");

    if (bytes < 1 || bytes > maxBytes) {
        throw createError({
            code: "PASSWORD_INPUT_INVALID",
            message: `Password must contain between 1 and ${String(maxBytes)} bytes.`,
        });
    }
};

const createArgon2id = (
    config: Extract<ResolvedPasswordConfig, { algorithm: "argon2id" }>,
): PasswordService => ({
    algorithm: "argon2id",

    hash: async (password) => {
        requirePassword({ maxBytes: config.maxBytes, password });

        return argon2.hash(password, {
            hashLength: config.hashLength,
            memoryCost: config.memoryCost,
            parallelism: config.parallelism,
            timeCost: config.timeCost,
            type: argon2.argon2id,
        });
    },

    verify: async ({ password, storedHash }) => {
        requirePassword({ maxBytes: config.maxBytes, password });

        if (!storedHash.startsWith("$argon2id$")) {
            return false;
        }

        return argon2.verify(storedHash, password);
    },
});

const createBcrypt = (
    config: Extract<ResolvedPasswordConfig, { algorithm: "bcrypt" }>,
): PasswordService => ({
    algorithm: "bcrypt",

    hash: async (password) => {
        requirePassword({ maxBytes: config.maxBytes, password });

        return hashBcrypt(password, config.rounds);
    },

    verify: async ({ password, storedHash }) => {
        requirePassword({ maxBytes: config.verifyMaxBytes, password });

        if (!BCRYPT_PATTERN.test(storedHash)) {
            return false;
        }

        return compareBcrypt(password, storedHash);
    },
});

export const createPassword = (config: ResolvedPasswordConfig): PasswordService => {
    return config.algorithm === "bcrypt" ? createBcrypt(config) : createArgon2id(config);
};
