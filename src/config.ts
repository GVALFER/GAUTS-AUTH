import { createError } from "./errors.js";

export type Argon2idConfig = {
    algorithm?: "argon2id";
    hashLength?: number;
    maxBytes?: number;
    memoryCost?: number;
    parallelism?: number;
    timeCost?: number;
};

export type BcryptConfig = {
    algorithm: "bcrypt";
    maxBytes?: number;
    rounds?: number;
    verifyMaxBytes?: number;
};

export type PasswordConfig = Argon2idConfig | BcryptConfig;

export type SessionValidation = "agent" | "ip" | "platform";

export type SessionConfig = {
    maxLifetime?: number;
    renewInterval?: number;
    ttl?: number;
    validation?: readonly SessionValidation[];
};

type ResolvedArgon2idConfig = {
    algorithm: "argon2id";
    hashLength: number;
    maxBytes: number;
    memoryCost: number;
    parallelism: number;
    timeCost: number;
};

type ResolvedBcryptConfig = {
    algorithm: "bcrypt";
    maxBytes: number;
    rounds: number;
    verifyMaxBytes: number;
};

export type ResolvedPasswordConfig = ResolvedArgon2idConfig | ResolvedBcryptConfig;

export type ResolvedSessionConfig = {
    maxLifetime: number;
    renewInterval: number;
    ttl: number;
    validation: readonly SessionValidation[];
};

type IntegerRequirement = {
    max: number;
    min: number;
    name: string;
    value: number;
};

const ARGON_DEFAULTS = {
    algorithm: "argon2id",
    hashLength: 32,
    maxBytes: 1024,
    memoryCost: 65_536,
    parallelism: 4,
    timeCost: 3,
} as const;

const BCRYPT_DEFAULTS = {
    algorithm: "bcrypt",
    maxBytes: 72,
    rounds: 12,
    verifyMaxBytes: 72,
} as const;

export const COOKIE_DEFAULTS = {
    cacheName: "__cac",
    renewName: "__ren",
    sessionName: "__ses",
} as const;

const SESSION_DEFAULTS = {
    maxLifetime: 60 * 60 * 24 * 30,
    renewInterval: 60 * 60 * 24,
    ttl: 60 * 60 * 24 * 7,
    validation: ["agent"],
} as const;

const SESSION_VALIDATION = new Set<SessionValidation>(["agent", "ip", "platform"]);

const requireInteger = ({ max, min, name, value }: IntegerRequirement) => {
    if (!Number.isInteger(value) || value < min || value > max) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${name} must be an integer between ${String(min)} and ${String(max)}.`,
        });
    }

    return value;
};

const resolveSessionValidation = (input: unknown): SessionValidation[] => {
    if (!Array.isArray(input)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "session.validation contains an invalid field.",
        });
    }

    const fields: unknown[] = input;

    if (
        fields.some(
            (field) =>
                typeof field !== "string" || !SESSION_VALIDATION.has(field as SessionValidation),
        )
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "session.validation contains an invalid field.",
        });
    }

    if (new Set(fields).size !== fields.length) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "session.validation contains duplicate fields.",
        });
    }

    return fields.map((field) => field as SessionValidation);
};

export const resolvePasswordConfig = (config: PasswordConfig = {}): ResolvedPasswordConfig => {
    const input: unknown = config;

    if (typeof input !== "object" || input === null) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Password configuration is invalid.",
        });
    }

    const algorithm = (config as { algorithm?: unknown }).algorithm;

    if (algorithm !== undefined && algorithm !== "argon2id" && algorithm !== "bcrypt") {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Password algorithm is invalid.",
        });
    }

    if (config.algorithm === "bcrypt") {
        const resolved = { ...BCRYPT_DEFAULTS, ...config };

        return {
            algorithm: "bcrypt",
            maxBytes: requireInteger({
                max: 72,
                min: 1,
                name: "password.maxBytes",
                value: resolved.maxBytes,
            }),
            rounds: requireInteger({
                max: 31,
                min: 4,
                name: "password.rounds",
                value: resolved.rounds,
            }),
            verifyMaxBytes: requireInteger({
                max: 1_048_576,
                min: resolved.maxBytes,
                name: "password.verifyMaxBytes",
                value: resolved.verifyMaxBytes,
            }),
        };
    }

    const resolved = { ...ARGON_DEFAULTS, ...config };

    return {
        algorithm: "argon2id",
        hashLength: requireInteger({
            max: 64,
            min: 16,
            name: "password.hashLength",
            value: resolved.hashLength,
        }),
        maxBytes: requireInteger({
            max: 1_048_576,
            min: 1,
            name: "password.maxBytes",
            value: resolved.maxBytes,
        }),
        memoryCost: requireInteger({
            max: 1_048_576,
            min: 8_192,
            name: "password.memoryCost",
            value: resolved.memoryCost,
        }),
        parallelism: requireInteger({
            max: 16,
            min: 1,
            name: "password.parallelism",
            value: resolved.parallelism,
        }),
        timeCost: requireInteger({
            max: 10,
            min: 1,
            name: "password.timeCost",
            value: resolved.timeCost,
        }),
    };
};

export const resolveSessionConfig = (config: SessionConfig = {}): ResolvedSessionConfig => {
    const input: unknown = config;

    if (typeof input !== "object" || input === null) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session configuration is invalid.",
        });
    }

    const resolved = { ...SESSION_DEFAULTS, ...config };

    const ttl = requireInteger({
        max: 60 * 60 * 24 * 365,
        min: 60,
        name: "session.ttl",
        value: resolved.ttl,
    });

    const renewInterval = requireInteger({
        max: ttl - 1,
        min: 1,
        name: "session.renewInterval",
        value: resolved.renewInterval,
    });

    const maxLifetime = requireInteger({
        max: 60 * 60 * 24 * 365,
        min: ttl,
        name: "session.maxLifetime",
        value: resolved.maxLifetime,
    });

    return {
        maxLifetime,
        renewInterval,
        ttl,
        validation: resolveSessionValidation(config.validation ?? SESSION_DEFAULTS.validation),
    };
};
