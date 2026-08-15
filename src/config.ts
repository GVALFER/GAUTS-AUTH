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

export type SessionConfig = {
  max?: number;
  touchAfter?: number;
  ttl?: number;
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

export type ResolvedPasswordConfig =
  ResolvedArgon2idConfig | ResolvedBcryptConfig;

export type ResolvedSessionConfig = {
  max: number;
  touchAfter: number;
  ttl: number;
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

const SESSION_DEFAULTS = {
  max: 10,
  touchAfter: 60 * 60 * 24,
  ttl: 60 * 60 * 24 * 7,
} as const;

const requireInteger = ({ max, min, name, value }: IntegerRequirement) => {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw createError({
      code: "AUTH_CONFIG_INVALID",
      message: `${name} must be an integer between ${String(min)} and ${String(max)}.`,
    });
  }

  return value;
};

export const resolvePasswordConfig = (
  config: PasswordConfig = {},
): ResolvedPasswordConfig => {
  const input: unknown = config;

  if (typeof input !== "object" || input === null) {
    throw createError({
      code: "AUTH_CONFIG_INVALID",
      message: "Password configuration is invalid.",
    });
  }

  const algorithm = (config as { algorithm?: unknown }).algorithm;

  if (
    algorithm !== undefined &&
    algorithm !== "argon2id" &&
    algorithm !== "bcrypt"
  ) {
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

export const resolveSessionConfig = (
  config: SessionConfig = {},
): ResolvedSessionConfig => {
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

  const touchAfter = requireInteger({
    max: ttl - 1,
    min: 1,
    name: "session.touchAfter",
    value: resolved.touchAfter,
  });

  return {
    max: requireInteger({
      max: 10_000,
      min: 1,
      name: "session.max",
      value: resolved.max,
    }),
    touchAfter,
    ttl,
  };
};
