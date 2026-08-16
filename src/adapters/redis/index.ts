import type { RedisClientType } from "redis";
import { createError } from "../../errors.js";
import type { RedisAdapter } from "../../session/types.js";

export type RedisAdapterConfig = {
    prefix?: string;
};

export type RedisAdapterInput = {
    client: RedisClientType;
    config?: RedisAdapterConfig;
};

const getPrefix = (input?: string): string => {
    const candidate = input?.trim();
    const prefix = candidate?.length ? candidate : "gauts:auth";

    if (prefix.length > 128 || !/^[A-Za-z0-9:_-]+$/.test(prefix)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Redis key prefix is invalid.",
        });
    }

    return prefix.replace(/:+$/g, "");
};

export const createRedisAdapter = ({ client, config = {} }: RedisAdapterInput): RedisAdapter => {
    const prefix = getPrefix(config.prefix);
    const getKey = (token_hash: string) => `${prefix}:session:${token_hash}`;

    return {
        create: async ({ token_hash, ttl, value }) => {
            const result = await client.set(getKey(token_hash), value, {
                EX: ttl,
                NX: true,
            });

            if (result !== "OK") {
                throw new Error("Redis session key already exists.");
            }
        },

        get: async (token_hash) => {
            return client.get(getKey(token_hash));
        },

        getMany: async (token_hashes) => {
            return token_hashes.length === 0
                ? []
                : client.mGet(token_hashes.map((token_hash) => getKey(token_hash)));
        },

        update: async ({ token_hash, ttl, value }) => {
            const result = await client.set(getKey(token_hash), value, {
                EX: ttl,
                XX: true,
            });

            return result === "OK";
        },

        keep: async ({ token_hash, value }) => {
            const result = await client.set(getKey(token_hash), value, {
                KEEPTTL: true,
                XX: true,
            });

            return result === "OK";
        },

        delete: async (token_hashes) => {
            if (token_hashes.length > 0) {
                await client.del(token_hashes.map((token_hash) => getKey(token_hash)));
            }
        },

        exists: async (token_hashes) => {
            if (token_hashes.length === 0) {
                return [];
            }

            const values = await client.mGet(token_hashes.map((token_hash) => getKey(token_hash)));

            return values.map((value) => value !== null);
        },
    };
};
