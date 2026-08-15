import type { RedisClientType } from "redis";
import { createError } from "../../errors.js";
import type { RedisSessionStore } from "../../session/types.js";

export type RedisStoreConfig = {
  prefix?: string;
};

export type RedisStoreInput = {
  client: RedisClientType;
  config?: RedisStoreConfig;
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

export const createRedisStore = ({
  client,
  config = {},
}: RedisStoreInput): RedisSessionStore => {
  const prefix = getPrefix(config.prefix);
  const getKey = (tokenHash: string) => `${prefix}:session:${tokenHash}`;

  return {
    create: async ({ tokenHash, ttl, value }) => {
      const result = await client.set(getKey(tokenHash), value, {
        EX: ttl,
        NX: true,
      });

      if (result !== "OK") {
        throw new Error("Redis session key already exists.");
      }
    },

    get: async (tokenHash) => {
      return client.get(getKey(tokenHash));
    },

    getMany: async (tokenHashes) => {
      return tokenHashes.length === 0
        ? []
        : client.mGet(tokenHashes.map((tokenHash) => getKey(tokenHash)));
    },

    update: async ({ tokenHash, ttl, value }) => {
      const result = await client.set(getKey(tokenHash), value, {
        EX: ttl,
        XX: true,
      });

      return result === "OK";
    },

    keep: async ({ tokenHash, value }) => {
      const result = await client.set(getKey(tokenHash), value, {
        KEEPTTL: true,
        XX: true,
      });

      return result === "OK";
    },

    delete: async (tokenHashes) => {
      if (tokenHashes.length > 0) {
        await client.del(tokenHashes.map((tokenHash) => getKey(tokenHash)));
      }
    },

    exists: async (tokenHashes) => {
      if (tokenHashes.length === 0) {
        return [];
      }

      const values = await client.mGet(
        tokenHashes.map((tokenHash) => getKey(tokenHash)),
      );

      return values.map((value) => value !== null);
    },
  };
};
