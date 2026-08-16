import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";

import { createClient } from "redis";

import { createRedisAdapter } from "../src/adapters/redis/index.js";

const redisUrl = process.env.REDIS_TEST_URL;

describe(
  "node-redis adapter",
  { skip: redisUrl ? false : "REDIS_TEST_URL is not set" },
  () => {
    it("creates, reads, updates, preserves and deletes session values", async () => {
      assert.ok(redisUrl);
      const client = createClient({ url: redisUrl });
      const prefix = `gauts:auth:test:${randomUUID()}`;
      const store = createRedisAdapter({ client, config: { prefix } });
      const firstHash = "a".repeat(64);
      const secondHash = "b".repeat(64);

      await client.connect();

      try {
        await store.create({ token_hash: firstHash, ttl: 60, value: "first" });
        await store.create({
          token_hash: secondHash,
          ttl: 60,
          value: "second",
        });

        assert.equal(await store.get(firstHash), "first");
        assert.deepEqual(await store.getMany([firstHash, secondHash]), [
          "first",
          "second",
        ]);
        assert.deepEqual(
          await store.exists([firstHash, secondHash, "c".repeat(64)]),
          [true, true, false],
        );
        assert.equal(
          await store.update({
            token_hash: firstHash,
            ttl: 120,
            value: "updated",
          }),
          true,
        );
        assert.equal(
          await store.keep({ token_hash: firstHash, value: "kept" }),
          true,
        );
        assert.equal(await store.get(firstHash), "kept");
        assert.ok(await client.ttl(`${prefix}:session:${firstHash}`));
        await assert.rejects(
          store.create({ token_hash: firstHash, ttl: 60, value: "collision" }),
        );

        await store.delete([firstHash, secondHash]);
        assert.deepEqual(await store.exists([firstHash, secondHash]), [
          false,
          false,
        ]);
      } finally {
        await store.delete([firstHash, secondHash]);
        await client.close();
      }
    });
  },
);
