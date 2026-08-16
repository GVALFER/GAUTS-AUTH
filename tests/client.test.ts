import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  matchesClient,
  normalizeClient,
  normalizeIp,
} from "../src/client/index.js";

describe("client normalization", () => {
  it("canonicalizes IPv4 and IPv6 in one place", () => {
    assert.equal(normalizeIp("192.0.2.10"), "192.0.2.10");
    assert.equal(normalizeIp("::ffff:192.0.2.10"), "192.0.2.10");
    assert.equal(normalizeIp("0:0:0:0:0:ffff:c000:020a"), "192.0.2.10");
    assert.equal(normalizeIp("2001:0DB8:0:0:0:0:0:1"), "2001:db8::1");
    assert.equal(normalizeIp("[2001:db8::1]"), "2001:db8::1");
    assert.equal(normalizeIp("::1"), "127.0.0.1");
    assert.equal(normalizeIp("192.168.001.001"), null);
    assert.equal(normalizeIp("fe80::1%lo0"), null);
    assert.equal(normalizeIp("invalid"), null);
  });

  it("preserves the complete user agent", () => {
    const agent = `${"a".repeat(512)}  complete agent`;
    const client = normalizeClient({
      ip: "2001:0DB8:0:0:0:0:0:1",
      platform: '"macOS"',
      agent,
    });

    assert.deepEqual(client, {
      ip: "2001:db8::1",
      platform: "macOS",
      agent,
    });
  });

  it("compares only the configured client fields", () => {
    const stored = normalizeClient({
      ip: "::ffff:192.0.2.10",
      platform: '"macOS"',
      agent: "Agent  Value",
    });

    assert.equal(
      matchesClient({
        current: normalizeClient({
          ip: "192.0.2.11",
          platform: '"macOS"',
          agent: "Agent  Value",
        }),
        stored,
        validation: ["agent"],
      }),
      true,
    );
    assert.equal(
      matchesClient({
        current: normalizeClient({
          ip: "192.0.2.11",
          platform: '"macOS"',
          agent: "Agent  Value",
        }),
        stored,
        validation: ["ip", "agent"],
      }),
      false,
    );
    assert.equal(
      matchesClient({
        current: normalizeClient({
          ip: "192.0.2.10",
          platform: '"Windows"',
          agent: "Agent Value",
        }),
        stored,
        validation: ["platform", "agent"],
      }),
      false,
    );
    assert.equal(
      matchesClient({ current: normalizeClient({}), stored, validation: [] }),
      true,
    );
  });
});
