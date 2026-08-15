import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  matchesClient,
  normalizeClient,
  normalizeIdentity,
  normalizeIp,
} from "../src/client/index.js";

describe("client normalization", () => {
  it("canonicalizes IPv4 and IPv6 in one place", () => {
    assert.equal(normalizeIp("192.0.2.10"), "192.0.2.10");
    assert.equal(normalizeIp("::ffff:192.0.2.10"), "192.0.2.10");
    assert.equal(normalizeIp("2001:0DB8:0:0:0:0:0:1"), "2001:db8::1");
    assert.equal(normalizeIp("[2001:db8::1]"), "2001:db8::1");
    assert.equal(normalizeIp("invalid"), null);
  });

  it("preserves the complete user agent", () => {
    const userAgent = `${"a".repeat(512)}  complete agent`;
    const client = normalizeClient({
      country: " pt ",
      ip: "2001:0DB8:0:0:0:0:0:1",
      platform: '"macOS"',
      userAgent,
    });

    assert.deepEqual(client, {
      country: "PT",
      ip: "2001:db8::1",
      platform: "macOS",
      userAgent,
    });
  });

  it("matches only canonical IP and complete user agent", () => {
    const stored = normalizeClient({ ip: "::ffff:192.0.2.10", userAgent: "Agent  Value" });

    assert.equal(
      matchesClient({
        current: normalizeIdentity({ ip: "192.0.2.10", userAgent: "Agent  Value" }),
        stored,
      }),
      true,
    );
    assert.equal(
      matchesClient({
        current: normalizeIdentity({ ip: "192.0.2.11", userAgent: "Agent  Value" }),
        stored,
      }),
      false,
    );
    assert.equal(
      matchesClient({
        current: normalizeIdentity({ ip: "192.0.2.10", userAgent: "Agent Value" }),
        stored,
      }),
      false,
    );
  });
});
