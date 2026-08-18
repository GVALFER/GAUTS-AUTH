import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { resolveSessionConfig, type SessionValidation } from "../src/config.js";
import { isAuthError } from "../src/errors.js";
import { createSessionService } from "../src/session/service.js";
import { hashToken, tokenPattern } from "../src/session/token.js";
import type {
    CreateSessionRecord,
    DbAdapter,
    SessionRecord,
} from "../src/session/types.js";

const client = {
    agent: "Complete  User Agent",
    ip: "2001:0DB8:0:0:0:0:0:1",
    platform: '"macOS"',
};

const account = {
    email: "owner@example.com",
    id: "account-1",
    name: "Owner",
    role: "OWNER",
    status: "ACTIVE",
    timezone: "Europe/Lisbon",
    user: {
        id: "user-1",
        name: "Company",
        role: "ADMIN",
        status: "ACTIVE",
    },
} as const;

type HarnessConfig = {
    maxLifetime?: number;
    validation?: readonly SessionValidation[];
};

type StoredSessionRecord = SessionRecord & Pick<CreateSessionRecord, "country">;

const createDb = () => {
    let allowed = true;
    const rows = new Map<string, StoredSessionRecord>();
    const calls = {
        create: 0,
        find: 0,
        findActive: 0,
        findToken: 0,
        revoke: 0,
        updateExpiry: 0,
    };
    const adapter: DbAdapter<typeof account> = {
        create: async (input: CreateSessionRecord) => {
            calls.create += 1;
            rows.set(input.id, { ...input, revoked_at: null, updated_at: null });
        },
        find: async ({ account_id, session_id }) => {
            calls.find += 1;
            const row = rows.get(session_id);
            return row?.account_id === account_id ? row : null;
        },
        findActive: async ({ account_id, now }) => {
            calls.findActive += 1;
            return [...rows.values()].filter(
                (row) =>
                    row.account_id === account_id &&
                    row.revoked_at === null &&
                    row.expires_at.getTime() > now.getTime(),
            );
        },
        findToken: async (token_hash) => {
            calls.findToken += 1;
            const row = [...rows.values()].find((value) => value.token_hash === token_hash);
            return row ? { ...row, account, allowed } : null;
        },
        revoke: async ({ revoked_at, session_ids }) => {
            calls.revoke += 1;
            for (const session_id of session_ids) {
                const row = rows.get(session_id);
                if (row) {
                    rows.set(session_id, { ...row, revoked_at, updated_at: revoked_at });
                }
            }
        },
        updateExpiry: async ({ expires_at, session_id, updated_at }) => {
            calls.updateExpiry += 1;
            const row = rows.get(session_id);
            if (row) rows.set(session_id, { ...row, expires_at, updated_at });
        },
    };

    return {
        adapter,
        calls,
        rows,
        setAllowed: (value: boolean) => {
            allowed = value;
        },
    };
};

const createHarness = ({
    maxLifetime = 1_800,
    validation = ["agent"],
}: HarnessConfig = {}) => {
    let current = new Date("2026-08-15T12:00:00.000Z");
    const db = createDb();
    const session = createSessionService({
        config: resolveSessionConfig({
            maxLifetime,
            renewInterval: 60,
            ttl: 300,
            validation,
        }),
        db: db.adapter,
        now: () => new Date(current),
    });

    return {
        advance: (seconds: number) => {
            current = new Date(current.getTime() + seconds * 1000);
        },
        db,
        now: () => new Date(current),
        session,
    };
};

describe("session service", () => {
    it("creates a database session with only the token hash", async () => {
        const harness = createHarness();
        const created = await harness.session.create({
            account_id: account.id,
            client,
            country: " pt ",
        });
        const row = harness.db.rows.get(created.session.id);

        assert.match(created.token, tokenPattern);
        assert.equal(hashToken(created.token).length, 64);
        assert.equal(row?.token_hash, hashToken(created.token));
        assert.notEqual(row?.token_hash, created.token);
        assert.equal(created.account, account);
        assert.equal(created.session.account_id, account.id);
        assert.equal(row?.ip, "2001:db8::1");
        assert.equal(row?.agent, client.agent);
        assert.equal(row?.country, "PT");
        assert.equal(
            created.session.renew_at.toISOString(),
            "2026-08-15T12:01:00.000Z",
        );
        assert.equal(
            created.session.expires_at.toISOString(),
            "2026-08-15T12:05:00.000Z",
        );
    });

    it("resolves from the database without renewing", async () => {
        const harness = createHarness();
        const created = await harness.session.create({
            account_id: account.id,
            client,
        });

        harness.advance(61);
        const resolved = await harness.session.resolve({
            client,
            token: created.token,
        });

        assert.equal(resolved?.session.id, created.session.id);
        assert.equal(
            resolved?.session.expires_at.getTime(),
            created.session.expires_at.getTime(),
        );
        assert.equal(resolved?.account, account);
        assert.equal(harness.db.calls.findToken, 2);
        assert.equal(harness.db.calls.updateExpiry, 0);
    });

    it("renews the existing token only through the explicit renew operation", async () => {
        const harness = createHarness();
        const created = await harness.session.create({
            account_id: account.id,
            client,
        });

        const early = await harness.session.renew({
            client,
            token: created.token,
        });
        assert.equal(early?.renewed, false);
        assert.equal(harness.db.calls.updateExpiry, 0);

        harness.advance(61);
        const renewed = await harness.session.renew({
            client,
            token: created.token,
        });

        assert.equal(renewed?.renewed, true);
        assert.equal(renewed?.account, account);
        assert.equal(harness.db.calls.updateExpiry, 1);
        assert.equal(
            renewed?.session.expires_at.toISOString(),
            "2026-08-15T12:06:01.000Z",
        );
        assert.equal(
            renewed?.session.renew_at.toISOString(),
            "2026-08-15T12:02:01.000Z",
        );
        assert.ok(
            await harness.session.resolve({
                client,
                token: created.token,
            }),
        );
    });

    it("never renews a session beyond its maximum lifetime", async () => {
        const harness = createHarness({ maxLifetime: 360 });
        const created = await harness.session.create({
            account_id: account.id,
            client,
        });

        harness.advance(61);
        const first = await harness.session.renew({
            client,
            token: created.token,
        });

        assert.equal(first?.renewed, true);
        assert.equal(first?.session.expires_at.toISOString(), "2026-08-15T12:06:00.000Z");
        assert.equal(first?.session.renew_at.toISOString(), "2026-08-15T12:02:01.000Z");

        harness.advance(60);
        const second = await harness.session.renew({
            client,
            token: created.token,
        });

        assert.equal(second?.renewed, true);
        assert.equal(second?.session.expires_at.toISOString(), "2026-08-15T12:06:00.000Z");
        assert.equal(second?.session.renew_at.toISOString(), "2026-08-15T12:03:01.000Z");

        harness.advance(239);
        assert.equal(
            await harness.session.resolve({ client, token: created.token }),
            null,
        );
    });

    it("rejects inactive sessions", async () => {
        const harness = createHarness();
        const created = await harness.session.create({
            account_id: account.id,
            client,
        });

        harness.advance(301);
        assert.equal(
            await harness.session.resolve({ client, token: created.token }),
            null,
        );
        assert.equal(
            await harness.session.renew({ client, token: created.token }),
            null,
        );
    });

    it("revokes a session when a configured client field changes", async () => {
        const harness = createHarness({ validation: ["ip", "agent"] });
        const created = await harness.session.create({
            account_id: account.id,
            client,
        });

        await assert.rejects(
            harness.session.resolve({
                client: { ...client, ip: "2001:db8::2" },
                token: created.token,
            }),
            (error) => isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH",
        );
        assert.ok(harness.db.rows.get(created.session.id)?.revoked_at);
        assert.equal(
            await harness.session.resolve({ client, token: created.token }),
            null,
        );
    });

    it("rejects creation when a configured client field is missing", async () => {
        const harness = createHarness({ validation: ["ip", "agent"] });

        await assert.rejects(
            harness.session.create({
                account_id: account.id,
                client: { agent: client.agent },
            }),
            (error) => isAuthError(error) && error.code === "SESSION_DATA_INVALID",
        );
        assert.equal(harness.db.calls.create, 0);
    });

    it("revokes an existing session when a configured field is missing", async () => {
        const harness = createHarness({ validation: ["ip", "agent"] });
        const created = await harness.session.create({
            account_id: account.id,
            client,
        });
        const row = harness.db.rows.get(created.session.id);

        assert.ok(row);
        harness.db.rows.set(row.id, { ...row, ip: null });

        await assert.rejects(
            harness.session.resolve({
                client: { ...client, ip: null },
                token: created.token,
            }),
            (error) => isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH",
        );
        assert.ok(harness.db.rows.get(created.session.id)?.revoked_at);
    });

    it("lists and revokes active database sessions", async () => {
        const harness = createHarness();
        const first = await harness.session.create({
            account_id: account.id,
            client,
        });
        const second = await harness.session.create({
            account_id: account.id,
            client,
        });

        assert.equal((await harness.session.list("account-1")).length, 2);
        assert.deepEqual(
            await harness.session.revoke({
                account_id: "account-1",
                session_id: first.session.id,
            }),
            [first.session.id],
        );
        assert.deepEqual(await harness.session.revokeAccount("account-1"), [
            second.session.id,
        ]);
        assert.equal((await harness.session.list("account-1")).length, 0);
    });

    it("does not query the database for malformed tokens", async () => {
        const harness = createHarness();

        assert.equal(
            await harness.session.resolve({ client, token: "invalid" }),
            null,
        );
        assert.equal(harness.db.calls.findToken, 0);
    });

    it("revokes sessions rejected by current account access rules", async () => {
        const harness = createHarness();
        const created = await harness.session.create({
            account_id: account.id,
            client,
        });

        harness.db.setAllowed(false);

        assert.equal(
            await harness.session.resolve({ client, token: created.token }),
            null,
        );
        assert.ok(harness.db.rows.get(created.session.id)?.revoked_at);
    });

    it("rejects session creation for a disallowed account", async () => {
        const harness = createHarness();
        harness.db.setAllowed(false);

        await assert.rejects(
            harness.session.create({ account_id: account.id, client }),
            (error) => isAuthError(error) && error.code === "SESSION_INVALID",
        );
        assert.ok([...harness.db.rows.values()][0]?.revoked_at);
    });

    it("fails explicitly when the database is unavailable", async () => {
        const harness = createHarness();
        harness.db.adapter.create = () => Promise.reject(new Error("offline"));

        await assert.rejects(
            harness.session.create({ account_id: account.id, client }),
            (error) => isAuthError(error) && error.code === "DB_UNAVAILABLE",
        );
    });
});
