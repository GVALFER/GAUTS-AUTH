import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createDbAdapter,
  type PrismaAdapterInput,
  type PrismaSessionTable,
} from "../src/adapters/prisma/index.js";
import { isAuthError } from "../src/errors.js";
import type { SessionRecord } from "../src/session/types.js";

const meta = Symbol("Prisma delegate metadata");

type Delegate<Row> = {
  [meta]: {
    types: {
      payload: {
        scalars: Row;
      };
    };
  };
  create(args: unknown): Promise<unknown>;
  findFirst(args: unknown): Promise<unknown>;
  findMany(args: unknown): Promise<unknown>;
  update(args: unknown): Promise<unknown>;
  updateMany(args: unknown): Promise<unknown>;
};

const row: SessionRecord = {
  account_id: "account-1",
  agent: "Test Agent",
  created_at: new Date("2026-08-16T12:00:00.000Z"),
  expires_at: new Date("2026-08-23T12:00:00.000Z"),
  id: "session-1",
  ip: "192.0.2.10",
  platform: "macOS",
  revoked_at: null,
  token_hash: "a".repeat(64),
  updated_at: null,
};

const createDelegate = () => {
  const calls: Record<string, unknown> = {};
  const delegate: Delegate<SessionRecord> = {
    [meta]: null as never,
    create: async (args) => {
      calls.create = args;
      return row;
    },
    findFirst: async (args) => {
      calls.findFirst = args;
      return row;
    },
    findMany: async (args) => {
      calls.findMany = args;
      return [row];
    },
    update: async (args) => {
      calls.update = args;
      return row;
    },
    updateMany: async (args) => {
      calls.updateMany = args;
      return { count: 1 };
    },
  };

  return { calls, delegate };
};

const assertTypes = () => {
  const sessions = createDelegate();
  const accounts: Delegate<{ id: string }> = {
    ...sessions.delegate,
    [meta]: null as never,
  };
  const client = {
    auth_sessions: sessions.delegate,
    user_accounts: accounts,
  };
  const custom = { admin_sessions: sessions.delegate };

  const table: PrismaSessionTable<typeof client> = "auth_sessions";
  void table;

  // @ts-expect-error user_accounts does not implement the session schema.
  const invalidTable: PrismaSessionTable<typeof client> = "user_accounts";
  void invalidTable;

  const defaultInput = { client } satisfies PrismaAdapterInput<typeof client>;
  void defaultInput;

  const customInput = {
    client: custom,
    config: { table: "admin_sessions" },
  } satisfies PrismaAdapterInput<typeof custom>;
  void customInput;

  // @ts-expect-error config.table is required without auth_sessions.
  const missingConfig = { client: custom } satisfies PrismaAdapterInput<
    typeof custom
  >;
  void missingConfig;
};

void assertTypes;

describe("Prisma database adapter", () => {
  it("uses auth_sessions when config is omitted", async () => {
    const { calls, delegate } = createDelegate();
    const db = createDbAdapter({ client: { auth_sessions: delegate } });

    await db.create({
      account_id: row.account_id,
      agent: row.agent,
      created_at: row.created_at,
      expires_at: row.expires_at,
      id: row.id,
      ip: row.ip,
      platform: row.platform,
      token_hash: row.token_hash,
    });
    assert.deepEqual(calls.create, {
      data: {
        account_id: row.account_id,
        agent: row.agent,
        created_at: row.created_at,
        expires_at: row.expires_at,
        id: row.id,
        ip: row.ip,
        platform: row.platform,
        token_hash: row.token_hash,
      },
    });

    assert.deepEqual(
      await db.find({ account_id: row.account_id, session_id: row.id }),
      row,
    );
    assert.deepEqual(
      await db.findActive({ account_id: row.account_id, now: row.created_at }),
      [row],
    );

    await db.revoke({ revoked_at: row.expires_at, session_ids: [row.id] });
    assert.deepEqual(calls.updateMany, {
      data: { revoked_at: row.expires_at, updated_at: row.expires_at },
      where: { id: { in: [row.id] }, revoked_at: null },
    });

    await db.updateExpiry({
      expires_at: row.expires_at,
      session_id: row.id,
      updated_at: row.created_at,
    });
    assert.deepEqual(calls.update, {
      data: { expires_at: row.expires_at, updated_at: row.created_at },
      where: { id: row.id },
    });
  });

  it("uses a configured compatible model", async () => {
    const { delegate } = createDelegate();
    const db = createDbAdapter({
      client: { admin_sessions: delegate },
      config: { table: "admin_sessions" },
    });

    assert.deepEqual(
      await db.find({ account_id: row.account_id, session_id: row.id }),
      row,
    );
  });

  it("rejects an invalid runtime model", () => {
    assert.throws(
      () =>
        createDbAdapter({
          client: { auth_sessions: {} as Delegate<SessionRecord> },
        }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
  });
});
