import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createPrismaAdapter,
  type PrismaAdapterInput,
  type PrismaSessionTable,
} from "../src/adapters/prisma/index.js";
import { isAuthError } from "../src/errors.js";
import type { AuthAccount, SessionRecord } from "../src/session/types.js";

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
  findUnique(args: unknown): Promise<unknown>;
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

const account: AuthAccount = {
  email: "owner@example.com",
  id: "account-1",
  name: "Owner",
  role: "OWNER",
  status: "PENDING",
  timezone: "Europe/Lisbon",
  user: {
    id: "user-1",
    role: "ADMIN",
    status: "PENDING",
  },
};

const access = {
  account: { status: ["ACTIVE"] },
  user: { status: ["ACTIVE"] },
} as const;

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
    findUnique: async (args) => {
      calls.findUnique = args;
      return { ...row, account };
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
    account_sessions: sessions.delegate,
    user_accounts: accounts,
  };
  const custom = { admin_sessions: sessions.delegate };

  const table: PrismaSessionTable<typeof client> = "account_sessions";
  void table;

  // @ts-expect-error user_accounts does not implement the session schema.
  const invalidTable: PrismaSessionTable<typeof client> = "user_accounts";
  void invalidTable;

  const defaultInput = {
    client,
    config: access,
  } satisfies PrismaAdapterInput<typeof client>;
  void defaultInput;

  const appSpecificInput = {
    client,
    config: {
      account: { role: ["MANAGER"], status: ["INVITED"] },
      user: { role: ["OPERATOR"], status: ["VERIFIED"] },
    },
  } satisfies PrismaAdapterInput<typeof client>;
  void appSpecificInput;

  const customInput = {
    client: custom,
    config: { ...access, table: "admin_sessions" },
  } satisfies PrismaAdapterInput<typeof custom>;
  void customInput;

  // @ts-expect-error config.table is required without account_sessions.
  const missingConfig = { client: custom } satisfies PrismaAdapterInput<
    typeof custom
  >;
  void missingConfig;

  // @ts-expect-error account and user status rules are required.
  const missingAccess = { client, config: {} } satisfies PrismaAdapterInput<
    typeof client
  >;
  void missingAccess;
};

void assertTypes;

describe("Prisma database adapter", () => {
  it("uses account_sessions when table is omitted", async () => {
    const { calls, delegate } = createDelegate();
    const db = createPrismaAdapter({
      client: { account_sessions: delegate },
      config: access,
    });

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
    assert.deepEqual(await db.findToken(row.token_hash), {
      ...row,
      account,
      allowed: false,
    });
    assert.deepEqual(calls.findUnique, {
      select: {
        account_id: true,
        agent: true,
        created_at: true,
        expires_at: true,
        id: true,
        ip: true,
        platform: true,
        revoked_at: true,
        token_hash: true,
        updated_at: true,
        account: {
          select: {
            email: true,
            id: true,
            name: true,
            role: true,
            status: true,
            timezone: true,
            user: {
              select: {
                id: true,
                role: true,
                status: true,
              },
            },
          },
        },
      },
      where: { token_hash: row.token_hash },
    });

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

  it("applies configured account and user access rules", async () => {
    const { delegate } = createDelegate();
    const db = createPrismaAdapter({
      client: { account_sessions: delegate },
      config: {
        account: { status: ["ACTIVE", "PENDING"] },
        user: {
          role: ["ADMIN"],
          status: ["ACTIVE", "PENDING"],
        },
      },
    });

    assert.equal((await db.findToken(row.token_hash))?.allowed, true);
  });

  it("uses a configured compatible model", async () => {
    const { delegate } = createDelegate();
    const db = createPrismaAdapter({
      client: { admin_sessions: delegate },
      config: { ...access, table: "admin_sessions" },
    });

    assert.deepEqual(
      await db.find({ account_id: row.account_id, session_id: row.id }),
      row,
    );
  });

  it("rejects an invalid runtime model", () => {
    assert.throws(
      () =>
        createPrismaAdapter({
          client: { account_sessions: {} as Delegate<SessionRecord> },
          config: access,
        }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
  });

  it("rejects invalid access rules", () => {
    const { delegate } = createDelegate();

    assert.throws(
      () =>
        // @ts-expect-error access configuration is required.
        createPrismaAdapter({ client: { account_sessions: delegate } }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );

    assert.throws(
      () =>
        createPrismaAdapter({
          client: { account_sessions: delegate },
          config: {
            account: { status: [] },
            user: { status: ["ACTIVE"] },
          },
        }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );

    assert.throws(
      () =>
        createPrismaAdapter({
          client: { account_sessions: delegate },
          config: {
            account: { status: ["ACTIVE"] },
            // @ts-expect-error user.status is required.
            user: { role: ["ANY_ROLE"] },
          },
        }),
      (error) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
    );
  });
});
