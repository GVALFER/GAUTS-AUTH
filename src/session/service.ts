import { randomUUID } from "node:crypto";

import { matchesClient, normalizeClient } from "../client/index.js";
import type { ResolvedSessionConfig } from "../config.js";
import { createError, isAuthError } from "../errors.js";
import { encodeSession, parseSession, toSession } from "./schema.js";
import { createToken, hashToken, tokenPattern } from "./token.js";
import type {
  ActiveSession,
  DbAdapter,
  RedisAdapter,
  SessionInput,
  SessionRecord,
  SessionService,
  StoredSession,
} from "./types.js";

type SessionDeps = {
  config: ResolvedSessionConfig;
  db: DbAdapter;
  now?: () => Date;
  redis: RedisAdapter;
};

type RevokeRowsProps = {
  revoked_at: Date;
  rows: SessionRecord[];
};

type ValidatedSession<TData extends object> = {
  current: Date;
  stored: StoredSession<TData>;
  token_hash: string;
};

const toActiveSession = (session: SessionRecord): ActiveSession => ({
  account_id: session.account_id,
  agent: session.agent,
  created_at: session.created_at,
  expires_at: session.expires_at,
  id: session.id,
  ip: session.ip,
  platform: session.platform,
  revoked_at: session.revoked_at,
  updated_at: session.updated_at,
});

export const createSessionService = <TData extends object>({
  config,
  db,
  now = () => new Date(),
  redis,
}: SessionDeps): SessionService<TData> => {
  const runRedis = async <T>(operation: () => Promise<T>): Promise<T> => {
    try {
      return await operation();
    } catch (error) {
      if (isAuthError(error)) {
        throw error;
      }

      throw createError({
        cause: error,
        code: "REDIS_UNAVAILABLE",
        message: "Authentication service unavailable.",
      });
    }
  };

  const runDb = async <T>(operation: () => Promise<T>): Promise<T> => {
    try {
      return await operation();
    } catch (error) {
      if (isAuthError(error)) {
        throw error;
      }

      throw createError({
        cause: error,
        code: "DB_UNAVAILABLE",
        message: "Session database unavailable.",
      });
    }
  };

  const getActive = async (account_id: string): Promise<SessionRecord[]> => {
    const current = now();
    const rows = await runDb(() => db.findActive({ account_id, now: current }));

    const valid = rows.filter(
      (row) =>
        row.revoked_at === null && row.expires_at.getTime() > current.getTime(),
    );

    if (valid.length === 0) {
      return [];
    }

    const active = await runRedis(() =>
      redis.exists(valid.map((row) => row.token_hash)),
    );

    if (active.length !== valid.length) {
      throw createError({
        code: "REDIS_UNAVAILABLE",
        message: "Authentication service returned invalid data.",
      });
    }

    return valid.filter((_, index) => active[index]);
  };

  const revokeRows = async ({
    revoked_at,
    rows,
  }: RevokeRowsProps): Promise<string[]> => {
    if (rows.length === 0) {
      return [];
    }

    await runRedis(() => redis.delete(rows.map((row) => row.token_hash)));
    const session_ids = rows.map((row) => row.id);
    await runDb(() => db.revoke({ revoked_at, session_ids }));

    return session_ids;
  };

  const validateSession = async (
    input: SessionInput,
  ): Promise<ValidatedSession<TData> | null> => {
    if (!tokenPattern.test(input.token)) {
      return null;
    }

    const token_hash = hashToken(input.token);
    const raw = await runRedis(() => redis.get(token_hash));

    if (!raw) {
      return null;
    }

    const stored = parseSession<TData>(raw);

    if (!stored) {
      await runRedis(() => redis.delete([token_hash]));
      return null;
    }

    const current = now();

    if (Date.parse(stored.expires_at) <= current.getTime()) {
      await runRedis(() => redis.delete([token_hash]));
      return null;
    }

    const client = normalizeClient(input.client);
    const matches = matchesClient({
      current: client,
      stored: stored.client,
      validation: config.validation,
    });

    if (!matches) {
      await runRedis(() => redis.delete([token_hash]));

      try {
        await runDb(() =>
          db.revoke({ revoked_at: current, session_ids: [stored.id] }),
        );
      } catch (error) {
        throw createError({
          cause: error,
          code: "SESSION_CLIENT_MISMATCH",
          message:
            "Session client identity changed and the session was revoked.",
        });
      }

      throw createError({
        code: "SESSION_CLIENT_MISMATCH",
        message: "Session client identity changed and the session was revoked.",
      });
    }

    return { current, stored, token_hash };
  };

  return {
    create: async (input) => {
      if (!input.account_id) {
        throw createError({
          code: "SESSION_DATA_INVALID",
          message: "Session account ID is required.",
        });
      }

      const client = normalizeClient(input.client);
      const created_at = now();
      const expires_at = new Date(created_at.getTime() + config.ttl * 1000);
      const token = createToken();
      const token_hash = hashToken(token);
      const id = randomUUID();

      const stored: StoredSession<TData> = {
        account_id: input.account_id,
        client,
        created_at: created_at.toISOString(),
        data: input.data,
        expires_at: expires_at.toISOString(),
        id,
        touched_at: created_at.toISOString(),
      };

      const value = encodeSession(stored);
      const active = await getActive(input.account_id);

      if (active.length >= config.max) {
        throw createError({
          code: "SESSION_LIMIT_REACHED",
          message: `Maximum active sessions reached (${String(config.max)}).`,
        });
      }

      await runDb(() =>
        db.create({
          account_id: input.account_id,
          agent: client.agent,
          created_at,
          expires_at,
          id,
          ip: client.ip,
          platform: client.platform,
          token_hash,
        }),
      );

      try {
        await runRedis(() =>
          redis.create({ token_hash, ttl: config.ttl, value }),
        );
      } catch (error) {
        try {
          await runDb(() =>
            db.revoke({ revoked_at: now(), session_ids: [id] }),
          );
        } catch (dbError) {
          throw createError({
            cause: new AggregateError([error, dbError]),
            code: "DB_UNAVAILABLE",
            message: "Session creation compensation failed.",
          });
        }

        throw error;
      }

      return {
        session: toSession(stored),
        token,
      };
    },

    resolve: async (input) => {
      const validated = await validateSession(input);

      if (!validated) {
        return null;
      }

      const { current, stored, token_hash } = validated;
      const due =
        current.getTime() - Date.parse(stored.touched_at) >=
        config.renewInterval * 1000;

      if (!due) {
        return { renewed: false, session: toSession(stored) };
      }

      const expires_at = new Date(current.getTime() + config.ttl * 1000);
      const renewed: StoredSession<TData> = {
        ...stored,
        expires_at: expires_at.toISOString(),
        touched_at: current.toISOString(),
      };

      await runDb(() =>
        db.updateExpiry({
          expires_at,
          session_id: stored.id,
          updated_at: current,
        }),
      );

      const updated = await runRedis(() =>
        redis.update({
          token_hash,
          ttl: config.ttl,
          value: encodeSession(renewed),
        }),
      );

      return updated ? { renewed: true, session: toSession(renewed) } : null;
    },

    validate: async (input) => {
      const validated = await validateSession(input);
      return validated ? toSession(validated.stored) : null;
    },

    revokeToken: async (token) => {
      if (!tokenPattern.test(token)) {
        return [];
      }

      const token_hash = hashToken(token);
      const raw = await runRedis(() => redis.get(token_hash));

      if (!raw) {
        return [];
      }

      const stored = parseSession<TData>(raw);
      await runRedis(() => redis.delete([token_hash]));

      if (!stored) {
        return [];
      }

      await runDb(() =>
        db.revoke({ revoked_at: now(), session_ids: [stored.id] }),
      );

      return [stored.id];
    },

    revoke: async ({ account_id, session_id }) => {
      const row = await runDb(() => db.find({ account_id, session_id }));

      if (row?.revoked_at !== null) {
        throw createError({
          code: "SESSION_NOT_FOUND",
          message: "Session not found.",
        });
      }

      return revokeRows({ revoked_at: now(), rows: [row] });
    },

    revokeAccount: async (account_id) => {
      return revokeRows({
        revoked_at: now(),
        rows: await getActive(account_id),
      });
    },

    list: async (account_id) => {
      return (await getActive(account_id)).map(toActiveSession);
    },

    sync: async ({ account_id, data }) => {
      const rows = await getActive(account_id);

      if (rows.length === 0) {
        return;
      }

      const token_hashes = rows.map((row) => row.token_hash);
      const values = await runRedis(() => redis.getMany(token_hashes));

      if (values.length !== token_hashes.length) {
        throw createError({
          code: "REDIS_UNAVAILABLE",
          message: "Authentication service returned invalid data.",
        });
      }

      await Promise.all(
        values.map(async (raw, index) => {
          if (!raw) return;

          const stored = parseSession<TData>(raw);
          const token_hash = token_hashes[index];

          if (!stored || !token_hash || stored.account_id !== account_id) {
            if (token_hash) {
              await runRedis(() => redis.delete([token_hash]));
            }
            return;
          }

          await runRedis(() =>
            redis.keep({
              token_hash,
              value: encodeSession({ ...stored, data }),
            }),
          );
        }),
      );
    },
  };
};
