import { randomUUID } from "node:crypto";

import { matchesClient, normalizeClient } from "../client/index.js";
import type { ResolvedSessionConfig } from "../config.js";
import { createError, isAuthError } from "../errors.js";
import { encodeSession, parseSession, toSession } from "./schema.js";
import { createToken, hashToken, tokenPattern } from "./token.js";
import type {
  ActiveSession,
  RedisSessionStore,
  SessionInput,
  SessionRecord,
  SessionActions,
  SessionService,
  StoredSession,
} from "./types.js";

type SessionDeps = {
  actions: SessionActions;
  config: ResolvedSessionConfig;
  now?: () => Date;
  redis: RedisSessionStore;
};

type RevokeRowsProps = {
  revokedAt: Date;
  rows: SessionRecord[];
};

type ValidatedSession<TData extends object> = {
  current: Date;
  stored: StoredSession<TData>;
  tokenHash: string;
};

const toActiveSession = (session: SessionRecord): ActiveSession => ({
  accountId: session.accountId,
  client: session.client,
  createdAt: session.createdAt,
  expiresAt: session.expiresAt,
  id: session.id,
  revokedAt: session.revokedAt,
  updatedAt: session.updatedAt,
});

export const createSessionService = <TData extends object>({
  actions,
  config,
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

  const runAction = async <T>(operation: () => Promise<T>): Promise<T> => {
    try {
      return await operation();
    } catch (error) {
      if (isAuthError(error)) {
        throw error;
      }

      throw createError({
        cause: error,
        code: "SESSION_ACTION_FAILED",
        message: "Session action failed.",
      });
    }
  };

  const getActive = async (accountId: string): Promise<SessionRecord[]> => {
    const current = now();
    const rows = await runAction(() =>
      actions.findActive({ accountId, now: current }),
    );

    const valid = rows.filter(
      (row) =>
        row.revokedAt === null && row.expiresAt.getTime() > current.getTime(),
    );

    if (valid.length === 0) {
      return [];
    }

    const active = await runRedis(() =>
      redis.exists(valid.map((row) => row.tokenHash)),
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
    revokedAt,
    rows,
  }: RevokeRowsProps): Promise<string[]> => {
    if (rows.length === 0) {
      return [];
    }

    await runRedis(() => redis.delete(rows.map((row) => row.tokenHash)));
    const ids = rows.map((row) => row.id);
    await runAction(() => actions.revoke({ revokedAt, sessionIds: ids }));

    return ids;
  };

  const validateSession = async (
    input: SessionInput,
  ): Promise<ValidatedSession<TData> | null> => {
    if (!tokenPattern.test(input.token)) {
      return null;
    }

    const tokenHash = hashToken(input.token);
    const raw = await runRedis(() => redis.get(tokenHash));

    if (!raw) {
      return null;
    }

    const stored = parseSession<TData>(raw);

    if (!stored) {
      await runRedis(() => redis.delete([tokenHash]));
      return null;
    }

    const current = now();

    if (Date.parse(stored.expiresAt) <= current.getTime()) {
      await runRedis(() => redis.delete([tokenHash]));
      return null;
    }

    const client = normalizeClient(input.client);

    const matches = matchesClient({
      current: client,
      stored: stored.client,
      validation: config.validation,
    });

    if (!matches) {
      await runRedis(() => redis.delete([tokenHash]));

      try {
        await runAction(() =>
          actions.revoke({ revokedAt: current, sessionIds: [stored.id] }),
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

    return { current, stored, tokenHash };
  };

  return {
    create: async (input) => {
      if (!input.accountId) {
        throw createError({
          code: "SESSION_DATA_INVALID",
          message: "Session account ID is required.",
        });
      }

      const client = normalizeClient(input.client);
      const createdAt = now();
      const expiresAt = new Date(createdAt.getTime() + config.ttl * 1000);
      const token = createToken();
      const tokenHash = hashToken(token);
      const id = randomUUID();

      const stored: StoredSession<TData> = {
        accountId: input.accountId,
        client,
        createdAt: createdAt.toISOString(),
        data: input.data,
        expiresAt: expiresAt.toISOString(),
        id,
        touchedAt: createdAt.toISOString(),
      };

      const value = encodeSession(stored);
      const active = await getActive(input.accountId);

      if (active.length >= config.max) {
        throw createError({
          code: "SESSION_LIMIT_REACHED",
          message: `Maximum active sessions reached (${String(config.max)}).`,
        });
      }

      await runAction(() =>
        actions.create({
          accountId: input.accountId,
          client,
          createdAt,
          expiresAt,
          id,
          tokenHash,
        }),
      );

      try {
        await runRedis(() =>
          redis.create({ tokenHash, ttl: config.ttl, value }),
        );
      } catch (error) {
        try {
          await runAction(() =>
            actions.revoke({ revokedAt: now(), sessionIds: [id] }),
          );
        } catch (actionError) {
          throw createError({
            cause: new AggregateError([error, actionError]),
            code: "SESSION_ACTION_FAILED",
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

      const { current, stored, tokenHash } = validated;

      const due =
        current.getTime() - Date.parse(stored.touchedAt) >=
        config.renewInterval * 1000;

      if (!due) {
        return { renewed: false, session: toSession(stored) };
      }

      const expiresAt = new Date(current.getTime() + config.ttl * 1000);

      const renewed: StoredSession<TData> = {
        ...stored,
        expiresAt: expiresAt.toISOString(),
        touchedAt: current.toISOString(),
      };

      await runAction(() =>
        actions.updateExpiry({
          expiresAt,
          sessionId: stored.id,
          updatedAt: current,
        }),
      );

      const updated = await runRedis(() =>
        redis.update({
          tokenHash,
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

      const tokenHash = hashToken(token);
      const raw = await runRedis(() => redis.get(tokenHash));

      if (!raw) {
        return [];
      }

      const stored = parseSession<TData>(raw);
      await runRedis(() => redis.delete([tokenHash]));

      if (!stored) {
        return [];
      }

      await runAction(() =>
        actions.revoke({ revokedAt: now(), sessionIds: [stored.id] }),
      );

      return [stored.id];
    },

    revoke: async ({ accountId, sessionId }) => {
      const row = await runAction(() => actions.find({ accountId, sessionId }));

      if (row?.revokedAt !== null) {
        throw createError({
          code: "SESSION_NOT_FOUND",
          message: "Session not found.",
        });
      }

      return revokeRows({ revokedAt: now(), rows: [row] });
    },

    revokeAccount: async (accountId) => {
      return revokeRows({ revokedAt: now(), rows: await getActive(accountId) });
    },

    list: async (accountId) => {
      return (await getActive(accountId)).map(toActiveSession);
    },

    sync: async ({ accountId, data }) => {
      const rows = await getActive(accountId);

      if (rows.length === 0) {
        return;
      }

      const hashes = rows.map((row) => row.tokenHash);
      const values = await runRedis(() => redis.getMany(hashes));

      if (values.length !== hashes.length) {
        throw createError({
          code: "REDIS_UNAVAILABLE",
          message: "Authentication service returned invalid data.",
        });
      }

      await Promise.all(
        values.map(async (raw, index) => {
          if (!raw) return;

          const stored = parseSession<TData>(raw);
          const tokenHash = hashes[index];

          if (!stored || !tokenHash || stored.accountId !== accountId) {
            if (tokenHash) {
              await runRedis(() => redis.delete([tokenHash]));
            }
            return;
          }

          await runRedis(() =>
            redis.keep({
              tokenHash,
              value: encodeSession({ ...stored, data }),
            }),
          );
        }),
      );
    },
  };
};
