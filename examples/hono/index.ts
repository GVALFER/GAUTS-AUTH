import { Hono, type Context } from "hono";
import { createAuth, isAuthError, type SessionRecords } from "@gauts/auth";
import { createHonoAdapter, type HonoAuthEnv } from "@gauts/auth/hono";
import { createRedisStore } from "@gauts/auth/redis";
import type { RedisClientType } from "redis";

type AccountSession = {
  email: string;
  role: "admin" | "owner";
};

type Account = AccountSession & {
  id: string;
  passwordHash: string;
};

type ExampleDeps = {
  findAccount: (email: string) => Promise<Account | null>;
  getIp: (
    c: Context,
  ) => Promise<string | null | undefined> | string | null | undefined;
  records: SessionRecords;
  redis: RedisClientType;
};

export const createApp = ({
  findAccount,
  getIp,
  records,
  redis,
}: ExampleDeps) => {
  const auth = createAuth<AccountSession>({
    records,
    redis: createRedisStore({
      client: redis,
      config: { prefix: "example:auth" },
    }),
  });

  const hono = createHonoAdapter({ auth, getIp });
  const app = new Hono<HonoAuthEnv<AccountSession>>();

  app.onError((error, c) => {
    if (!isAuthError(error)) {
      return c.json({ error: "Internal server error." }, 500);
    }

    const status =
      error.code === "REDIS_UNAVAILABLE" || error.code === "RECORDS_UNAVAILABLE"
        ? 503
        : 401;

    return c.json({ error: error.message }, status);
  });

  app.post("/auth/login", async (c) => {
    const body = await c.req.json<{ email: string; password: string }>();
    const account = await findAccount(body.email);

    if (
      !account ||
      !(await auth.password.verify({
        password: body.password,
        storedHash: account.passwordHash,
      }))
    ) {
      return c.json({ error: "Invalid credentials." }, 401);
    }

    const session = await hono.createSession({
      accountId: account.id,
      context: c,
      data: { email: account.email, role: account.role },
    });

    return c.json({ account: session.data });
  });

  app.post("/auth/logout", async (c) => {
    await hono.revokeSession(c);
    return c.body(null, 204);
  });

  app.get("/account", hono.requireSession, (c) =>
    c.json({ accountId: c.get("session").accountId }),
  );

  return app;
};
