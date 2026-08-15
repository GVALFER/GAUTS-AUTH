import type { Context, Env, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createAuth, type Auth, type AuthDeps } from "../../auth.js";
import type { SessionClientInput } from "../../client/index.js";
import { createError, isAuthError } from "../../errors.js";
import type { Session } from "../../session/types.js";

export type HonoAuthVariables<TData extends object> = {
  account: TData;
  session: Session<TData>;
};

export type HonoAuthEnv<TData extends object> = Env & {
  Variables: HonoAuthVariables<TData>;
};

export type HonoCookieConfig = {
  domain?: string;
  name?: string;
  path?: string;
  sameSite?: "Strict" | "Lax" | "None";
  secure?: boolean;
};

export type HonoGetIp = (
  c: Context,
) => Promise<string | null | undefined> | string | null | undefined;

export type HonoAdapterConfig<TData extends object> = {
  auth: Auth<TData>;
  cookie?: HonoCookieConfig;
  getIp: HonoGetIp;
};

export type HonoAuthConfig = AuthDeps & {
  cookie?: HonoCookieConfig;
  getIp: HonoGetIp;
};

type CreateSessionInput<TData extends object> = {
  accountId: string;
  context: Context;
  data: TData;
};

export type HonoAdapter<TData extends object> = {
  clearSession(c: Context): void;
  createSession(input: CreateSessionInput<TData>): Promise<Session<TData>>;
  getToken(c: Context): string | null;
  requireSession: MiddlewareHandler<HonoAuthEnv<TData>>;
  resolveSession(c: Context): Promise<Session<TData>>;
  revokeSession(c: Context): Promise<string[]>;
};

export type HonoAuth<TData extends object> = Auth<TData> & HonoAdapter<TData>;

const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

const resolveCookie = (config: HonoCookieConfig = {}) => {
  const name = config.name ?? "__Host-session";
  const path = config.path ?? "/";
  const sameSite = config.sameSite ?? "Lax";
  const secure = config.secure ?? true;

  if (!COOKIE_NAME_PATTERN.test(name)) {
    throw createError({
      code: "AUTH_CONFIG_INVALID",
      message: "Session cookie name is invalid.",
    });
  }

  if (!path.startsWith("/")) {
    throw createError({
      code: "AUTH_CONFIG_INVALID",
      message: "Session cookie path must start with /.",
    });
  }

  if (
    name.startsWith("__Host-") &&
    (!secure || path !== "/" || config.domain)
  ) {
    throw createError({
      code: "AUTH_CONFIG_INVALID",
      message: "__Host- cookies require secure=true, path=/, and no domain.",
    });
  }

  if (name.startsWith("__Secure-") && !secure) {
    throw createError({
      code: "AUTH_CONFIG_INVALID",
      message: "__Secure- cookies require secure=true.",
    });
  }

  if (sameSite === "None" && !secure) {
    throw createError({
      code: "AUTH_CONFIG_INVALID",
      message: "SameSite=None cookies require secure=true.",
    });
  }

  return {
    name,
    options: {
      ...(config.domain ? { domain: config.domain } : {}),
      httpOnly: true as const,
      path,
      sameSite,
      secure,
    },
  };
};

export const createHonoAdapter = <TData extends object>({
  auth,
  cookie,
  getIp,
}: HonoAdapterConfig<TData>): HonoAdapter<TData> => {
  if (typeof getIp !== "function") {
    throw createError({
      code: "AUTH_CONFIG_INVALID",
      message: "Hono getIp must be a function.",
    });
  }

  const resolved = resolveCookie(cookie);

  const getSessionClient = async (c: Context): Promise<SessionClientInput> => ({
    ip: (await getIp(c)) ?? null,
    platform: c.req.header("sec-ch-ua-platform") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
  });

  const getToken = (c: Context): string | null => {
    const token = getCookie(c, resolved.name)?.trim();

    return token?.length ? token : null;
  };

  const setToken = ({
    context,
    expiresAt,
    token,
  }: {
    context: Context;
    expiresAt: Date;
    token: string;
  }): void => {
    setCookie(context, resolved.name, token, {
      ...resolved.options,
      expires: expiresAt,
    });
  };

  const clearSession = (c: Context): void => {
    deleteCookie(c, resolved.name, resolved.options);
  };

  const createSession = async ({
    accountId,
    context,
    data,
  }: CreateSessionInput<TData>): Promise<Session<TData>> => {
    const created = await auth.session.create({
      accountId,
      client: await getSessionClient(context),
      data,
    });

    setToken({
      context,
      expiresAt: created.session.expiresAt,
      token: created.token,
    });

    return created.session;
  };

  const resolveSession = async (c: Context): Promise<Session<TData>> => {
    const token = getToken(c);

    if (!token) {
      throw createError({
        code: "SESSION_INVALID",
        message: "Authentication required.",
      });
    }

    let resolvedSession;

    try {
      resolvedSession = await auth.session.resolve({
        client: await getSessionClient(c),
        token,
      });
    } catch (error) {
      if (isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH") {
        clearSession(c);
      }

      throw error;
    }

    if (!resolvedSession) {
      clearSession(c);
      throw createError({
        code: "SESSION_INVALID",
        message: "Authentication required.",
      });
    }

    if (resolvedSession.renewed) {
      setToken({
        context: c,
        expiresAt: resolvedSession.session.expiresAt,
        token,
      });
    }

    return resolvedSession.session;
  };

  const requireSession: MiddlewareHandler<HonoAuthEnv<TData>> = async (
    c,
    next,
  ) => {
    const session = await resolveSession(c);

    c.set("session", session);
    c.set("account", session.data);
    await next();
  };

  const revokeSession = async (c: Context): Promise<string[]> => {
    const token = getToken(c);
    const revoked = token ? await auth.session.revokeToken(token) : [];

    clearSession(c);

    return revoked;
  };

  return {
    clearSession,
    createSession,
    getToken,
    requireSession,
    resolveSession,
    revokeSession,
  };
};

export const createHonoAuth = <TData extends object = Record<string, unknown>>({
  cookie,
  getIp,
  password,
  records,
  redis,
  session,
}: HonoAuthConfig): HonoAuth<TData> => {
  const auth = createAuth<TData>({
    records,
    redis,
    ...(password === undefined ? {} : { password }),
    ...(session === undefined ? {} : { session }),
  });

  return {
    ...auth,
    ...createHonoAdapter({
      auth,
      getIp,
      ...(cookie === undefined ? {} : { cookie }),
    }),
  };
};
