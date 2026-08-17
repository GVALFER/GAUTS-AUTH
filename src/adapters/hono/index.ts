import type { Context, Env, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createAuth, type Auth, type AuthDeps } from "../../auth.js";
import type { SessionClientInput } from "../../client/index.js";
import { createError, isAuthError } from "../../errors.js";
import { createSessionCache, type SessionCacheConfig } from "../../session/cache.js";
import type { AuthAccount, AuthUser, ResolvedSession, Session } from "../../session/types.js";

export type { SessionCacheConfig } from "../../session/cache.js";
import {
    formatRenewAt,
    parseSessionToken,
    resolveSessionCookieNames,
    type SessionCookieNames,
} from "../../session/cookie.js";

export type HonoAuthVariables = {
    account: AuthAccount;
    session: Session;
    user: AuthUser;
};

export type HonoAuthEnv = Env & {
    Variables: HonoAuthVariables;
};

export type HonoCookieConfig = {
    cacheName?: string;
    domain?: string;
    path?: string;
    renewName?: string;
    sameSite?: "Strict" | "Lax" | "None";
    secure?: boolean;
    sessionName?: string;
};

export type HonoGetIp = (
    c: Context,
) => Promise<string | null | undefined> | string | null | undefined;

type HonoCacheOptions =
    | {
          cache: SessionCacheConfig;
          secret: string;
      }
    | {
          cache?: undefined;
          secret?: string;
      };

export type HonoAdapterConfig = {
    auth: Auth;
    cache?: SessionCacheConfig;
    cookie?: HonoCookieConfig;
    getIp?: HonoGetIp;
    secret?: string;
};

type HonoAuthBase = AuthDeps & {
    cookie?: HonoCookieConfig;
    getIp?: HonoGetIp;
};

export type HonoAuthConfig = HonoAuthBase & HonoCacheOptions;

type CreateSessionInput = {
    account_id: string;
    context: Context;
};

type SetSessionInput = {
    context: Context;
    session: Session;
    token: string;
};

type SetCacheInput = {
    context: Context;
    resolved: ResolvedSession;
    token: string;
};

export type HonoAdapter = {
    clearSession(c: Context): void;
    cookie: Readonly<SessionCookieNames>;
    createSession(input: CreateSessionInput): Promise<Session>;
    getToken(c: Context): string | null;
    renewSession(c: Context): Promise<Session>;
    requireSession: MiddlewareHandler<HonoAuthEnv>;
    resolveSession(c: Context): Promise<ResolvedSession>;
    revokeSession(c: Context): Promise<string[]>;
};

export type HonoAuth = Auth & HonoAdapter;

const resolveCookie = (config: HonoCookieConfig = {}) => {
    const names = resolveSessionCookieNames(config);
    const path = config.path ?? "/";
    const sameSite = config.sameSite ?? "Lax";
    const secure = config.secure ?? true;

    if (!path.startsWith("/")) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie path must start with /.",
        });
    }

    for (const name of Object.values(names)) {
        if (name.startsWith("__Host-") && (!secure || path !== "/" || config.domain)) {
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
    }

    if (sameSite === "None" && !secure) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "SameSite=None cookies require secure=true.",
        });
    }

    return {
        names,
        options: {
            ...(config.domain ? { domain: config.domain } : {}),
            httpOnly: true as const,
            path,
            sameSite,
            secure,
        },
    };
};

const canUseCache = (method: string): boolean => method === "GET" || method === "HEAD";

export const createHonoAdapter = ({
    auth,
    cache,
    cookie,
    getIp,
    secret,
}: HonoAdapterConfig): HonoAdapter => {
    if (getIp !== undefined && typeof getIp !== "function") {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Hono getIp must be a function.",
        });
    }

    if (auth.config.session.validation.includes("ip") && !getIp) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Hono getIp is required when session validation includes ip.",
        });
    }

    const resolved = resolveCookie(cookie);
    let cacheService = null;

    if (cache !== undefined) {
        if (typeof secret !== "string") {
            throw createError({
                code: "AUTH_CONFIG_INVALID",
                message: "Authentication secret is required when session cache is configured.",
            });
        }

        cacheService = createSessionCache({
            config: cache,
            secret,
            session: auth.config.session,
        });
    }

    const getSessionClient = async (c: Context): Promise<SessionClientInput> => ({
        agent: c.req.header("user-agent") ?? null,
        ip: getIp ? ((await getIp(c)) ?? null) : null,
        platform: c.req.header("sec-ch-ua-platform") ?? null,
    });

    const getToken = (c: Context): string | null => {
        return parseSessionToken(getCookie(c, resolved.names.sessionName));
    };

    const setSession = ({ context, session: value, token }: SetSessionInput): void => {
        setCookie(context, resolved.names.sessionName, token, {
            ...resolved.options,
            expires: value.expires_at,
        });
        setCookie(context, resolved.names.renewName, formatRenewAt(value.renew_at), {
            ...resolved.options,
            expires: value.expires_at,
        });
    };

    const setCache = ({ context, resolved: value, token }: SetCacheInput): void => {
        if (!cacheService) {
            return;
        }

        const cached = cacheService.create({ resolved: value, token });
        setCookie(context, resolved.names.cacheName, cached.value, {
            ...resolved.options,
            expires: cached.expires_at,
        });
    };

    const clearCache = (c: Context): void => {
        if (cacheService) {
            deleteCookie(c, resolved.names.cacheName, resolved.options);
        }
    };

    const clearSession = (c: Context): void => {
        deleteCookie(c, resolved.names.sessionName, resolved.options);
        deleteCookie(c, resolved.names.cacheName, resolved.options);
        deleteCookie(c, resolved.names.renewName, resolved.options);
    };

    const requireToken = (c: Context): string => {
        const token = getToken(c);

        if (!token) {
            clearSession(c);
            throw createError({
                code: "SESSION_INVALID",
                message: "Authentication required.",
            });
        }

        return token;
    };

    const resolveDbSession = async ({
        client,
        context,
        token,
    }: {
        client: SessionClientInput;
        context: Context;
        token: string;
    }): Promise<ResolvedSession> => {
        let value;

        try {
            value = await auth.session.resolve({ client, token });
        } catch (error) {
            if (isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH") {
                clearSession(context);
            }

            throw error;
        }

        if (!value) {
            clearSession(context);
            throw createError({
                code: "SESSION_INVALID",
                message: "Authentication required.",
            });
        }

        return value;
    };

    const createSession = async ({ account_id, context }: CreateSessionInput): Promise<Session> => {
        const created = await auth.session.create({
            account_id,
            client: await getSessionClient(context),
        });
        const value: ResolvedSession = {
            account: created.account,
            session: created.session,
            user: created.user,
        };

        setSession({ context, session: created.session, token: created.token });
        setCache({ context, resolved: value, token: created.token });

        return created.session;
    };

    const resolveSession = async (c: Context): Promise<ResolvedSession> => {
        const token = requireToken(c);
        const client = await getSessionClient(c);
        const useCache = canUseCache(c.req.method);

        if (cacheService && useCache) {
            const cached = cacheService.resolve({
                client,
                token,
                value: getCookie(c, resolved.names.cacheName),
            });

            if (cached) {
                return cached;
            }
        }

        const value = await resolveDbSession({ client, context: c, token });

        if (cacheService && useCache) {
            setCache({ context: c, resolved: value, token });
        } else {
            clearCache(c);
        }

        return value;
    };

    const renewSession = async (c: Context): Promise<Session> => {
        const token = requireToken(c);
        let renewed;

        try {
            renewed = await auth.session.renew({
                client: await getSessionClient(c),
                token,
            });
        } catch (error) {
            if (isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH") {
                clearSession(c);
            }

            throw error;
        }

        if (!renewed) {
            clearSession(c);
            throw createError({
                code: "SESSION_INVALID",
                message: "Authentication required.",
            });
        }

        setSession({ context: c, session: renewed.session, token });
        setCache({ context: c, resolved: renewed, token });
        return renewed.session;
    };

    const requireSession: MiddlewareHandler<HonoAuthEnv> = async (c, next) => {
        const value = await resolveSession(c);

        c.set("session", value.session);
        c.set("account", value.account);
        c.set("user", value.user);
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
        cookie: resolved.names,
        createSession,
        getToken,
        renewSession,
        requireSession,
        resolveSession,
        revokeSession,
    };
};

export const createHonoAuth = ({
    cache,
    cookie,
    db,
    getIp,
    password,
    secret,
    session,
}: HonoAuthConfig): HonoAuth => {
    const auth = createAuth({
        db,
        ...(password === undefined ? {} : { password }),
        ...(session === undefined ? {} : { session }),
    });

    return {
        ...auth,
        ...createHonoAdapter({
            auth,
            ...(cache === undefined ? {} : { cache }),
            ...(cookie === undefined ? {} : { cookie }),
            ...(getIp === undefined ? {} : { getIp }),
            ...(secret === undefined ? {} : { secret }),
        }),
    };
};
