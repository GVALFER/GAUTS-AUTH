import type { Context, Env, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createAuth, type Auth, type AuthDeps } from "../../auth.js";
import type { SessionClientInput } from "../../client/index.js";
import { createError, isAuthError } from "../../errors.js";
import type { AuthAccount, AuthUser, ResolvedSession, Session } from "../../session/types.js";
import {
    createSessionCookie,
    parseSessionCookie,
    resolveSessionCookieName,
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
    domain?: string;
    name?: string;
    path?: string;
    sameSite?: "Strict" | "Lax" | "None";
    secure?: boolean;
};

export type HonoGetIp = (
    c: Context,
) => Promise<string | null | undefined> | string | null | undefined;

export type HonoAdapterConfig = {
    auth: Auth;
    cookie?: HonoCookieConfig;
    getIp: HonoGetIp;
};

export type HonoAuthConfig = AuthDeps & {
    cookie?: HonoCookieConfig;
    getIp: HonoGetIp;
};

type CreateSessionInput = {
    account_id: string;
    context: Context;
};

type SetSessionInput = {
    context: Context;
    session: Session;
    token: string;
};

export type HonoAdapter = {
    clearSession(c: Context): void;
    createSession(input: CreateSessionInput): Promise<Session>;
    getToken(c: Context): string | null;
    renewSession(c: Context): Promise<Session>;
    requireSession: MiddlewareHandler<HonoAuthEnv>;
    resolveSession(c: Context): Promise<ResolvedSession>;
    revokeSession(c: Context): Promise<string[]>;
};

export type HonoAuth = Auth & HonoAdapter;

const resolveCookie = (config: HonoCookieConfig = {}) => {
    const name = resolveSessionCookieName(config.name);
    const path = config.path ?? "/";
    const sameSite = config.sameSite ?? "Lax";
    const secure = config.secure ?? true;

    if (!path.startsWith("/")) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cookie path must start with /.",
        });
    }

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

export const createHonoAdapter = ({ auth, cookie, getIp }: HonoAdapterConfig): HonoAdapter => {
    if (typeof getIp !== "function") {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Hono getIp must be a function.",
        });
    }

    const resolved = resolveCookie(cookie);

    const getSessionClient = async (c: Context): Promise<SessionClientInput> => ({
        agent: c.req.header("user-agent") ?? null,
        ip: (await getIp(c)) ?? null,
        platform: c.req.header("sec-ch-ua-platform") ?? null,
    });

    const getCookieData = (c: Context) => {
        return parseSessionCookie(getCookie(c, resolved.name));
    };

    const getToken = (c: Context): string | null => {
        return getCookieData(c)?.token ?? null;
    };

    const setSession = ({ context, session, token }: SetSessionInput): void => {
        setCookie(
            context,
            resolved.name,
            createSessionCookie({ renew_at: session.renew_at, token }),
            { ...resolved.options, expires: session.expires_at },
        );
    };

    const clearSession = (c: Context): void => {
        deleteCookie(c, resolved.name, resolved.options);
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

    const createSession = async ({ account_id, context }: CreateSessionInput): Promise<Session> => {
        const created = await auth.session.create({
            account_id,
            client: await getSessionClient(context),
        });

        setSession({
            context,
            session: created.session,
            token: created.token,
        });

        return created.session;
    };

    const resolveSession = async (c: Context): Promise<ResolvedSession> => {
        const token = requireToken(c);
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

        return resolvedSession;
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
        return renewed.session;
    };

    const requireSession: MiddlewareHandler<HonoAuthEnv> = async (c, next) => {
        const { account, session, user } = await resolveSession(c);

        c.set("session", session);
        c.set("account", account);
        c.set("user", user);
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
        renewSession,
        requireSession,
        resolveSession,
        revokeSession,
    };
};

export const createHonoAuth = ({
    cookie,
    db,
    getIp,
    password,
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
            getIp,
            ...(cookie === undefined ? {} : { cookie }),
        }),
    };
};
