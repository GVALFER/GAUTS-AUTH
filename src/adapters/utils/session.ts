import type { SessionClientInput } from "../../client/index.js";
import { createError, isAuthError } from "../../errors.js";
import { createSessionCache, type SessionCache } from "../../session/cache.js";
import { formatRenewAt, parseSessionToken } from "../../session/cookie.js";
import type { AuthAccount, ResolvedSession } from "../../session/types.js";
import { createCookieHeader, getCookieValue, resolveHttpCookie } from "./cookie.js";
import type { HttpRequestInput, HttpSessionAdapter, HttpSessionConfig } from "./types.js";

type ResolveDbSessionInput<TResponse> = {
    client: SessionClientInput;
    response: TResponse;
    token: string;
};

type SetCookieInput<TResponse> = {
    expires?: Date;
    maxAge?: number;
    name: string;
    response: TResponse;
    value: string;
};

type SetSessionInput<TResponse, TAccount extends AuthAccount> = {
    response: TResponse;
    session: ResolvedSession<TAccount>["session"];
    token: string;
};

type SetCacheInput<TResponse, TAccount extends AuthAccount> = {
    response: TResponse;
    session: ResolvedSession<TAccount>;
    token: string;
};

const canUseCache = (method: string): boolean => method === "GET" || method === "HEAD";

export const createHttpSession = <TRequest, TResponse, TAccount extends AuthAccount>({
    appendSetCookie,
    auth,
    cache,
    cookie,
    framework,
    getHeader,
    getIp,
    getMethod,
    secret,
}: HttpSessionConfig<TRequest, TResponse, TAccount>): HttpSessionAdapter<
    TRequest,
    TResponse,
    TAccount
> => {
    if (getIp !== undefined && typeof getIp !== "function") {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${framework} getIp must be a function.`,
        });
    }

    if (auth.config.session.validation.includes("ip") && !getIp) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${framework} getIp is required when session validation includes ip.`,
        });
    }

    const resolvedCookie = resolveHttpCookie(cookie);
    let cacheService: SessionCache<TAccount> | null = null;

    if (cache !== undefined) {
        if (typeof secret !== "string") {
            throw createError({
                code: "AUTH_CONFIG_INVALID",
                message: "Authentication secret is required when session cache is configured.",
            });
        }

        cacheService = createSessionCache<TAccount>({
            config: cache,
            secret,
            session: auth.config.session,
        });
    }

    const getCookie = ({ name, request }: { name: string; request: TRequest }) => {
        const header = getHeader({ name: "cookie", request });

        return getCookieValue({
            ...(header === undefined ? {} : { header }),
            name,
        });
    };

    const getSessionClient = async (request: TRequest): Promise<SessionClientInput> => ({
        agent: getHeader({ name: "user-agent", request }) ?? null,
        ip: getIp ? ((await getIp(request)) ?? null) : null,
        platform: getHeader({ name: "sec-ch-ua-platform", request }) ?? null,
    });

    const getToken = (request: TRequest): string | null => {
        return parseSessionToken(getCookie({ name: resolvedCookie.names.sessionName, request }));
    };

    const setCookie = ({
        expires,
        maxAge,
        name,
        response,
        value,
    }: SetCookieInput<TResponse>): void => {
        appendSetCookie({
            response,
            value: createCookieHeader({
                ...(expires === undefined ? {} : { expires }),
                ...(maxAge === undefined ? {} : { maxAge }),
                name,
                options: resolvedCookie.options,
                value,
            }),
        });
    };

    const deleteCookie = ({ name, response }: { name: string; response: TResponse }): void => {
        setCookie({
            expires: new Date(0),
            maxAge: 0,
            name,
            response,
            value: "",
        });
    };

    const setSession = ({
        response,
        session,
        token,
    }: SetSessionInput<TResponse, TAccount>): void => {
        setCookie({
            expires: session.expires_at,
            name: resolvedCookie.names.sessionName,
            response,
            value: token,
        });
        setCookie({
            expires: session.expires_at,
            name: resolvedCookie.names.renewName,
            response,
            value: formatRenewAt(session.renew_at),
        });
    };

    const setCache = ({
        response,
        session,
        token,
    }: SetCacheInput<TResponse, TAccount>): void => {
        if (!cacheService) {
            return;
        }

        const cached = cacheService.create({ resolved: session, token });
        setCookie({
            expires: cached.expires_at,
            name: resolvedCookie.names.cacheName,
            response,
            value: cached.value,
        });
    };

    const clearCache = (response: TResponse): void => {
        if (cacheService) {
            deleteCookie({ name: resolvedCookie.names.cacheName, response });
        }
    };

    const clearSession = (response: TResponse): void => {
        deleteCookie({ name: resolvedCookie.names.sessionName, response });
        deleteCookie({ name: resolvedCookie.names.cacheName, response });
        deleteCookie({ name: resolvedCookie.names.renewName, response });
    };

    const requireToken = ({ request, response }: HttpRequestInput<TRequest, TResponse>): string => {
        const token = getToken(request);

        if (!token) {
            clearSession(response);
            throw createError({
                code: "SESSION_INVALID",
                message: "Authentication required.",
            });
        }

        return token;
    };

    const resolveDbSession = async ({
        client,
        response,
        token,
    }: ResolveDbSessionInput<TResponse>): Promise<ResolvedSession<TAccount>> => {
        let value;

        try {
            value = await auth.session.resolve({ client, token });
        } catch (error) {
            if (isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH") {
                clearSession(response);
            }

            throw error;
        }

        if (!value) {
            clearSession(response);
            throw createError({
                code: "SESSION_INVALID",
                message: "Authentication required.",
            });
        }

        return value;
    };

    const createSession: HttpSessionAdapter<
        TRequest,
        TResponse,
        TAccount
    >["createSession"] = async ({ account_id, country, request, response }) => {
        const created = await auth.session.create({
            account_id,
            client: await getSessionClient(request),
            ...(country === undefined ? {} : { country }),
        });
        const value: ResolvedSession<TAccount> = {
            account: created.account,
            session: created.session,
        };

        setSession({ response, session: created.session, token: created.token });
        setCache({ response, session: value, token: created.token });
        return created.session;
    };

    const resolveSession: HttpSessionAdapter<
        TRequest,
        TResponse,
        TAccount
    >["resolveSession"] = async ({ request, response }) => {
        const token = requireToken({ request, response });
        const client = await getSessionClient(request);
        const useCache = canUseCache(getMethod(request));

        if (cacheService && useCache) {
            const cached = cacheService.resolve({
                client,
                token,
                value: getCookie({ name: resolvedCookie.names.cacheName, request }),
            });

            if (cached) {
                return cached;
            }
        }

        const value = await resolveDbSession({ client, response, token });

        if (cacheService && useCache) {
            setCache({ response, session: value, token });
        } else {
            clearCache(response);
        }

        return value;
    };

    const renewSession: HttpSessionAdapter<TRequest, TResponse, TAccount>["renewSession"] = async ({
        request,
        response,
    }) => {
        const token = requireToken({ request, response });
        let renewed;

        try {
            renewed = await auth.session.renew({
                client: await getSessionClient(request),
                token,
            });
        } catch (error) {
            if (isAuthError(error) && error.code === "SESSION_CLIENT_MISMATCH") {
                clearSession(response);
            }

            throw error;
        }

        if (!renewed) {
            clearSession(response);
            throw createError({
                code: "SESSION_INVALID",
                message: "Authentication required.",
            });
        }

        setSession({ response, session: renewed.session, token });
        setCache({ response, session: renewed, token });
        return renewed.session;
    };

    const revokeSession: HttpSessionAdapter<
        TRequest,
        TResponse,
        TAccount
    >["revokeSession"] = async ({ request, response }) => {
        const token = getToken(request);
        const revoked = token ? await auth.session.revokeToken(token) : [];

        clearSession(response);
        return revoked;
    };

    return {
        clearSession,
        cookie: resolvedCookie.names,
        createSession,
        getToken,
        renewSession,
        resolveSession,
        revokeSession,
    };
};
