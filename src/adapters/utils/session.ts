import type { SessionClientInput } from "../../client/index.js";
import { createError, isAuthError } from "../../errors.js";
import { parseSessionToken } from "../../session/cookie.js";
import {
    createSessionState,
    type ResolvedSessionState,
    type SessionState,
} from "../../session/state.js";
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

type SetSessionInput<TResponse> = {
    expires_at: Date;
    response: TResponse;
    token: string;
};

type SetStateInput<TResponse, TAccount extends AuthAccount> = {
    cache?: boolean;
    response: TResponse;
    session: ResolvedSession<TAccount>;
    token: string;
};

type GetStateInput<TRequest> = {
    client: SessionClientInput;
    request: TRequest;
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
    const stateService: SessionState<TAccount> = createSessionState({
        secret,
        session: auth.config.session,
        ...(cache === undefined ? {} : { cache }),
    });

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

    const getState = ({
        client,
        request,
        token,
    }: GetStateInput<TRequest>): ResolvedSessionState<TAccount> | null => {
        return stateService.resolve({
            client,
            token,
            value: getCookie({ name: resolvedCookie.names.contextName, request }),
        });
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

    const setSession = ({ expires_at, response, token }: SetSessionInput<TResponse>): void => {
        setCookie({
            expires: expires_at,
            name: resolvedCookie.names.sessionName,
            response,
            value: token,
        });
    };

    const setState = ({
        cache: useCache,
        response,
        session,
        token,
    }: SetStateInput<TResponse, TAccount>): void => {
        const state = stateService.create({
            resolved: session,
            token,
            ...(useCache === undefined ? {} : { cache: useCache }),
        });

        setCookie({
            expires: state.expires_at,
            name: resolvedCookie.names.contextName,
            response,
            value: state.value,
        });
    };

    const clearSession = (response: TResponse): void => {
        deleteCookie({ name: resolvedCookie.names.sessionName, response });
        deleteCookie({ name: resolvedCookie.names.contextName, response });
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

    const renewDbSession = async ({
        client,
        response,
        token,
    }: ResolveDbSessionInput<TResponse>): Promise<ResolvedSession<TAccount>> => {
        let value;

        try {
            value = await auth.session.renew({ client, token });
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

        return {
            account: value.account,
            session: value.session,
        };
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

        setSession({ expires_at: created.session.expires_at, response, token: created.token });
        setState({ response, session: value, token: created.token });
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
        const state = getState({ client, request, token });

        if (!state || state.renew_at.getTime() <= Date.now()) {
            const value = await renewDbSession({ client, response, token });

            setSession({ expires_at: value.session.expires_at, response, token });
            setState({ cache: useCache, response, session: value, token });
            return value;
        }

        if (useCache && state.cache) {
            return state.cache;
        }

        const value = await resolveDbSession({ client, response, token });

        if (cache !== undefined) {
            setState({ cache: useCache, response, session: value, token });
        }

        return value;
    };

    const renewSession: HttpSessionAdapter<TRequest, TResponse, TAccount>["renewSession"] = async ({
        request,
        response,
    }) => {
        const token = requireToken({ request, response });
        const value = await renewDbSession({
            client: await getSessionClient(request),
            response,
            token,
        });

        setSession({ expires_at: value.session.expires_at, response, token });
        setState({ response, session: value, token });
        return value.session;
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
