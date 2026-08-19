import type { Auth } from "../../auth.js";
import type { SessionCacheConfig } from "../../session/state.js";
import type { SessionCookieNames } from "../../session/cookie.js";
import type { AuthAccount, ResolvedSession, Session } from "../../session/types.js";

export type HttpCookieConfig = {
    contextName?: string;
    domain?: string;
    path?: string;
    sameSite?: "Strict" | "Lax" | "None";
    secure?: boolean;
    sessionName?: string;
};

export type HttpCookieOptions = {
    domain?: string;
    httpOnly: true;
    path: string;
    sameSite: "Strict" | "Lax" | "None";
    secure: boolean;
};

export type ResolvedHttpCookie = {
    names: SessionCookieNames;
    options: HttpCookieOptions;
};

export type HttpGetIp<TRequest> = (
    request: TRequest,
) => Promise<string | null | undefined> | string | null | undefined;

export type HttpSessionConfig<TRequest, TResponse, TAccount extends AuthAccount> = {
    appendSetCookie: (input: { response: TResponse; value: string }) => void;
    auth: Auth<TAccount>;
    cache?: SessionCacheConfig;
    cookie?: HttpCookieConfig;
    framework: string;
    getHeader: (input: { name: string; request: TRequest }) => string | undefined;
    getIp?: HttpGetIp<TRequest>;
    getMethod: (request: TRequest) => string;
    secret: string;
};

export type HttpCreateSessionInput<TRequest, TResponse> = {
    account_id: string;
    country?: string | null;
    request: TRequest;
    response: TResponse;
};

export type HttpRequestInput<TRequest, TResponse> = {
    request: TRequest;
    response: TResponse;
};

export type HttpSessionAdapter<TRequest, TResponse, TAccount extends AuthAccount> = {
    clearSession(response: TResponse): void;
    cookie: Readonly<SessionCookieNames>;
    createSession(input: HttpCreateSessionInput<TRequest, TResponse>): Promise<Session>;
    getToken(request: TRequest): string | null;
    renewSession(input: HttpRequestInput<TRequest, TResponse>): Promise<Session>;
    resolveSession(
        input: HttpRequestInput<TRequest, TResponse>,
    ): Promise<ResolvedSession<TAccount>>;
    revokeSession(input: HttpRequestInput<TRequest, TResponse>): Promise<string[]>;
};
