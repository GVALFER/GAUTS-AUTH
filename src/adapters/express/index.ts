import type { Request, RequestHandler, Response } from "express";
import { createAuth, type Auth, type AuthDeps } from "../../auth.js";
import type { SessionCookieNames } from "../../session/cookie.js";
import type { SessionCacheConfig } from "../../session/state.js";
import type { AuthAccount, DbAdapter, ResolvedSession, Session } from "../../session/types.js";
import type { SocialConfig, SocialDbAdapter } from "../../social/types.js";
import { resolveHttpCookie } from "../utils/cookie.js";
import { requireSocialDb } from "../utils/social.js";
import { createHttpSession } from "../utils/session.js";
import type { HttpCookieConfig } from "../utils/types.js";
import { createExpressSocial, type ExpressSocial } from "./social.js";

export type { SessionCacheConfig } from "../../session/state.js";
export type { ExpressSocial, ExpressSocialLocals } from "./social.js";

export type ExpressAuthLocals<TAccount extends AuthAccount = AuthAccount> = {
    account: TAccount;
    session: Session;
    user: TAccount["user"];
};

export type ExpressCookieConfig = HttpCookieConfig;

export type ExpressGetIp = (
    request: Request,
) => Promise<string | null | undefined> | string | null | undefined;

export type ExpressAdapterConfig<TAccount extends AuthAccount = AuthAccount> = {
    auth: Auth<TAccount>;
    cache?: SessionCacheConfig;
    cookie?: ExpressCookieConfig;
    getIp?: ExpressGetIp;
    secret: string;
};

type ExpressAuthBase<TAccount extends AuthAccount> = Omit<AuthDeps<TAccount>, "db"> & {
    cache?: SessionCacheConfig;
    cookie?: ExpressCookieConfig;
    db: DbAdapter<TAccount>;
    getIp?: ExpressGetIp;
    secret: string;
};

type ExpressSocialOptions<TAccount extends AuthAccount, TData> =
    | {
          db: DbAdapter<TAccount> & SocialDbAdapter<TAccount>;
          social: SocialConfig<TData>;
      }
    | {
          db: DbAdapter<TAccount>;
          social?: undefined;
      };

export type ExpressAuthConfig<TAccount extends AuthAccount = AuthAccount, TData = undefined> = Omit<
    ExpressAuthBase<TAccount>,
    "db"
> &
    ExpressSocialOptions<TAccount, TData>;

type ExpressAuthOptions<TAccount extends AuthAccount> = Omit<ExpressAuthBase<TAccount>, "db">;

type DbAccount<TDb> = TDb extends DbAdapter<infer TAccount> ? TAccount : never;

type ExpressRequestInput = {
    request: Request;
    response: Response;
};

type CreateSessionInput = ExpressRequestInput & {
    account_id: string;
    country?: string | null;
};

export type ExpressAdapter<TAccount extends AuthAccount = AuthAccount> = {
    clearSession(response: Response): void;
    cookie: Readonly<SessionCookieNames>;
    createSession(input: CreateSessionInput): Promise<Session>;
    getToken(request: Request): string | null;
    renewSession(input: ExpressRequestInput): Promise<Session>;
    requireSession: RequestHandler;
    resolveSession(input: ExpressRequestInput): Promise<ResolvedSession<TAccount>>;
    revokeSession(input: ExpressRequestInput): Promise<string[]>;
};

export type ExpressAuth<TAccount extends AuthAccount = AuthAccount> = Auth<TAccount> &
    ExpressAdapter<TAccount>;

export type ExpressSocialAuth<
    TAccount extends AuthAccount = AuthAccount,
    TData = undefined,
> = Auth<TAccount> &
    ExpressAdapter<TAccount> & {
        social: ExpressSocial<TAccount, TData>;
    };

export const createExpressAdapter = <TAccount extends AuthAccount>({
    auth,
    cache,
    cookie,
    getIp,
    secret,
}: ExpressAdapterConfig<TAccount>): ExpressAdapter<TAccount> => {
    const session = createHttpSession<Request, Response, TAccount>({
        auth,
        secret,
        framework: "Express",
        appendSetCookie: ({ response, value }) => {
            response.append("Set-Cookie", value);
        },
        getHeader: ({ name, request }) => request.get(name),
        getMethod: (request) => request.method,
        ...(cache === undefined ? {} : { cache }),
        ...(cookie === undefined ? {} : { cookie }),
        ...(getIp === undefined ? {} : { getIp }),
    });

    const resolveSession = (input: ExpressRequestInput): Promise<ResolvedSession<TAccount>> => {
        return session.resolveSession(input);
    };

    const requireSession: RequestHandler = async (request, response, next) => {
        const value = await resolveSession({ request, response });
        const locals = response.locals as ExpressAuthLocals<TAccount>;

        locals.session = value.session;
        locals.account = value.account;
        locals.user = value.account.user;
        next();
    };

    return {
        clearSession: (response) => session.clearSession(response),
        cookie: session.cookie,
        createSession: (input) => session.createSession(input),
        getToken: (request) => session.getToken(request),
        renewSession: (input) => session.renewSession(input),
        requireSession,
        resolveSession,
        revokeSession: (input) => session.revokeSession(input),
    };
};

type CreateExpressAuth = {
    <TDb extends DbAdapter, TData>(
        input: ExpressAuthOptions<DbAccount<TDb>> & {
            db: TDb & SocialDbAdapter<DbAccount<TDb>>;
            secret: string;
            social: SocialConfig<TData>;
        },
    ): ExpressSocialAuth<DbAccount<TDb>, TData>;
    <TDb extends DbAdapter>(
        input: ExpressAuthOptions<DbAccount<TDb>> & {
            db: TDb;
            social?: undefined;
        },
    ): ExpressAuth<DbAccount<TDb>>;
};

const createExpressAuthImpl = <TAccount extends AuthAccount, TData = undefined>({
    cache,
    cookie,
    db,
    getIp,
    password,
    secret,
    session,
    social,
}: ExpressAuthConfig<TAccount, TData>):
    ExpressAuth<TAccount> | ExpressSocialAuth<TAccount, TData> => {
    const auth = createAuth({
        db,
        ...(password === undefined ? {} : { password }),
        ...(session === undefined ? {} : { session }),
    });
    const adapter = createExpressAdapter({
        auth,
        secret,
        ...(cache === undefined ? {} : { cache }),
        ...(cookie === undefined ? {} : { cookie }),
        ...(getIp === undefined ? {} : { getIp }),
    });

    if (social === undefined) {
        return { ...auth, ...adapter };
    }

    const resolvedCookie = resolveHttpCookie(cookie);

    return {
        ...auth,
        ...adapter,
        social: createExpressSocial({
            config: social,
            cookie: resolvedCookie.options,
            db: requireSocialDb(db),
            sessionCookieNames: Object.values(resolvedCookie.names),
            secret,
        }),
    };
};

export const createExpressAuth = createExpressAuthImpl as CreateExpressAuth;
