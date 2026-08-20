import type { Context, Env, MiddlewareHandler } from "hono";
import { createAuth, type Auth, type AuthDeps } from "../../auth.js";
import type { SessionCookieNames } from "../../session/cookie.js";
import type { SessionCacheConfig } from "../../session/state.js";
import type { AuthAccount, DbAdapter, ResolvedSession, Session } from "../../session/types.js";
import type { SocialConfig, SocialDbAdapter } from "../../social/types.js";
import { resolveHttpCookie } from "../utils/httpCookie.js";
import { requireSocialDb } from "../utils/social.js";
import { createHttpSession } from "../utils/session.js";
import type { HttpCookieConfig } from "../utils/types.js";
import { createHonoSocial, type HonoSocial } from "./social.js";

export type { SessionCacheConfig } from "../../session/state.js";
export type { HonoSocial, HonoSocialEnv, HonoSocialVariables } from "./social.js";

export type HonoAuthVariables<TAccount extends AuthAccount = AuthAccount> = {
    account: TAccount;
    session: Session;
    user: TAccount["user"];
};

export type HonoAuthEnv<TAccount extends AuthAccount = AuthAccount> = Env & {
    Variables: HonoAuthVariables<TAccount>;
};

export type HonoCookieConfig = HttpCookieConfig;

export type HonoGetIp = (
    c: Context,
) => Promise<string | null | undefined> | string | null | undefined;

export type HonoAdapterConfig<TAccount extends AuthAccount = AuthAccount> = {
    auth: Auth<TAccount>;
    cache?: SessionCacheConfig;
    cookie?: HonoCookieConfig;
    getIp?: HonoGetIp;
    secret: string;
};

type HonoAuthBase<TAccount extends AuthAccount> = Omit<AuthDeps<TAccount>, "db"> & {
    cache?: SessionCacheConfig;
    cookie?: HonoCookieConfig;
    db: DbAdapter<TAccount>;
    getIp?: HonoGetIp;
    secret: string;
};

type HonoSocialOptions<TAccount extends AuthAccount, TData> =
    | {
          db: DbAdapter<TAccount> & SocialDbAdapter<TAccount>;
          social: SocialConfig<TData>;
      }
    | {
          db: DbAdapter<TAccount>;
          social?: undefined;
      };

export type HonoAuthConfig<TAccount extends AuthAccount = AuthAccount, TData = undefined> = Omit<
    HonoAuthBase<TAccount>,
    "db"
> &
    HonoSocialOptions<TAccount, TData>;

type HonoAuthOptions<TAccount extends AuthAccount> = Omit<HonoAuthBase<TAccount>, "db">;

type DbAccount<TDb> = TDb extends DbAdapter<infer TAccount> ? TAccount : never;

type CreateSessionInput = {
    account_id: string;
    context: Context;
    country?: string | null;
};

export type HonoAdapter<TAccount extends AuthAccount = AuthAccount> = {
    clearSession(c: Context): void;
    cookie: Readonly<SessionCookieNames>;
    createSession(input: CreateSessionInput): Promise<Session>;
    getToken(c: Context): string | null;
    renewSession(c: Context): Promise<Session>;
    requireSession: MiddlewareHandler<HonoAuthEnv<TAccount>>;
    resolveSession(c: Context): Promise<ResolvedSession<TAccount>>;
    revokeSession(c: Context): Promise<string[]>;
};

export type HonoAuth<TAccount extends AuthAccount = AuthAccount> = Auth<TAccount> &
    HonoAdapter<TAccount>;

export type HonoSocialAuth<
    TAccount extends AuthAccount = AuthAccount,
    TData = undefined,
> = Auth<TAccount> &
    HonoAdapter<TAccount> & {
        social: HonoSocial<TAccount, TData>;
    };

export const createHonoAdapter = <TAccount extends AuthAccount>({
    auth,
    cache,
    cookie,
    getIp,
    secret,
}: HonoAdapterConfig<TAccount>): HonoAdapter<TAccount> => {
    const session = createHttpSession<Context, Context, TAccount>({
        appendSetCookie: ({ response, value }) => {
            response.header("Set-Cookie", value, { append: true });
        },
        auth,
        secret,
        framework: "Hono",
        getHeader: ({ name, request }) => request.req.header(name),
        getMethod: (request) => request.req.method,
        ...(cache === undefined ? {} : { cache }),
        ...(cookie === undefined ? {} : { cookie }),
        ...(getIp === undefined ? {} : { getIp }),
    });

    const clearSession = (c: Context): void => {
        session.clearSession(c);
    };

    const createSession = ({
        account_id,
        context,
        country,
    }: CreateSessionInput): Promise<Session> => {
        return session.createSession({
            account_id,
            ...(country === undefined ? {} : { country }),
            request: context,
            response: context,
        });
    };

    const getToken = (c: Context): string | null => session.getToken(c);

    const renewSession = (c: Context): Promise<Session> => {
        return session.renewSession({ request: c, response: c });
    };

    const resolveSession = (c: Context): Promise<ResolvedSession<TAccount>> => {
        return session.resolveSession({ request: c, response: c });
    };

    const requireSession: MiddlewareHandler<HonoAuthEnv<TAccount>> = async (c, next) => {
        const value = await resolveSession(c);

        c.set("session", value.session);
        c.set("account", value.account);
        c.set("user", value.account.user);
        await next();
    };

    const revokeSession = (c: Context): Promise<string[]> => {
        return session.revokeSession({ request: c, response: c });
    };

    return {
        clearSession,
        cookie: session.cookie,
        createSession,
        getToken,
        renewSession,
        requireSession,
        resolveSession,
        revokeSession,
    };
};

type CreateHonoAuth = {
    <TDb extends DbAdapter, TData>(
        input: HonoAuthOptions<DbAccount<TDb>> & {
            db: TDb & SocialDbAdapter<DbAccount<TDb>>;
            secret: string;
            social: SocialConfig<TData>;
        },
    ): HonoSocialAuth<DbAccount<TDb>, TData>;
    <TDb extends DbAdapter>(
        input: HonoAuthOptions<DbAccount<TDb>> & {
            db: TDb;
            social?: undefined;
        },
    ): HonoAuth<DbAccount<TDb>>;
};

const createHonoAuthImpl = <TAccount extends AuthAccount, TData = undefined>({
    cache,
    cookie,
    db,
    getIp,
    password,
    secret,
    session,
    social,
}: HonoAuthConfig<TAccount, TData>): HonoAuth<TAccount> | HonoSocialAuth<TAccount, TData> => {
    const auth = createAuth({
        db,
        ...(password === undefined ? {} : { password }),
        ...(session === undefined ? {} : { session }),
    });
    const adapter = createHonoAdapter({
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
        social: createHonoSocial({
            config: social,
            cookie: resolvedCookie.options,
            db: requireSocialDb(db),
            sessionCookieNames: Object.values(resolvedCookie.names),
            secret,
        }),
    };
};

export const createHonoAuth = createHonoAuthImpl as CreateHonoAuth;
