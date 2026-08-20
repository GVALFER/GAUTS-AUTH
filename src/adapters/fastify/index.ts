import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createAuth, type Auth, type AuthDeps } from "../../auth.js";
import type { SessionCookieNames } from "../../session/cookie.js";
import type { SessionCacheConfig } from "../../session/state.js";
import type { AuthAccount, DbAdapter, ResolvedSession, Session } from "../../session/types.js";
import type { SocialConfig, SocialDbAdapter } from "../../social/types.js";
import { resolveHttpCookie } from "../utils/httpCookie.js";
import { requireSocialDb } from "../utils/social.js";
import { createHttpSession } from "../utils/session.js";
import type { HttpCookieConfig } from "../utils/types.js";
import { createFastifySocial, type FastifySocial } from "./social.js";

export type { SessionCacheConfig } from "../../session/state.js";
export type { FastifySocial, FastifySocialHandler } from "./social.js";

export type FastifyAuthContext<TAccount extends AuthAccount = AuthAccount> = {
    account: TAccount;
    session: Session;
    user: TAccount["user"];
};

export type FastifyCookieConfig = HttpCookieConfig;

export type FastifyGetIp = (
    request: FastifyRequest,
) => Promise<string | null | undefined> | string | null | undefined;

export type FastifyAdapterConfig<TAccount extends AuthAccount = AuthAccount> = {
    auth: Auth<TAccount>;
    cache?: SessionCacheConfig;
    cookie?: FastifyCookieConfig;
    getIp?: FastifyGetIp;
    secret: string;
};

type FastifyAuthBase<TAccount extends AuthAccount> = Omit<AuthDeps<TAccount>, "db"> & {
    cache?: SessionCacheConfig;
    cookie?: FastifyCookieConfig;
    db: DbAdapter<TAccount>;
    getIp?: FastifyGetIp;
    secret: string;
};

type FastifySocialOptions<TAccount extends AuthAccount, TData> =
    | {
          db: DbAdapter<TAccount> & SocialDbAdapter<TAccount>;
          social: SocialConfig<TData>;
      }
    | {
          db: DbAdapter<TAccount>;
          social?: undefined;
      };

export type FastifyAuthConfig<TAccount extends AuthAccount = AuthAccount, TData = undefined> = Omit<
    FastifyAuthBase<TAccount>,
    "db"
> &
    FastifySocialOptions<TAccount, TData>;

type FastifyAuthOptions<TAccount extends AuthAccount> = Omit<FastifyAuthBase<TAccount>, "db">;

type DbAccount<TDb> = TDb extends DbAdapter<infer TAccount> ? TAccount : never;

type FastifyRequestInput = {
    reply: FastifyReply;
    request: FastifyRequest;
};

type CreateSessionInput = FastifyRequestInput & {
    account_id: string;
    country?: string | null;
};

export type FastifySessionHandler = (request: FastifyRequest, reply: FastifyReply) => Promise<void>;

export type FastifyAdapter<TAccount extends AuthAccount = AuthAccount> = {
    clearSession(reply: FastifyReply): void;
    cookie: Readonly<SessionCookieNames>;
    createSession(input: CreateSessionInput): Promise<Session>;
    decorate(app: FastifyInstance): void;
    getToken(request: FastifyRequest): string | null;
    renewSession(input: FastifyRequestInput): Promise<Session>;
    requireSession: FastifySessionHandler;
    resolveSession(input: FastifyRequestInput): Promise<ResolvedSession<TAccount>>;
    revokeSession(input: FastifyRequestInput): Promise<string[]>;
};

export type FastifyAuth<TAccount extends AuthAccount = AuthAccount> = Auth<TAccount> &
    FastifyAdapter<TAccount>;

export type FastifySocialAuth<
    TAccount extends AuthAccount = AuthAccount,
    TData = undefined,
> = Auth<TAccount> &
    FastifyAdapter<TAccount> & {
        social: FastifySocial<TAccount, TData>;
    };

const decorateRequest = ({ app, name }: { app: FastifyInstance; name: string }): void => {
    if (!app.hasRequestDecorator(name)) {
        app.decorateRequest(name);
    }
};

export const createFastifyAdapter = <TAccount extends AuthAccount>({
    auth,
    cache,
    cookie,
    getIp,
    secret,
}: FastifyAdapterConfig<TAccount>): FastifyAdapter<TAccount> => {
    const session = createHttpSession<FastifyRequest, FastifyReply, TAccount>({
        appendSetCookie: ({ response, value }) => {
            response.header("Set-Cookie", value);
        },
        auth,
        secret,
        framework: "Fastify",
        getMethod: (request) => request.method,
        getHeader: ({ name, request }) => {
            const value = request.headers[name];
            return Array.isArray(value) ? value[0] : value;
        },
        ...(getIp === undefined ? {} : { getIp }),
        ...(cache === undefined ? {} : { cache }),
        ...(cookie === undefined ? {} : { cookie }),
    });

    const resolveSession = ({
        reply,
        request,
    }: FastifyRequestInput): Promise<ResolvedSession<TAccount>> => {
        return session.resolveSession({ request, response: reply });
    };

    const requireSession: FastifySessionHandler = async (request, reply) => {
        const value = await resolveSession({ reply, request });

        request.setDecorator("session", value.session);
        request.setDecorator("account", value.account);
        request.setDecorator("user", value.account.user);
    };

    const decorate = (app: FastifyInstance): void => {
        decorateRequest({ app, name: "session" });
        decorateRequest({ app, name: "account" });
        decorateRequest({ app, name: "user" });
    };

    return {
        clearSession: (reply) => session.clearSession(reply),
        cookie: session.cookie,
        createSession: ({ account_id, country, reply, request }) => {
            return session.createSession({
                account_id,
                ...(country === undefined ? {} : { country }),
                request,
                response: reply,
            });
        },
        decorate,
        getToken: (request) => session.getToken(request),
        renewSession: ({ reply, request }) => {
            return session.renewSession({ request, response: reply });
        },
        requireSession,
        resolveSession,
        revokeSession: ({ reply, request }) => {
            return session.revokeSession({ request, response: reply });
        },
    };
};

type CreateFastifyAuth = {
    <TDb extends DbAdapter, TData>(
        input: FastifyAuthOptions<DbAccount<TDb>> & {
            db: TDb & SocialDbAdapter<DbAccount<TDb>>;
            secret: string;
            social: SocialConfig<TData>;
        },
    ): FastifySocialAuth<DbAccount<TDb>, TData>;
    <TDb extends DbAdapter>(
        input: FastifyAuthOptions<DbAccount<TDb>> & {
            db: TDb;
            social?: undefined;
        },
    ): FastifyAuth<DbAccount<TDb>>;
};

const createFastifyAuthImpl = <TAccount extends AuthAccount, TData = undefined>({
    cache,
    cookie,
    db,
    getIp,
    password,
    secret,
    session,
    social,
}: FastifyAuthConfig<TAccount, TData>):
    FastifyAuth<TAccount> | FastifySocialAuth<TAccount, TData> => {
    const auth = createAuth({
        db,
        ...(password === undefined ? {} : { password }),
        ...(session === undefined ? {} : { session }),
    });
    const adapter = createFastifyAdapter({
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
    const socialAdapter = createFastifySocial({
        config: social,
        cookie: resolvedCookie.options,
        db: requireSocialDb(db),
        sessionCookieNames: Object.values(resolvedCookie.names),
        secret,
    });

    return {
        ...auth,
        ...adapter,
        decorate: (app) => {
            adapter.decorate(app);
            decorateRequest({ app, name: "social" });
        },
        social: socialAdapter,
    };
};

export const createFastifyAuth = createFastifyAuthImpl as CreateFastifyAuth;
