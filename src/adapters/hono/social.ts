import type { Context, Env, MiddlewareHandler } from "hono";
import type { AuthAccount } from "../../session/types.js";
import type {
    SocialAuthenticated,
    SocialConfig,
    SocialDbAdapter,
    SocialIdentity,
} from "../../social/types.js";
import { createHttpSocial } from "../utils/social.js";
import type { HttpCookieOptions } from "../utils/types.js";

type HonoSocialDeps<TAccount extends AuthAccount, TData> = {
    config: SocialConfig<TData>;
    cookie: HttpCookieOptions;
    db: SocialDbAdapter<TAccount>;
    sessionCookieNames: readonly string[];
    secret: string;
};

type CompleteRegistrationInput<TData> = {
    context: Context;
    data: TData;
};

export type HonoSocialVariables<TAccount extends AuthAccount = AuthAccount> = {
    social: SocialAuthenticated<TAccount>;
};

export type HonoSocialEnv<TAccount extends AuthAccount = AuthAccount> = Env & {
    Variables: HonoSocialVariables<TAccount>;
};

export type HonoSocial<TAccount extends AuthAccount = AuthAccount, TData = undefined> = {
    completeRegistration(
        input: CompleteRegistrationInput<TData>,
    ): Promise<SocialAuthenticated<TAccount>>;
    getRegistration(c: Context): SocialIdentity;
    handle: MiddlewareHandler<HonoSocialEnv<TAccount>>;
};

export const createHonoSocial = <TAccount extends AuthAccount, TData>({
    config,
    cookie,
    db,
    sessionCookieNames,
    secret,
}: HonoSocialDeps<TAccount, TData>): HonoSocial<TAccount, TData> => {
    const social = createHttpSocial<Context, Context, TAccount, TData>({
        appendSetCookie: ({ response, value }) => {
            response.header("Set-Cookie", value, { append: true });
        },
        config,
        cookie,
        db,
        getHeader: ({ name, request }) => request.req.header(name),
        getParam: ({ name, request }) => request.req.param(name),
        getQuery: ({ name, request }) => request.req.query(name),
        sessionCookieNames,
        secret,
    });

    const handle: MiddlewareHandler<HonoSocialEnv<TAccount>> = async (c, next) => {
        const result = await social.handle({ request: c, response: c });

        if (result.type === "not_found") {
            return c.notFound();
        }

        if (result.type === "redirect") {
            return c.redirect(result.url);
        }

        c.set("social", result.value);
        await next();
    };

    const getRegistration = (c: Context): SocialIdentity => {
        return social.getRegistration({ request: c, response: c });
    };

    const completeRegistration = ({
        context,
        data,
    }: CompleteRegistrationInput<TData>): Promise<SocialAuthenticated<TAccount>> => {
        return social.completeRegistration({
            data,
            request: context,
            response: context,
        });
    };

    return {
        completeRegistration,
        getRegistration,
        handle,
    };
};
