import type { Request, RequestHandler, Response } from "express";
import type { AuthAccount } from "../../session/types.js";
import type {
    SocialAuthenticated,
    SocialConfig,
    SocialDbAdapter,
    SocialIdentity,
} from "../../social/types.js";
import { createHttpSocial } from "../utils/social.js";
import type { HttpCookieOptions } from "../utils/types.js";

type ExpressSocialDeps<TAccount extends AuthAccount, TData> = {
    config: SocialConfig<TData>;
    cookie: HttpCookieOptions;
    db: SocialDbAdapter<TAccount>;
    sessionCookieNames: readonly string[];
    secret: string;
};

type ExpressSocialInput = {
    request: Request;
    response: Response;
};

type CompleteRegistrationInput<TData> = ExpressSocialInput & {
    data: TData;
};

export type ExpressSocialLocals<TAccount extends AuthAccount = AuthAccount> = {
    social: SocialAuthenticated<TAccount>;
};

export type ExpressSocial<TAccount extends AuthAccount = AuthAccount, TData = undefined> = {
    completeRegistration(
        input: CompleteRegistrationInput<TData>,
    ): Promise<SocialAuthenticated<TAccount>>;
    getRegistration(input: ExpressSocialInput): SocialIdentity;
    handle: RequestHandler;
};

const getParam = ({ name, request }: { name: string; request: Request }): string | undefined => {
    const value = request.params[name];

    return typeof value === "string" ? value : value?.[0];
};

const getQuery = ({ name, request }: { name: string; request: Request }): string | undefined => {
    const value = request.query[name];

    return typeof value === "string" ? value : undefined;
};

export const createExpressSocial = <TAccount extends AuthAccount, TData>({
    config,
    cookie,
    db,
    sessionCookieNames,
    secret,
}: ExpressSocialDeps<TAccount, TData>): ExpressSocial<TAccount, TData> => {
    const social = createHttpSocial<Request, Response, TAccount, TData>({
        appendSetCookie: ({ response, value }) => {
            response.append("Set-Cookie", value);
        },
        config,
        cookie,
        db,
        getHeader: ({ name, request }) => request.get(name),
        getParam,
        getQuery,
        sessionCookieNames,
        secret,
    });

    const handle: RequestHandler = async (request, response, next) => {
        const result = await social.handle({ request, response });

        if (result.type === "not_found") {
            response.sendStatus(404);
            return;
        }

        if (result.type === "redirect") {
            response.redirect(result.url);
            return;
        }

        const locals = response.locals as ExpressSocialLocals<TAccount>;
        locals.social = result.value;
        next();
    };

    return {
        completeRegistration: (input) => social.completeRegistration(input),
        getRegistration: (input) => social.getRegistration(input),
        handle,
    };
};
