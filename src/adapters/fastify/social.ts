import type { FastifyReply, FastifyRequest } from "fastify";
import type { AuthAccount } from "../../session/types.js";
import type {
    SocialAuthenticated,
    SocialConfig,
    SocialDbAdapter,
    SocialIdentity,
} from "../../social/types.js";
import { createHttpSocial } from "../utils/social.js";
import type { HttpCookieOptions } from "../utils/types.js";

type FastifySocialDeps<TAccount extends AuthAccount, TData> = {
    config: SocialConfig<TData>;
    cookie: HttpCookieOptions;
    db: SocialDbAdapter<TAccount>;
    sessionCookieNames: readonly string[];
    secret: string;
};

type FastifySocialInput = {
    reply: FastifyReply;
    request: FastifyRequest;
};

type CompleteRegistrationInput<TData> = FastifySocialInput & {
    data: TData;
};

export type FastifySocialHandler = (request: FastifyRequest, reply: FastifyReply) => Promise<void>;

export type FastifySocial<TAccount extends AuthAccount = AuthAccount, TData = undefined> = {
    completeRegistration(
        input: CompleteRegistrationInput<TData>,
    ): Promise<SocialAuthenticated<TAccount>>;
    getRegistration(input: FastifySocialInput): SocialIdentity;
    handle: FastifySocialHandler;
};

const getValue = ({ name, value }: { name: string; value: unknown }): string | undefined => {
    if (typeof value !== "object" || value === null) {
        return undefined;
    }

    const field = (value as Record<string, unknown>)[name];
    return typeof field === "string" ? field : undefined;
};

export const createFastifySocial = <TAccount extends AuthAccount, TData>({
    config,
    cookie,
    db,
    sessionCookieNames,
    secret,
}: FastifySocialDeps<TAccount, TData>): FastifySocial<TAccount, TData> => {
    const social = createHttpSocial<FastifyRequest, FastifyReply, TAccount, TData>({
        appendSetCookie: ({ response, value }) => {
            response.header("Set-Cookie", value);
        },
        config,
        cookie,
        db,
        getHeader: ({ name, request }) => {
            const value = request.headers[name];
            return Array.isArray(value) ? value[0] : value;
        },
        getParam: ({ name, request }) => getValue({ name, value: request.params }),
        getQuery: ({ name, request }) => getValue({ name, value: request.query }),
        sessionCookieNames,
        secret,
    });

    const handle: FastifySocialHandler = async (request, reply) => {
        const result = await social.handle({ request, response: reply });

        if (result.type === "not_found") {
            reply.callNotFound();
            return;
        }

        if (result.type === "redirect") {
            reply.redirect(result.url);
            return;
        }

        request.setDecorator("social", result.value);
    };

    return {
        completeRegistration: ({ data, reply, request }) => {
            return social.completeRegistration({ data, request, response: reply });
        },
        getRegistration: ({ reply, request }) => {
            return social.getRegistration({ request, response: reply });
        },
        handle,
    };
};
