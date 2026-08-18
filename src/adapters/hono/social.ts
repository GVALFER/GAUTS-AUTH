import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createError, isAuthError } from "../../errors.js";
import { resolveSocialConfig } from "../../social/config.js";
import { createSocialService } from "../../social/service.js";
import type { AuthAccount, Session } from "../../session/types.js";
import {
    createOAuthState,
    createRegistrationState,
    resolveOAuthState,
    resolveRegistrationState,
    validateSocialSecret,
} from "../../social/state.js";
import type {
    SocialConfig,
    SocialDbAdapter,
    SocialIdentity,
    SocialIntent,
    SocialProvider,
    SocialProviderId,
} from "../../social/types.js";

type CookieOptions = {
    domain?: string;
    httpOnly: true;
    path: string;
    sameSite: "Strict" | "Lax" | "None";
    secure: boolean;
};

type CreateSessionInput = {
    account_id: string;
    context: Context;
};

type HonoSocialDeps<TAccount extends AuthAccount, TData> = {
    config: SocialConfig<TData>;
    cookie: CookieOptions;
    createSession: (input: CreateSessionInput) => Promise<Session>;
    db: SocialDbAdapter<TAccount>;
    sessionCookieNames: readonly string[];
    secret: string;
};

type CompleteRegistrationInput<TData> = {
    context: Context;
    data: TData;
};

export type HonoSocial<TData = undefined> = {
    completeRegistration(input: CompleteRegistrationInput<TData>): Promise<Session>;
    getRegistration(c: Context): SocialIdentity;
    handle: (c: Context) => Promise<Response>;
};

type SetSocialInput = {
    context: Context;
    expiresAt: Date;
    value: string;
};

type FinishInput = {
    account_id: string;
    context: Context;
};

const SOCIAL_ERROR_CODES = new Set([
    "SOCIAL_ACCOUNT_INVALID",
    "SOCIAL_ACCOUNT_NOT_FOUND",
    "SOCIAL_EMAIL_INVALID",
    "SOCIAL_PROVIDER_ERROR",
    "SOCIAL_REGISTRATION_INVALID",
    "SOCIAL_STATE_INVALID",
]);

const getProviderId = (value: string | undefined): SocialProviderId | null => {
    return value === "github" || value === "google" || value === "x" ? value : null;
};

const getIntent = (value: string | undefined): SocialIntent => {
    if (value === undefined || value === "login") {
        return "login";
    }

    if (value === "register") {
        return value;
    }

    throw createError({
        code: "SOCIAL_STATE_INVALID",
        message: "Social authentication intent is invalid.",
    });
};

const getErrorUrl = ({ code, url }: { code: string; url: string }): string => {
    const target = new URL(url);
    target.searchParams.set("error", code);
    return target.toString();
};

export const createHonoSocial = <TAccount extends AuthAccount, TData>({
    config: input,
    cookie,
    createSession,
    db,
    sessionCookieNames,
    secret,
}: HonoSocialDeps<TAccount, TData>): HonoSocial<TData> => {
    validateSocialSecret(secret);

    if (cookie.sameSite === "Strict") {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Social authentication requires SameSite=Lax or SameSite=None cookies.",
        });
    }

    const config = resolveSocialConfig(input);

    if (sessionCookieNames.includes(config.cookieName)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Social and session cookie names must be unique.",
        });
    }

    if (
        config.cookieName.startsWith("__Host-") &&
        (!cookie.secure || cookie.path !== "/" || cookie.domain)
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "__Host- cookies require secure=true, path=/, and no domain.",
        });
    }

    if (config.cookieName.startsWith("__Secure-") && !cookie.secure) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "__Secure- cookies require secure=true.",
        });
    }

    const service = createSocialService({
        db,
        registration: config.registration,
    });

    const clearSocial = (c: Context): void => {
        deleteCookie(c, config.cookieName, cookie);
    };

    const setSocial = ({ context, expiresAt, value }: SetSocialInput): void => {
        setCookie(context, config.cookieName, value, {
            ...cookie,
            expires: expiresAt,
        });
    };

    const requireProvider = (value: string | undefined): SocialProvider => {
        const id = getProviderId(value);
        const provider = id ? config.providers.get(id) : undefined;

        if (!provider) {
            throw createError({
                code: "SOCIAL_PROVIDER_ERROR",
                message: "Social provider is not configured.",
            });
        }

        return provider;
    };

    const fail = (c: Context, error: unknown): Response => {
        if (!isAuthError(error) || !SOCIAL_ERROR_CODES.has(error.code)) {
            throw error;
        }

        clearSocial(c);
        return c.redirect(getErrorUrl({ code: error.code, url: config.errorUrl }));
    };

    const finish = async ({ account_id, context }: FinishInput): Promise<Response> => {
        await createSession({ account_id, context });
        clearSocial(context);
        return context.redirect(config.successUrl);
    };

    const handle = async (c: Context): Promise<Response> => {
        const action = c.req.param("action");

        if (action !== "start" && action !== "callback") {
            return c.notFound();
        }

        try {
            const provider = requireProvider(c.req.param("provider"));

            if (action === "start") {
                const created = createOAuthState({
                    intent: getIntent(c.req.query("intent")),
                    provider: provider.id,
                    secret,
                });

                setSocial({
                    context: c,
                    expiresAt: created.expires_at,
                    value: created.value,
                });
                return c.redirect(
                    provider.getAuthorizationUrl({
                        codeChallenge: created.codeChallenge,
                        state: created.state,
                    }),
                );
            }

            const code = c.req.query("code");
            const state = c.req.query("state");
            const providerError = c.req.query("error");

            if (providerError || !code) {
                throw createError({
                    code: "SOCIAL_PROVIDER_ERROR",
                    message: "Social provider denied authentication.",
                });
            }

            const stored = resolveOAuthState({
                provider: provider.id,
                secret,
                state,
                value: getCookie(c, config.cookieName),
            });

            if (!stored) {
                throw createError({
                    code: "SOCIAL_STATE_INVALID",
                    message: "Social authentication state is invalid or expired.",
                });
            }

            const identity = await provider.getIdentity({
                code,
                codeVerifier: stored.verifier,
            });

            const account = await service.find(identity);

            if (account) {
                return await finish({ account_id: account.id, context: c });
            }

            if (stored.intent !== "register" || !config.registration) {
                throw createError({
                    code: "SOCIAL_ACCOUNT_NOT_FOUND",
                    message: "Social account does not exist.",
                });
            }

            if (config.registration.registerUrl) {
                const pending = createRegistrationState({ identity, secret });
                setSocial({
                    context: c,
                    expiresAt: pending.expires_at,
                    value: pending.value,
                });
                return c.redirect(config.registration.registerUrl);
            }

            const created = await service.register({
                data: undefined as TData,
                identity,
            });
            return await finish({ account_id: created.id, context: c });
        } catch (error) {
            return fail(c, error);
        }
    };

    const getRegistration = (c: Context): SocialIdentity => {
        const identity = resolveRegistrationState({
            secret,
            value: getCookie(c, config.cookieName),
        });

        if (!identity) {
            clearSocial(c);
            throw createError({
                code: "SOCIAL_STATE_INVALID",
                message: "Social registration is invalid or expired.",
            });
        }

        return identity;
    };

    const completeRegistration = async ({
        context,
        data,
    }: CompleteRegistrationInput<TData>): Promise<Session> => {
        const identity = getRegistration(context);
        const account = await service.register({ data, identity });
        const session = await createSession({ account_id: account.id, context });
        clearSocial(context);
        return session;
    };

    return {
        completeRegistration,
        getRegistration,
        handle,
    };
};
