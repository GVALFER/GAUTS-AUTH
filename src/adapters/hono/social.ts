import type { Context, Env, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createError, isAuthError } from "../../errors.js";
import { resolveSocialConfig } from "../../social/config.js";
import { addSocialError, resolveSocialNavigation } from "../../social/navigation.js";
import { createSocialService } from "../../social/service.js";
import {
    createOAuthState,
    createRegistrationState,
    resolveOAuthState,
    resolveRegistrationState,
    validateSocialSecret,
} from "../../social/state.js";
import type {
    SocialAuthenticated,
    SocialConfig,
    SocialDbAdapter,
    SocialIdentity,
    SocialIntent,
    SocialNavigation,
    SocialProvider,
    SocialProviderId,
} from "../../social/types.js";
import type { AuthAccount } from "../../session/types.js";

type CookieOptions = {
    domain?: string;
    httpOnly: true;
    path: string;
    sameSite: "Strict" | "Lax" | "None";
    secure: boolean;
};

type HonoSocialDeps<TAccount extends AuthAccount, TData> = {
    config: SocialConfig<TData>;
    cookie: CookieOptions;
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

type SetSocialInput = {
    context: Context;
    expiresAt: Date;
    value: string;
};

type FailInput = {
    context: Context;
    error: unknown;
    errorTo: string;
};

type AuthenticateInput = {
    context: Context;
    intent: SocialIntent;
    navigation: SocialNavigation;
    provider: SocialProvider;
    verifier: string;
};

const SOCIAL_ERROR_CODES = new Set([
    "SOCIAL_ACCOUNT_INVALID",
    "SOCIAL_ACCOUNT_NOT_FOUND",
    "SOCIAL_EMAIL_INVALID",
    "SOCIAL_EMAIL_MISMATCH",
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

export const createHonoSocial = <TAccount extends AuthAccount, TData>({
    config: input,
    cookie,
    db,
    sessionCookieNames,
    secret,
}: HonoSocialDeps<TAccount, TData>): HonoSocial<TAccount, TData> => {
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

    const fail = ({ context, error, errorTo }: FailInput): Response => {
        if (!isAuthError(error) || !SOCIAL_ERROR_CODES.has(error.code)) {
            throw error;
        }

        clearSocial(context);
        return context.redirect(addSocialError({ code: error.code, path: errorTo }));
    };

    const authenticate = async ({
        context,
        intent,
        navigation,
        provider,
        verifier,
    }: AuthenticateInput): Promise<SocialAuthenticated<TAccount> | Response> => {
        const code = context.req.query("code");
        const providerError = context.req.query("error");

        if (providerError || !code) {
            throw createError({
                code: "SOCIAL_PROVIDER_ERROR",
                message: "Social provider denied authentication.",
            });
        }

        const identity = await provider.getIdentity({
            code,
            codeVerifier: verifier,
        });
        const account = await service.find(identity);

        if (account) {
            return {
                account,
                identity,
                registered: false,
                returnTo: navigation.returnTo,
            };
        }

        if (intent !== "register" || !config.registration) {
            throw createError({
                code: "SOCIAL_ACCOUNT_NOT_FOUND",
                message: "Social account does not exist.",
            });
        }

        if (navigation.registerTo) {
            if (!config.registration.createAccount) {
                throw createError({
                    code: "SOCIAL_REGISTRATION_INVALID",
                    message: "Custom social registration is not configured.",
                });
            }

            const pending = createRegistrationState({ identity, navigation, secret });
            setSocial({
                context,
                expiresAt: pending.expires_at,
                value: pending.value,
            });
            return context.redirect(navigation.registerTo);
        }

        const created = await service.register({
            data: undefined as TData,
            identity,
        });

        return {
            account: created,
            identity,
            registered: true,
            returnTo: navigation.returnTo,
        };
    };

    const handle: MiddlewareHandler<HonoSocialEnv<TAccount>> = async (c, next) => {
        const action = c.req.param("action");

        if (action !== "start" && action !== "callback") {
            return c.notFound();
        }

        const provider = requireProvider(c.req.param("provider"));

        if (action === "start") {
            const navigation = resolveSocialNavigation({
                errorTo: c.req.query("errorTo"),
                registerTo: c.req.query("registerTo"),
                returnTo: c.req.query("returnTo"),
            });
            const created = createOAuthState({
                intent: getIntent(c.req.query("intent")),
                navigation,
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

        const stored = resolveOAuthState({
            provider: provider.id,
            secret,
            state: c.req.query("state"),
            value: getCookie(c, config.cookieName),
        });

        if (!stored) {
            clearSocial(c);
            throw createError({
                code: "SOCIAL_STATE_INVALID",
                message: "Social authentication state is invalid or expired.",
            });
        }

        let authenticated;

        try {
            authenticated = await authenticate({
                context: c,
                intent: stored.intent,
                navigation: stored,
                provider,
                verifier: stored.verifier,
            });
        } catch (error) {
            return fail({ context: c, error, errorTo: stored.errorTo });
        }

        if (authenticated instanceof Response) {
            return authenticated;
        }

        clearSocial(c);
        c.set("social", authenticated);
        await next();
    };

    const requireRegistration = (c: Context) => {
        const registration = resolveRegistrationState({
            secret,
            value: getCookie(c, config.cookieName),
        });

        if (!registration) {
            clearSocial(c);
            throw createError({
                code: "SOCIAL_STATE_INVALID",
                message: "Social registration is invalid or expired.",
            });
        }

        return registration;
    };

    const getRegistration = (c: Context): SocialIdentity => {
        return requireRegistration(c).identity;
    };

    const completeRegistration = async ({
        context,
        data,
    }: CompleteRegistrationInput<TData>): Promise<SocialAuthenticated<TAccount>> => {
        const registration = requireRegistration(context);
        const account = await service.register({ data, identity: registration.identity });

        clearSocial(context);
        return {
            account,
            identity: registration.identity,
            registered: true,
            returnTo: registration.navigation.returnTo,
        };
    };

    return {
        completeRegistration,
        getRegistration,
        handle,
    };
};
