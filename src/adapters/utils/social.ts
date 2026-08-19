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
import type { AuthAccount, DbAdapter } from "../../session/types.js";
import { createCookieHeader, getCookieValue } from "./cookie.js";
import type { HttpCookieOptions } from "./types.js";

type HttpSocialConfig<TRequest, TResponse, TAccount extends AuthAccount, TData> = {
    appendSetCookie: (input: { response: TResponse; value: string }) => void;
    config: SocialConfig<TData>;
    cookie: HttpCookieOptions;
    db: SocialDbAdapter<TAccount>;
    getHeader: (input: { name: string; request: TRequest }) => string | undefined;
    getParam: (input: { name: "action" | "provider"; request: TRequest }) => string | undefined;
    getQuery: (input: { name: string; request: TRequest }) => string | undefined;
    sessionCookieNames: readonly string[];
    secret: string;
};

type HttpSocialInput<TRequest, TResponse> = {
    request: TRequest;
    response: TResponse;
};

type CompleteRegistrationInput<TRequest, TResponse, TData> = HttpSocialInput<
    TRequest,
    TResponse
> & {
    data: TData;
};

type AuthenticateInput<TRequest, TResponse> = HttpSocialInput<TRequest, TResponse> & {
    intent: SocialIntent;
    navigation: SocialNavigation;
    provider: SocialProvider;
    verifier: string;
};

export type HttpSocialResult<TAccount extends AuthAccount> =
    | {
          type: "authenticated";
          value: SocialAuthenticated<TAccount>;
      }
    | {
          type: "not_found";
      }
    | {
          type: "redirect";
          url: string;
      };

export type HttpSocial<TRequest, TResponse, TAccount extends AuthAccount, TData> = {
    completeRegistration(
        input: CompleteRegistrationInput<TRequest, TResponse, TData>,
    ): Promise<SocialAuthenticated<TAccount>>;
    getRegistration(input: HttpSocialInput<TRequest, TResponse>): SocialIdentity;
    handle(input: HttpSocialInput<TRequest, TResponse>): Promise<HttpSocialResult<TAccount>>;
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

export const requireSocialDb = <TAccount extends AuthAccount>(
    db: DbAdapter<TAccount>,
): DbAdapter<TAccount> & SocialDbAdapter<TAccount> => {
    const socialDb = db as DbAdapter<TAccount> & Partial<SocialDbAdapter<TAccount>>;
    const methods: (keyof SocialDbAdapter<TAccount>)[] = [
        "createAccount",
        "createSocial",
        "findAccount",
        "findEmail",
        "findSocial",
    ];

    if (methods.some((method) => typeof socialDb[method] !== "function")) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "DB adapter does not support social authentication.",
        });
    }

    return socialDb as DbAdapter<TAccount> & SocialDbAdapter<TAccount>;
};

export const createHttpSocial = <TRequest, TResponse, TAccount extends AuthAccount, TData>({
    appendSetCookie,
    config: input,
    cookie,
    db,
    getHeader,
    getParam,
    getQuery,
    sessionCookieNames,
    secret,
}: HttpSocialConfig<TRequest, TResponse, TAccount, TData>): HttpSocial<
    TRequest,
    TResponse,
    TAccount,
    TData
> => {
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

    const getCookie = (request: TRequest): string | undefined => {
        const header = getHeader({ name: "cookie", request });

        return getCookieValue({
            ...(header === undefined ? {} : { header }),
            name: config.cookieName,
        });
    };

    const setSocial = ({
        expires,
        response,
        value,
    }: {
        expires: Date;
        response: TResponse;
        value: string;
    }): void => {
        appendSetCookie({
            response,
            value: createCookieHeader({
                expires,
                name: config.cookieName,
                options: cookie,
                value,
            }),
        });
    };

    const clearSocial = (response: TResponse): void => {
        appendSetCookie({
            response,
            value: createCookieHeader({
                expires: new Date(0),
                maxAge: 0,
                name: config.cookieName,
                options: cookie,
                value: "",
            }),
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

    const fail = ({
        error,
        errorTo,
        response,
    }: {
        error: unknown;
        errorTo: string;
        response: TResponse;
    }): HttpSocialResult<TAccount> => {
        if (!isAuthError(error) || !SOCIAL_ERROR_CODES.has(error.code)) {
            throw error;
        }

        clearSocial(response);
        return {
            type: "redirect",
            url: addSocialError({ code: error.code, path: errorTo }),
        };
    };

    const authenticate = async ({
        intent,
        navigation,
        provider,
        request,
        response,
        verifier,
    }: AuthenticateInput<TRequest, TResponse>): Promise<HttpSocialResult<TAccount>> => {
        const code = getQuery({ name: "code", request });
        const providerError = getQuery({ name: "error", request });

        if (providerError || !code) {
            throw createError({
                code: "SOCIAL_PROVIDER_ERROR",
                message: "Social provider denied authentication.",
            });
        }

        const identity = await provider.getIdentity({ code, codeVerifier: verifier });
        const account = await service.find(identity);

        if (account) {
            return {
                type: "authenticated",
                value: {
                    account,
                    identity,
                    registered: false,
                    returnTo: navigation.returnTo,
                },
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
            setSocial({ expires: pending.expires_at, response, value: pending.value });
            return { type: "redirect", url: navigation.registerTo };
        }

        const created = await service.register({
            data: undefined as TData,
            identity,
        });

        return {
            type: "authenticated",
            value: {
                account: created,
                identity,
                registered: true,
                returnTo: navigation.returnTo,
            },
        };
    };

    const handle = async ({
        request,
        response,
    }: HttpSocialInput<TRequest, TResponse>): Promise<HttpSocialResult<TAccount>> => {
        const action = getParam({ name: "action", request });

        if (action !== "start" && action !== "callback") {
            return { type: "not_found" };
        }

        const provider = requireProvider(getParam({ name: "provider", request }));

        if (action === "start") {
            const navigation = resolveSocialNavigation({
                errorTo: getQuery({ name: "errorTo", request }),
                registerTo: getQuery({ name: "registerTo", request }),
                returnTo: getQuery({ name: "returnTo", request }),
            });
            const created = createOAuthState({
                intent: getIntent(getQuery({ name: "intent", request })),
                navigation,
                provider: provider.id,
                secret,
            });

            setSocial({ expires: created.expires_at, response, value: created.value });
            return {
                type: "redirect",
                url: provider.getAuthorizationUrl({
                    codeChallenge: created.codeChallenge,
                    state: created.state,
                }),
            };
        }

        const stored = resolveOAuthState({
            provider: provider.id,
            secret,
            state: getQuery({ name: "state", request }),
            value: getCookie(request),
        });

        if (!stored) {
            clearSocial(response);
            throw createError({
                code: "SOCIAL_STATE_INVALID",
                message: "Social authentication state is invalid or expired.",
            });
        }

        let result;

        try {
            result = await authenticate({
                intent: stored.intent,
                navigation: stored,
                provider,
                request,
                response,
                verifier: stored.verifier,
            });
        } catch (error) {
            return fail({ error, errorTo: stored.errorTo, response });
        }

        if (result.type !== "authenticated") {
            return result;
        }

        clearSocial(response);
        return result;
    };

    const requireRegistration = ({ request, response }: HttpSocialInput<TRequest, TResponse>) => {
        const registration = resolveRegistrationState({
            secret,
            value: getCookie(request),
        });

        if (!registration) {
            clearSocial(response);
            throw createError({
                code: "SOCIAL_STATE_INVALID",
                message: "Social registration is invalid or expired.",
            });
        }

        return registration;
    };

    const getRegistration = (value: HttpSocialInput<TRequest, TResponse>): SocialIdentity => {
        return requireRegistration(value).identity;
    };

    const completeRegistration = async ({
        data,
        request,
        response,
    }: CompleteRegistrationInput<TRequest, TResponse, TData>): Promise<
        SocialAuthenticated<TAccount>
    > => {
        const registration = requireRegistration({ request, response });
        const account = await service.register({ data, identity: registration.identity });

        clearSocial(response);
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
