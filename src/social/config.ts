import { createError } from "../errors.js";
import { resolveCookieName } from "../session/cookie.js";
import { isRecord } from "../session/guards.js";
import type {
    ResolvedSocialConfig,
    SocialConfig,
    SocialProvider,
    SocialProviderId,
} from "./types.js";

const SOCIAL_DEFAULTS = {
    cookieName: "__soc",
} as const;

const requireUrl = ({ name, value }: { name: string; value: unknown }): string => {
    if (typeof value !== "string") {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${name} must be an absolute HTTP URL.`,
        });
    }

    try {
        const url = new URL(value);

        if (
            (url.protocol !== "https:" && url.protocol !== "http:") ||
            url.username ||
            url.password
        ) {
            throw new Error("invalid URL");
        }

        return url.toString();
    } catch {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${name} must be an absolute HTTP URL.`,
        });
    }
};

const resolveProviders = (input: unknown): ReadonlyMap<SocialProviderId, SocialProvider> => {
    if (!Array.isArray(input) || input.length === 0) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "social.providers must contain at least one provider.",
        });
    }

    const providers = new Map<SocialProviderId, SocialProvider>();
    const values: unknown[] = input;

    for (const value of values) {
        if (
            !isRecord(value) ||
            (value.id !== "google" && value.id !== "github" && value.id !== "x") ||
            typeof value.getAuthorizationUrl !== "function" ||
            typeof value.getIdentity !== "function"
        ) {
            throw createError({
                code: "AUTH_CONFIG_INVALID",
                message: "social.providers contains an invalid provider.",
            });
        }

        const id = value.id;

        if (providers.has(id)) {
            throw createError({
                code: "AUTH_CONFIG_INVALID",
                message: `Social provider ${id} is configured more than once.`,
            });
        }

        requireUrl({ name: `social.providers.${id}.callbackUrl`, value: value.callbackUrl });
        providers.set(id, value as SocialProvider);
    }

    return providers;
};

export const resolveSocialConfig = <TData>(
    input: SocialConfig<TData>,
): ResolvedSocialConfig<TData> => {
    const raw: unknown = input;

    if (!isRecord(raw)) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Social configuration is invalid.",
        });
    }

    const config = raw as SocialConfig<TData>;
    const registration = config.registration ?? null;

    if (
        registration !== null &&
        (typeof registration !== "object" || Array.isArray(registration))
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "social.registration is invalid.",
        });
    }

    if (
        registration?.createAccount !== undefined &&
        typeof registration.createAccount !== "function"
    ) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "social.registration.createAccount must be a function.",
        });
    }

    return {
        cookieName:
            config.cookieName === undefined
                ? SOCIAL_DEFAULTS.cookieName
                : resolveCookieName({ input: config.cookieName, label: "Social" }),
        providers: resolveProviders(config.providers),
        registration:
            registration === null
                ? null
                : {
                      ...(registration.createAccount
                          ? { createAccount: registration.createAccount }
                          : {}),
                  },
    };
};
