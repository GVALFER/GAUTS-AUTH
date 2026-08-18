import { createError, isAuthError } from "../errors.js";
import { isRecord } from "../session/guards.js";
import type { SocialIdentity, SocialProviderId } from "../social/types.js";

export type ProviderConfig = {
    callbackUrl: string;
    clientId: string;
    clientSecret: string;
};

type RequestJsonInput = {
    init?: RequestInit;
    provider: SocialProviderId;
    url: string;
};

type IdentityInput = {
    avatarUrl?: unknown;
    email: unknown;
    emailVerified: boolean;
    name: unknown;
    provider: SocialProviderId;
    providerId: unknown;
    username?: unknown;
};

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

type RequireAccessTokenInput = {
    provider: SocialProviderId;
    value: unknown;
};

export const requireProviderConfig = ({
    callbackUrl,
    clientId,
    clientSecret,
}: ProviderConfig): ProviderConfig => {
    if (!clientId.trim() || !clientSecret.trim()) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Social provider credentials are required.",
        });
    }

    try {
        const url = new URL(callbackUrl);

        if (
            (url.protocol !== "https:" && url.protocol !== "http:") ||
            url.username ||
            url.password
        ) {
            throw new Error("invalid URL");
        }
    } catch {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Social provider callbackUrl must be an absolute HTTP URL.",
        });
    }

    return { callbackUrl, clientId, clientSecret };
};

export const requestJson = async ({ init, provider, url }: RequestJsonInput): Promise<unknown> => {
    try {
        const response = await fetch(url, init);
        const value = await response.json();

        if (!response.ok || (isRecord(value) && typeof value.error === "string")) {
            throw createError({
                code: "SOCIAL_PROVIDER_ERROR",
                message: `${provider} authentication failed.`,
            });
        }

        return value;
    } catch (error) {
        if (isAuthError(error)) {
            throw error;
        }

        throw createError({
            cause: error,
            code: "SOCIAL_PROVIDER_ERROR",
            message: `${provider} authentication failed.`,
        });
    }
};

export const requireAccessToken = ({ provider, value }: RequireAccessTokenInput): string => {
    if (!isRecord(value) || typeof value.access_token !== "string" || !value.access_token) {
        throw createError({
            code: "SOCIAL_PROVIDER_ERROR",
            message: `${provider} did not return an access token.`,
        });
    }

    return value.access_token;
};

export const createIdentity = ({
    avatarUrl,
    email,
    emailVerified,
    name,
    provider,
    providerId,
    username,
}: IdentityInput): SocialIdentity => {
    const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";

    const normalizedId =
        typeof providerId === "string" || typeof providerId === "number"
            ? String(providerId).trim()
            : "";

    const normalizedUsername =
        typeof username === "string" && username.trim() ? username.trim() : null;

    const normalizedName =
        typeof name === "string" && name.trim()
            ? name.trim()
            : (normalizedUsername ?? normalizedEmail.split("@")[0] ?? "");

    if (
        !emailVerified ||
        !emailPattern.test(normalizedEmail) ||
        !normalizedId ||
        !normalizedName
    ) {
        throw createError({
            code: "SOCIAL_EMAIL_INVALID",
            message: `${provider} must return a verified email address.`,
        });
    }

    return {
        avatarUrl: typeof avatarUrl === "string" && avatarUrl.trim() ? avatarUrl.trim() : null,
        email: normalizedEmail,
        name: normalizedName,
        provider,
        providerId: normalizedId,
        username: normalizedUsername,
    };
};

export const createForm = (values: Record<string, string>): URLSearchParams => {
    return new URLSearchParams(values);
};
