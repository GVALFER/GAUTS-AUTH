import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createError } from "../errors.js";
import { isRecord } from "../session/guards.js";
import type { SocialIdentity, SocialIntent, SocialNavigation, SocialProviderId } from "./types.js";

type OAuthPayload = {
    exp: number;
    intent: SocialIntent;
    kind: "oauth";
    provider: SocialProviderId;
    state: string;
    verifier: string;
} & SocialNavigation;

type RegistrationPayload = {
    exp: number;
    identity: SocialIdentity;
    kind: "registration";
} & SocialNavigation;

type CreateOAuthStateInput = {
    intent: SocialIntent;
    navigation: SocialNavigation;
    now?: () => Date;
    provider: SocialProviderId;
    secret: string;
};

type ResolveOAuthStateInput = {
    now?: () => Date;
    provider: SocialProviderId;
    secret: string;
    state: string | null | undefined;
    value: string | null | undefined;
};

type CreateRegistrationStateInput = {
    identity: SocialIdentity;
    navigation: SocialNavigation;
    now?: () => Date;
    secret: string;
};

type ResolveRegistrationStateInput = {
    now?: () => Date;
    secret: string;
    value: string | null | undefined;
};

type StoredState<T> = {
    expires_at: Date;
    value: string;
} & T;

type ParsePayloadInput = {
    secret: string;
    value: string | null | undefined;
};

const SOCIAL_CONTEXT = "auth/social";
const SOCIAL_TTL = 10 * 60;
const MIN_SECRET_BYTES = 32;
const signaturePattern = /^[A-Za-z0-9_-]{43}$/;
const tokenPattern = /^[A-Za-z0-9_-]{43}$/;

export const validateSocialSecret = (secret: string): void => {
    if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < MIN_SECRET_BYTES) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Authentication secret must contain at least 32 bytes.",
        });
    }
};

const getSignature = ({ body, secret }: { body: string; secret: string }): string => {
    return createHmac("sha256", secret)
        .update(SOCIAL_CONTEXT)
        .update("\0")
        .update(body)
        .digest("base64url");
};

const signPayload = ({ payload, secret }: { payload: object; secret: string }): string => {
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    return `${body}.${getSignature({ body, secret })}`;
};

const parsePayload = ({ secret, value }: ParsePayloadInput): unknown => {
    const [body, signature, extra] = value?.trim().split(".") ?? [];

    if (!body || !signature || extra !== undefined || !signaturePattern.test(signature)) {
        return null;
    }

    const expected = Buffer.from(getSignature({ body, secret }), "ascii");
    const received = Buffer.from(signature, "ascii");

    if (expected.byteLength !== received.byteLength || !timingSafeEqual(expected, received)) {
        return null;
    }

    try {
        return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as unknown;
    } catch {
        return null;
    }
};

const isProvider = (value: unknown): value is SocialProviderId => {
    return value === "github" || value === "google" || value === "x";
};

const isIntent = (value: unknown): value is SocialIntent => {
    return value === "login" || value === "register";
};

const isNavigation = (value: unknown): value is SocialNavigation => {
    return (
        isRecord(value) &&
        typeof value.errorTo === "string" &&
        (typeof value.registerTo === "string" || value.registerTo === null) &&
        typeof value.returnTo === "string"
    );
};

const isIdentity = (value: unknown): value is SocialIdentity => {
    return (
        isRecord(value) &&
        (typeof value.avatarUrl === "string" || value.avatarUrl === null) &&
        typeof value.email === "string" &&
        typeof value.name === "string" &&
        isProvider(value.provider) &&
        typeof value.providerId === "string" &&
        (typeof value.username === "string" || value.username === null)
    );
};

const isOAuthPayload = (value: unknown): value is OAuthPayload => {
    return (
        isRecord(value) &&
        typeof value.exp === "number" &&
        Number.isSafeInteger(value.exp) &&
        isIntent(value.intent) &&
        value.kind === "oauth" &&
        isProvider(value.provider) &&
        typeof value.state === "string" &&
        tokenPattern.test(value.state) &&
        typeof value.verifier === "string" &&
        tokenPattern.test(value.verifier) &&
        isNavigation(value)
    );
};

const isRegistrationPayload = (value: unknown): value is RegistrationPayload => {
    return (
        isRecord(value) &&
        typeof value.exp === "number" &&
        Number.isSafeInteger(value.exp) &&
        value.kind === "registration" &&
        isIdentity(value.identity) &&
        isNavigation(value)
    );
};

const matchesState = ({ expected, received }: { expected: string; received: string }): boolean => {
    const left = Buffer.from(expected, "ascii");
    const right = Buffer.from(received, "ascii");
    return left.byteLength === right.byteLength && timingSafeEqual(left, right);
};

export const createOAuthState = ({
    intent,
    navigation,
    now = () => new Date(),
    provider,
    secret,
}: CreateOAuthStateInput): StoredState<{
    codeChallenge: string;
    state: string;
}> => {
    validateSocialSecret(secret);

    const current = now();
    const expires_at = new Date(current.getTime() + SOCIAL_TTL * 1000);
    const state = randomBytes(32).toString("base64url");
    const verifier = randomBytes(32).toString("base64url");
    const payload: OAuthPayload = {
        exp: expires_at.getTime(),
        intent,
        kind: "oauth",
        ...navigation,
        provider,
        state,
        verifier,
    };

    return {
        codeChallenge: createHash("sha256").update(verifier, "ascii").digest("base64url"),
        expires_at,
        state,
        value: signPayload({ payload, secret }),
    };
};

export const resolveOAuthState = ({
    now = () => new Date(),
    provider,
    secret,
    state,
    value,
}: ResolveOAuthStateInput): Pick<
    OAuthPayload,
    "errorTo" | "intent" | "registerTo" | "returnTo" | "verifier"
> | null => {
    validateSocialSecret(secret);

    if (!state || !tokenPattern.test(state)) {
        return null;
    }

    const payload = parsePayload({ secret, value });

    if (
        !isOAuthPayload(payload) ||
        payload.exp <= now().getTime() ||
        payload.provider !== provider ||
        !matchesState({ expected: payload.state, received: state })
    ) {
        return null;
    }

    return {
        errorTo: payload.errorTo,
        intent: payload.intent,
        registerTo: payload.registerTo,
        returnTo: payload.returnTo,
        verifier: payload.verifier,
    };
};

export const createRegistrationState = ({
    identity,
    navigation,
    now = () => new Date(),
    secret,
}: CreateRegistrationStateInput): StoredState<object> => {
    validateSocialSecret(secret);

    const expires_at = new Date(now().getTime() + SOCIAL_TTL * 1000);
    const payload: RegistrationPayload = {
        exp: expires_at.getTime(),
        identity,
        kind: "registration",
        ...navigation,
    };

    return {
        expires_at,
        value: signPayload({ payload, secret }),
    };
};

export const resolveRegistrationState = ({
    now = () => new Date(),
    secret,
    value,
}: ResolveRegistrationStateInput): {
    identity: SocialIdentity;
    navigation: SocialNavigation;
} | null => {
    validateSocialSecret(secret);
    const payload = parsePayload({ secret, value });

    return isRegistrationPayload(payload) && payload.exp > now().getTime()
        ? {
              identity: payload.identity,
              navigation: {
                  errorTo: payload.errorTo,
                  registerTo: payload.registerTo,
                  returnTo: payload.returnTo,
              },
          }
        : null;
};
