import { createHmac, timingSafeEqual } from "node:crypto";

import { matchesClient, normalizeClient, type SessionClientInput } from "../client/index.js";
import type { ResolvedSessionConfig } from "../config.js";
import { createError } from "../errors.js";
import { isAuthAccount, isNullableString, isRecord } from "./guards.js";
import type { ResolvedSession, Session } from "./types.js";

export type SessionCacheConfig = {
    ttl: number;
};

type SessionCacheDeps = {
    config: SessionCacheConfig;
    now?: () => Date;
    secret: string;
    session: ResolvedSessionConfig;
};

type CacheInput = {
    client: SessionClientInput;
    token: string;
    value: string | null | undefined;
};

type CreateCacheInput = {
    resolved: ResolvedSession;
    token: string;
};

type SessionCacheValue = {
    expires_at: Date;
    value: string;
};

type StoredSession = Omit<Session, "created_at" | "expires_at" | "renew_at"> & {
    created_at: number;
    expires_at: number;
    renew_at: number;
};

type CachePayload = {
    account: ResolvedSession["account"];
    cache_expires_at: number;
    session: StoredSession;
    version: 1;
};

export type SessionCache = {
    create(input: CreateCacheInput): SessionCacheValue;
    resolve(input: CacheInput): ResolvedSession | null;
};

type MatchesSignature = {
    body: string;
    secret: string;
    signature: string;
    token: string;
};

const signaturePattern = /^[A-Za-z0-9_-]{43}$/;
const CACHE_CONTEXT = "auth/session-cache";
const MIN_SECRET_BYTES = 32;

const getSignature = ({ body, secret, token }: { body: string; secret: string; token: string }) => {
    return createHmac("sha256", secret)
        .update(CACHE_CONTEXT)
        .update("\0")
        .update(token)
        .update("\0")
        .update(body)
        .digest("base64url");
};

const matchesSignature = ({ body, secret, signature, token }: MatchesSignature): boolean => {
    if (!signaturePattern.test(signature)) {
        return false;
    }

    const expected = Buffer.from(getSignature({ body, secret, token }), "ascii");
    const received = Buffer.from(signature, "ascii");

    return expected.byteLength === received.byteLength && timingSafeEqual(expected, received);
};

const isStoredSession = (value: unknown): value is StoredSession => {
    return (
        isRecord(value) &&
        typeof value.account_id === "string" &&
        isRecord(value.client) &&
        isNullableString(value.client.agent) &&
        isNullableString(value.client.ip) &&
        isNullableString(value.client.platform) &&
        typeof value.created_at === "number" &&
        Number.isSafeInteger(value.created_at) &&
        typeof value.expires_at === "number" &&
        Number.isSafeInteger(value.expires_at) &&
        typeof value.id === "string" &&
        typeof value.renew_at === "number" &&
        Number.isSafeInteger(value.renew_at)
    );
};

const isCachePayload = (value: unknown): value is CachePayload => {
    return (
        isRecord(value) &&
        value.version === 1 &&
        isAuthAccount(value.account) &&
        typeof value.cache_expires_at === "number" &&
        Number.isSafeInteger(value.cache_expires_at) &&
        isStoredSession(value.session) &&
        value.session.account_id === value.account.id
    );
};

const parsePayload = (body: string): CachePayload | null => {
    try {
        const value: unknown = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
        return isCachePayload(value) ? value : null;
    } catch {
        return null;
    }
};

const toSession = (stored: StoredSession): Session => ({
    ...stored,
    created_at: new Date(stored.created_at),
    expires_at: new Date(stored.expires_at),
    renew_at: new Date(stored.renew_at),
});

const toStoredSession = (session: Session): StoredSession => ({
    ...session,
    created_at: session.created_at.getTime(),
    expires_at: session.expires_at.getTime(),
    renew_at: session.renew_at.getTime(),
});

export const createSessionCache = ({
    config,
    now = () => new Date(),
    secret,
    session: sessionConfig,
}: SessionCacheDeps): SessionCache => {
    if (!Number.isInteger(config.ttl) || config.ttl < 1 || config.ttl > sessionConfig.ttl) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Session cache TTL must be an integer between 1 and the session TTL.",
        });
    }

    if (Buffer.byteLength(secret, "utf8") < MIN_SECRET_BYTES) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Authentication secret must contain at least 32 bytes.",
        });
    }

    return {
        create: ({ resolved, token }) => {
            const expires_at = new Date(
                Math.min(
                    now().getTime() + config.ttl * 1000,
                    resolved.session.expires_at.getTime(),
                ),
            );

            const payload: CachePayload = {
                account: resolved.account,
                cache_expires_at: expires_at.getTime(),
                session: toStoredSession(resolved.session),
                version: 1,
            };

            const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
            const signature = getSignature({ body, secret, token });

            return {
                expires_at,
                value: `${body}.${signature}`,
            };
        },

        resolve: ({ client, token, value }) => {
            const [body, signature, extra] = value?.trim().split(".") ?? [];

            if (
                !body ||
                !signature ||
                extra !== undefined ||
                !matchesSignature({ body, secret, signature, token })
            ) {
                return null;
            }

            const payload = parsePayload(body);
            if (!payload) {
                return null;
            }

            const current = now().getTime();
            const resolvedSession = toSession(payload.session);

            if (
                payload.cache_expires_at <= current ||
                resolvedSession.expires_at.getTime() <= current ||
                payload.cache_expires_at > resolvedSession.expires_at.getTime() ||
                !matchesClient({
                    current: normalizeClient(client),
                    stored: resolvedSession.client,
                    validation: sessionConfig.validation,
                })
            ) {
                return null;
            }

            return {
                account: payload.account,
                session: resolvedSession,
                user: payload.account.user,
            };
        },
    };
};
