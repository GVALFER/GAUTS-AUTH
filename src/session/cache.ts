import { createHmac, timingSafeEqual } from "node:crypto";

import { matchesClient, normalizeClient, type SessionClientInput } from "../client/index.js";
import type { ResolvedSessionConfig } from "../config.js";
import { createError } from "../errors.js";
import { isAuthAccount, isNullableString, isRecord } from "./guards.js";
import type { AuthAccount, ResolvedSession, Session } from "./types.js";

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

type CreateCacheInput<TAccount extends AuthAccount> = {
    resolved: ResolvedSession<TAccount>;
    token: string;
};

type SessionCacheValue = {
    expires_at: Date;
    value: string;
};

type StoredSession = {
    client: Session["client"];
    created_at: number;
    exp: number;
    id: string;
    ren: number;
};

type ToSessionInput = {
    account_id: string;
    stored: StoredSession;
};

type CachePayload = {
    acc: AuthAccount;
    exp: number;
    ses: StoredSession;
};

export type SessionCache<TAccount extends AuthAccount = AuthAccount> = {
    create(input: CreateCacheInput<TAccount>): SessionCacheValue;
    resolve(input: CacheInput): ResolvedSession<TAccount> | null;
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
        isRecord(value.client) &&
        isNullableString(value.client.agent) &&
        isNullableString(value.client.ip) &&
        isNullableString(value.client.platform) &&
        typeof value.created_at === "number" &&
        Number.isSafeInteger(value.created_at) &&
        typeof value.exp === "number" &&
        Number.isSafeInteger(value.exp) &&
        typeof value.id === "string" &&
        typeof value.ren === "number" &&
        Number.isSafeInteger(value.ren)
    );
};

const isCachePayload = (value: unknown): value is CachePayload => {
    return (
        isRecord(value) &&
        isAuthAccount(value.acc) &&
        typeof value.exp === "number" &&
        Number.isSafeInteger(value.exp) &&
        isStoredSession(value.ses)
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

const toSession = ({ account_id, stored }: ToSessionInput): Session => ({
    account_id,
    client: stored.client,
    created_at: new Date(stored.created_at),
    expires_at: new Date(stored.exp),
    id: stored.id,
    renew_at: new Date(stored.ren),
});

const toStoredSession = (session: Session): StoredSession => ({
    client: session.client,
    created_at: session.created_at.getTime(),
    exp: session.expires_at.getTime(),
    id: session.id,
    ren: session.renew_at.getTime(),
});

export const createSessionCache = <TAccount extends AuthAccount>({
    config,
    now = () => new Date(),
    secret,
    session: sessionConfig,
}: SessionCacheDeps): SessionCache<TAccount> => {
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
            const max_expires_at =
                resolved.session.created_at.getTime() + sessionConfig.maxLifetime * 1000;
            const expires_at = new Date(
                Math.min(
                    now().getTime() + config.ttl * 1000,
                    resolved.session.expires_at.getTime(),
                    max_expires_at,
                ),
            );

            const payload: CachePayload = {
                acc: resolved.account,
                exp: expires_at.getTime(),
                ses: toStoredSession(resolved.session),
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
            const account = payload.acc as TAccount;

            const resolvedSession = toSession({
                account_id: account.id,
                stored: payload.ses,
            });

            const max_expires_at =
                resolvedSession.created_at.getTime() + sessionConfig.maxLifetime * 1000;

            if (
                payload.exp <= current ||
                resolvedSession.expires_at.getTime() <= current ||
                max_expires_at <= current ||
                payload.exp > resolvedSession.expires_at.getTime() ||
                payload.exp > max_expires_at ||
                resolvedSession.expires_at.getTime() > max_expires_at ||
                !matchesClient({
                    current: normalizeClient(client),
                    stored: resolvedSession.client,
                    validation: sessionConfig.validation,
                })
            ) {
                return null;
            }

            return {
                account,
                session: resolvedSession,
            };
        },
    };
};
