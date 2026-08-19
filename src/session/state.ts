import { createHmac, timingSafeEqual } from "node:crypto";

import { matchesClient, normalizeClient, type SessionClientInput } from "../client/index.js";
import type { ResolvedSessionConfig } from "../config.js";
import { createError } from "../errors.js";
import { isAuthAccount, isNullableString, isRecord } from "./guards.js";
import type { AuthAccount, ResolvedSession, Session } from "./types.js";

export type SessionCacheConfig = {
    ttl: number;
};

type SessionStateDeps = {
    cache?: SessionCacheConfig;
    now?: () => Date;
    secret: string;
    session: ResolvedSessionConfig;
};

type ResolveStateInput = {
    client: SessionClientInput;
    token: string;
    value: string | null | undefined;
};

type CreateStateInput<TAccount extends AuthAccount> = {
    cache?: boolean;
    resolved: ResolvedSession<TAccount>;
    token: string;
};

type SessionStateCookie = {
    expires_at: Date;
    value: string;
};

type StoredSession = {
    client: Session["client"];
    created: number;
    id: string;
};

type StoredData = {
    account: AuthAccount;
    session: StoredSession;
};

type StoredCache = {
    data: StoredData;
    exp: number;
};

type StatePayload = {
    cache: StoredCache | null;
    exp: number;
    renew: number;
};

type StateEnvelope = {
    body: string;
    signature: string;
};

export type SessionStateSchedule = {
    expires_at: Date;
    renew_at: Date;
};

export type ResolvedSessionState<TAccount extends AuthAccount = AuthAccount> =
    SessionStateSchedule & {
        cache: ResolvedSession<TAccount> | null;
    };

export type SessionState<TAccount extends AuthAccount = AuthAccount> = {
    create(input: CreateStateInput<TAccount>): SessionStateCookie;
    resolve(input: ResolveStateInput): ResolvedSessionState<TAccount> | null;
};

type SignatureInput = {
    body: string;
    secret: string;
    token: string;
};

type MatchesSignatureInput = SignatureInput & {
    signature: string;
};

type ToSessionInput = {
    account_id: string;
    payload: StatePayload;
    stored: StoredSession;
};

const signaturePattern = /^[A-Za-z0-9_-]{43}$/;
const SIGNATURE_CONTEXT = "auth/session-context";
const MIN_SECRET_BYTES = 32;

const toSeconds = (value: Date): number => Math.floor(value.getTime() / 1000);
const toDate = (value: number): Date => new Date(value * 1000);

const getSignature = ({ body, secret, token }: SignatureInput) => {
    return createHmac("sha256", secret)
        .update(SIGNATURE_CONTEXT)
        .update("\0")
        .update(token)
        .update("\0")
        .update(body)
        .digest("base64url");
};

const matchesSignature = ({ body, secret, signature, token }: MatchesSignatureInput): boolean => {
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
        typeof value.created === "number" &&
        Number.isSafeInteger(value.created) &&
        typeof value.id === "string"
    );
};

const isStoredData = (value: unknown): value is StoredData => {
    return isRecord(value) && isAuthAccount(value.account) && isStoredSession(value.session);
};

const isStoredCache = (value: unknown): value is StoredCache => {
    return (
        isRecord(value) &&
        isStoredData(value.data) &&
        typeof value.exp === "number" &&
        Number.isSafeInteger(value.exp)
    );
};

const isStatePayload = (value: unknown): value is StatePayload => {
    return (
        isRecord(value) &&
        (value.cache === null || isStoredCache(value.cache)) &&
        typeof value.exp === "number" &&
        Number.isSafeInteger(value.exp) &&
        typeof value.renew === "number" &&
        Number.isSafeInteger(value.renew)
    );
};

const parsePayload = (body: string): StatePayload | null => {
    try {
        const value: unknown = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
        return isStatePayload(value) ? value : null;
    } catch {
        return null;
    }
};

const parseEnvelope = (value?: string | null): StateEnvelope | null => {
    const [body, signature, extra] = value?.trim().split(".") ?? [];

    if (!body || !signature || extra !== undefined || !signaturePattern.test(signature)) {
        return null;
    }

    return { body, signature };
};

const getSchedule = (payload: StatePayload): SessionStateSchedule | null => {
    if (payload.exp < 1 || payload.renew < 1 || payload.renew > payload.exp) {
        return null;
    }

    const schedule = {
        expires_at: toDate(payload.exp),
        renew_at: toDate(payload.renew),
    };

    return Number.isFinite(schedule.expires_at.getTime()) &&
        Number.isFinite(schedule.renew_at.getTime())
        ? schedule
        : null;
};

export const parseSessionState = (value?: string | null): SessionStateSchedule | null => {
    const envelope = parseEnvelope(value);

    if (!envelope) {
        return null;
    }

    const payload = parsePayload(envelope.body);
    return payload ? getSchedule(payload) : null;
};

const toSession = ({ account_id, payload, stored }: ToSessionInput): Session => ({
    account_id,
    client: stored.client,
    created_at: toDate(stored.created),
    expires_at: toDate(payload.exp),
    id: stored.id,
    renew_at: toDate(payload.renew),
});

const toStoredSession = (session: Session): StoredSession => ({
    client: session.client,
    created: toSeconds(session.created_at),
    id: session.id,
});

export const createSessionState = <TAccount extends AuthAccount>({
    cache,
    now = () => new Date(),
    secret,
    session: sessionConfig,
}: SessionStateDeps): SessionState<TAccount> => {
    if (cache !== undefined) {
        if (!Number.isInteger(cache.ttl) || cache.ttl < 1 || cache.ttl > sessionConfig.ttl) {
            throw createError({
                code: "AUTH_CONFIG_INVALID",
                message: "Session cache TTL must be an integer between 1 and the session TTL.",
            });
        }
    }

    if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < MIN_SECRET_BYTES) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: "Authentication secret must contain at least 32 bytes.",
        });
    }

    return {
        create: ({ cache: useCache = true, resolved, token }) => {
            const expires_at = resolved.session.expires_at;
            const cache_expires_at =
                cache && useCache
                    ? new Date(Math.min(now().getTime() + cache.ttl * 1000, expires_at.getTime()))
                    : null;

            const payload: StatePayload = {
                cache: cache_expires_at
                    ? {
                          data: {
                              account: resolved.account,
                              session: toStoredSession(resolved.session),
                          },
                          exp: toSeconds(cache_expires_at),
                      }
                    : null,
                exp: toSeconds(expires_at),
                renew: toSeconds(resolved.session.renew_at),
            };

            const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
            const signature = getSignature({ body, secret, token });

            return {
                expires_at,
                value: `${body}.${signature}`,
            };
        },

        resolve: ({ client, token, value }) => {
            const envelope = parseEnvelope(value);

            if (
                !envelope ||
                !matchesSignature({
                    body: envelope.body,
                    secret,
                    signature: envelope.signature,
                    token,
                })
            ) {
                return null;
            }

            const payload = parsePayload(envelope.body);

            if (!payload) {
                return null;
            }

            const current = now().getTime();
            const schedule = getSchedule(payload);

            if (!schedule || schedule.expires_at.getTime() <= current) {
                return null;
            }

            const { expires_at, renew_at } = schedule;

            let resolved: ResolvedSession<TAccount> | null = null;
            const storedCache = cache ? payload.cache : null;

            if (storedCache) {
                const account = storedCache.data.account as TAccount;
                const session = toSession({
                    account_id: account.id,
                    payload,
                    stored: storedCache.data.session,
                });

                const max_expires_at =
                    session.created_at.getTime() + sessionConfig.maxLifetime * 1000;

                if (
                    toDate(storedCache.exp).getTime() > current &&
                    storedCache.exp <= payload.exp &&
                    expires_at.getTime() <= max_expires_at &&
                    matchesClient({
                        current: normalizeClient(client),
                        stored: session.client,
                        validation: sessionConfig.validation,
                    })
                ) {
                    resolved = { account, session };
                }
            }

            return {
                cache: resolved,
                expires_at,
                renew_at,
            };
        },
    };
};
