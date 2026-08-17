import { randomUUID } from "node:crypto";

import { hasClientFields, matchesClient, normalizeClient } from "../client/index.js";
import type { ResolvedSessionConfig } from "../config.js";
import { createError, isAuthError } from "../errors.js";
import { createToken, hashToken, tokenPattern } from "./token.js";
import type {
    ActiveSession,
    AuthSessionRecord,
    DbAdapter,
    Session,
    SessionInput,
    SessionRecord,
    SessionService,
} from "./types.js";

type SessionDeps = {
    config: ResolvedSessionConfig;
    db: DbAdapter;
    now?: () => Date;
};

type ValidatedSession = {
    current: Date;
    row: AuthSessionRecord;
};

type RevokeRowsInput = {
    revoked_at: Date;
    rows: SessionRecord[];
};

const toActiveSession = (row: SessionRecord): ActiveSession => ({
    account_id: row.account_id,
    agent: row.agent,
    created_at: row.created_at,
    expires_at: row.expires_at,
    id: row.id,
    ip: row.ip,
    platform: row.platform,
    revoked_at: row.revoked_at,
    updated_at: row.updated_at,
});

export const createSessionService = ({
    config,
    db,
    now = () => new Date(),
}: SessionDeps): SessionService => {
    const runDb = async <T>(operation: () => Promise<T>): Promise<T> => {
        try {
            return await operation();
        } catch (error) {
            if (isAuthError(error)) {
                throw error;
            }

            throw createError({
                cause: error,
                code: "DB_UNAVAILABLE",
                message: "Session database unavailable.",
            });
        }
    };

    const getMaxExpiresAt = (created_at: Date): Date => {
        return new Date(created_at.getTime() + config.maxLifetime * 1000);
    };

    const getRenewAt = (row: SessionRecord): Date => {
        const renewed_at = row.updated_at ?? row.created_at;

        return new Date(
            Math.min(
                renewed_at.getTime() + config.renewInterval * 1000,
                getMaxExpiresAt(row.created_at).getTime(),
            ),
        );
    };

    const toSession = (row: SessionRecord): Session => {
        const expires_at = new Date(
            Math.min(row.expires_at.getTime(), getMaxExpiresAt(row.created_at).getTime()),
        );

        return {
            account_id: row.account_id,
            client: {
                agent: row.agent,
                ip: row.ip,
                platform: row.platform,
            },
            created_at: row.created_at,
            expires_at,
            id: row.id,
            renew_at: getRenewAt(row),
        };
    };

    const getActive = async (account_id: string): Promise<SessionRecord[]> => {
        const current = now();
        const rows = await runDb(() => db.findActive({ account_id, now: current }));

        return rows.filter(
            (row) =>
                row.revoked_at === null &&
                row.expires_at.getTime() > current.getTime() &&
                getMaxExpiresAt(row.created_at).getTime() > current.getTime(),
        );
    };

    const revokeRows = async ({ revoked_at, rows }: RevokeRowsInput): Promise<string[]> => {
        if (rows.length === 0) {
            return [];
        }

        const session_ids = rows.map((row) => row.id);
        await runDb(() => db.revoke({ revoked_at, session_ids }));

        return session_ids;
    };

    const validateSession = async (input: SessionInput): Promise<ValidatedSession | null> => {
        if (!tokenPattern.test(input.token)) {
            return null;
        }

        const row = await runDb(() => db.findToken(hashToken(input.token)));

        if (row?.revoked_at !== null) {
            return null;
        }

        const current = now();

        if (
            row.expires_at.getTime() <= current.getTime() ||
            getMaxExpiresAt(row.created_at).getTime() <= current.getTime()
        ) {
            return null;
        }

        if (!row.allowed) {
            await runDb(() => db.revoke({ revoked_at: current, session_ids: [row.id] }));
            return null;
        }

        const client = normalizeClient(input.client);

        const stored = {
            agent: row.agent,
            ip: row.ip,
            platform: row.platform,
        };

        const matches = matchesClient({
            current: client,
            stored,
            validation: config.validation,
        });

        if (!matches) {
            await runDb(() => db.revoke({ revoked_at: current, session_ids: [row.id] }));

            throw createError({
                code: "SESSION_CLIENT_MISMATCH",
                message: "Session client identity changed and the session was revoked.",
            });
        }

        return { current, row };
    };

    return {
        create: async (input) => {
            if (!input.account_id) {
                throw createError({
                    code: "SESSION_DATA_INVALID",
                    message: "Session account ID is required.",
                });
            }

            const client = normalizeClient(input.client);

            if (!hasClientFields({ client, validation: config.validation })) {
                throw createError({
                    code: "SESSION_DATA_INVALID",
                    message: "Configured session client fields are required.",
                });
            }

            const created_at = now();
            const expires_at = new Date(
                Math.min(
                    created_at.getTime() + config.ttl * 1000,
                    getMaxExpiresAt(created_at).getTime(),
                ),
            );

            const token = createToken();
            const row: SessionRecord = {
                account_id: input.account_id,
                agent: client.agent,
                created_at,
                expires_at,
                id: randomUUID(),
                ip: client.ip,
                platform: client.platform,
                revoked_at: null,
                token_hash: hashToken(token),
                updated_at: null,
            };

            await runDb(() =>
                db.create({
                    account_id: row.account_id,
                    agent: row.agent,
                    created_at: row.created_at,
                    expires_at: row.expires_at,
                    id: row.id,
                    ip: row.ip,
                    platform: row.platform,
                    token_hash: row.token_hash,
                }),
            );

            const stored = await runDb(() => db.findToken(row.token_hash));

            if (!stored?.allowed) {
                await runDb(() => db.revoke({ revoked_at: created_at, session_ids: [row.id] }));

                throw createError({
                    code: "SESSION_INVALID",
                    message: "Account is not allowed to authenticate.",
                });
            }

            return {
                account: stored.account,
                session: toSession(row),
                token,
                user: stored.account.user,
            };
        },

        resolve: async (input) => {
            const validated = await validateSession(input);

            if (!validated) {
                return null;
            }

            return {
                account: validated.row.account,
                session: toSession(validated.row),
                user: validated.row.account.user,
            };
        },

        renew: async (input) => {
            const validated = await validateSession(input);

            if (!validated) {
                return null;
            }

            const { current, row } = validated;

            if (current.getTime() < getRenewAt(row).getTime()) {
                return {
                    account: row.account,
                    renewed: false,
                    session: toSession(row),
                    user: row.account.user,
                };
            }

            const expires_at = new Date(
                Math.min(
                    current.getTime() + config.ttl * 1000,
                    getMaxExpiresAt(row.created_at).getTime(),
                ),
            );

            await runDb(() =>
                db.updateExpiry({
                    expires_at,
                    session_id: row.id,
                    updated_at: current,
                }),
            );

            return {
                account: row.account,
                renewed: true,
                session: toSession({
                    ...row,
                    expires_at,
                    updated_at: current,
                }),
                user: row.account.user,
            };
        },

        revokeToken: async (token) => {
            if (!tokenPattern.test(token)) {
                return [];
            }

            const row = await runDb(() => db.findToken(hashToken(token)));

            if (row?.revoked_at !== null) {
                return [];
            }

            return revokeRows({ revoked_at: now(), rows: [row] });
        },

        revoke: async ({ account_id, session_id }) => {
            const row = await runDb(() => db.find({ account_id, session_id }));

            if (row?.revoked_at !== null) {
                throw createError({
                    code: "SESSION_NOT_FOUND",
                    message: "Session not found.",
                });
            }

            return revokeRows({ revoked_at: now(), rows: [row] });
        },

        revokeAccount: async (account_id) => {
            return revokeRows({
                revoked_at: now(),
                rows: await getActive(account_id),
            });
        },

        list: async (account_id) => {
            return (await getActive(account_id)).map(toActiveSession);
        },
    };
};
