import type { SessionClient, SessionClientInput } from "../client/index.js";

export type AuthUser = {
    id: string;
    role: string;
    status: string;
};

export type AuthAccount = {
    email: string;
    id: string;
    name: string;
    role: string;
    status: string;
    timezone: string | null;
    user: AuthUser;
};

export type SessionRecord = {
    account_id: string;
    agent: string | null;
    created_at: Date;
    expires_at: Date;
    id: string;
    ip: string | null;
    platform: string | null;
    revoked_at: Date | null;
    token_hash: string;
    updated_at: Date | null;
};

export type AuthSessionRecord = SessionRecord & {
    account: AuthAccount;
    allowed: boolean;
};

export type CreateSessionRecord = Omit<SessionRecord, "revoked_at" | "updated_at">;

export type ActiveSession = Omit<SessionRecord, "token_hash">;

export type Session = {
    account_id: string;
    client: SessionClient;
    created_at: Date;
    expires_at: Date;
    id: string;
    renew_at: Date;
};

export type CreatedSession = {
    account: AuthAccount;
    session: Session;
    token: string;
    user: AuthUser;
};

export type ResolvedSession = {
    account: AuthAccount;
    session: Session;
    user: AuthUser;
};

export type RenewedSession = ResolvedSession & {
    renewed: boolean;
};

export type CreateSession = {
    account_id: string;
    client: SessionClientInput;
};

export type SessionInput = {
    client: SessionClientInput;
    token: string;
};

export type DbAdapter = {
    create(session: CreateSessionRecord): Promise<void>;
    find(input: { account_id: string; session_id: string }): Promise<SessionRecord | null>;
    findActive(input: { account_id: string; now: Date }): Promise<SessionRecord[]>;
    findToken(token_hash: string): Promise<AuthSessionRecord | null>;
    revoke(input: { revoked_at: Date; session_ids: string[] }): Promise<void>;
    updateExpiry(input: { expires_at: Date; session_id: string; updated_at: Date }): Promise<void>;
};

export type SessionService = {
    create(input: CreateSession): Promise<CreatedSession>;
    list(account_id: string): Promise<ActiveSession[]>;
    renew(input: SessionInput): Promise<RenewedSession | null>;
    resolve(input: SessionInput): Promise<ResolvedSession | null>;
    revoke(input: { account_id: string; session_id: string }): Promise<string[]>;
    revokeAccount(account_id: string): Promise<string[]>;
    revokeToken(token: string): Promise<string[]>;
};
