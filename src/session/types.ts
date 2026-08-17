import type { SessionClient, SessionClientInput } from "../client/index.js";

export type AuthScalar = boolean | null | number | string;

export type AuthValue = AuthScalar | AuthData | readonly AuthValue[];

export type AuthData = {
    [key: string]: AuthValue;
};

export type AuthAccount = {
    id: string;
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

export type AuthSessionRecord<TAccount extends AuthAccount = AuthAccount> = SessionRecord & {
    account: TAccount;
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

export type CreatedSession<TAccount extends AuthAccount = AuthAccount> = {
    account: TAccount;
    session: Session;
    token: string;
};

export type ResolvedSession<TAccount extends AuthAccount = AuthAccount> = {
    account: TAccount;
    session: Session;
};

export type RenewedSession<TAccount extends AuthAccount = AuthAccount> =
    ResolvedSession<TAccount> & {
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

export type DbAdapter<TAccount extends AuthAccount = AuthAccount> = {
    create(session: CreateSessionRecord): Promise<void>;
    find(input: { account_id: string; session_id: string }): Promise<SessionRecord | null>;
    findActive(input: { account_id: string; now: Date }): Promise<SessionRecord[]>;
    findToken(token_hash: string): Promise<AuthSessionRecord<TAccount> | null>;
    revoke(input: { revoked_at: Date; session_ids: string[] }): Promise<void>;
    updateExpiry(input: { expires_at: Date; session_id: string; updated_at: Date }): Promise<void>;
};

export type SessionService<TAccount extends AuthAccount = AuthAccount> = {
    create(input: CreateSession): Promise<CreatedSession<TAccount>>;
    list(account_id: string): Promise<ActiveSession[]>;
    renew(input: SessionInput): Promise<RenewedSession<TAccount> | null>;
    resolve(input: SessionInput): Promise<ResolvedSession<TAccount> | null>;
    revoke(input: { account_id: string; session_id: string }): Promise<string[]>;
    revokeAccount(account_id: string): Promise<string[]>;
    revokeToken(token: string): Promise<string[]>;
};

export type AuthAccountOf<T> =
    T extends DbAdapter<infer TAccount>
        ? TAccount
        : T extends { session: SessionService<infer TAccount> }
          ? TAccount
          : never;
