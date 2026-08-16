import type { SessionClient, SessionClientInput } from "../client/index.js";

export type SessionData = Record<string, unknown>;

export type StoredSession<TData extends object> = {
  account_id: string;
  client: SessionClient;
  created_at: string;
  data: TData;
  expires_at: string;
  id: string;
  touched_at: string;
};

export type Session<TData extends object> = {
  account_id: string;
  client: SessionClient;
  created_at: Date;
  data: TData;
  expires_at: Date;
  id: string;
  touched_at: Date;
};

export type CreatedSession<TData extends object> = {
  session: Session<TData>;
  token: string;
};

export type ResolvedSession<TData extends object> = {
  renewed: boolean;
  session: Session<TData>;
};

export type CreateSession<TData extends object> = {
  account_id: string;
  client: SessionClientInput;
  data: TData;
};

export type SessionInput = {
  client: SessionClientInput;
  token: string;
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

export type CreateSessionRecord = Omit<
  SessionRecord,
  "revoked_at" | "updated_at"
>;

export type ActiveSession = Omit<SessionRecord, "token_hash">;

export type DbAdapter = {
  create(session: CreateSessionRecord): Promise<void>;
  find(input: {
    account_id: string;
    session_id: string;
  }): Promise<SessionRecord | null>;
  findActive(input: {
    account_id: string;
    now: Date;
  }): Promise<SessionRecord[]>;
  revoke(input: { revoked_at: Date; session_ids: string[] }): Promise<void>;
  updateExpiry(input: {
    expires_at: Date;
    session_id: string;
    updated_at: Date;
  }): Promise<void>;
};

export type RedisAdapter = {
  create(input: {
    token_hash: string;
    ttl: number;
    value: string;
  }): Promise<void>;
  delete(token_hashes: string[]): Promise<void>;
  exists(token_hashes: string[]): Promise<boolean[]>;
  get(token_hash: string): Promise<string | null>;
  getMany(token_hashes: string[]): Promise<(string | null)[]>;
  keep(input: { token_hash: string; value: string }): Promise<boolean>;
  update(input: {
    token_hash: string;
    ttl: number;
    value: string;
  }): Promise<boolean>;
};

export type SessionService<TData extends object> = {
  create(input: CreateSession<TData>): Promise<CreatedSession<TData>>;
  list(account_id: string): Promise<ActiveSession[]>;
  resolve(input: SessionInput): Promise<ResolvedSession<TData> | null>;
  validate(input: SessionInput): Promise<Session<TData> | null>;
  revoke(input: { account_id: string; session_id: string }): Promise<string[]>;
  revokeAccount(account_id: string): Promise<string[]>;
  revokeToken(token: string): Promise<string[]>;
  sync(input: { account_id: string; data: TData }): Promise<void>;
};
