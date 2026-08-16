import type { SessionClient, SessionClientInput } from "../client/index.js";

export type SessionData = Record<string, unknown>;

export type StoredSession<TData extends object> = {
  accountId: string;
  client: SessionClient;
  createdAt: string;
  data: TData;
  expiresAt: string;
  id: string;
  touchedAt: string;
};

export type Session<TData extends object> = {
  accountId: string;
  client: SessionClient;
  createdAt: Date;
  data: TData;
  expiresAt: Date;
  id: string;
  touchedAt: Date;
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
  accountId: string;
  client: SessionClientInput;
  data: TData;
};

export type SessionInput = {
  client: SessionClientInput;
  token: string;
};

export type SessionRecord = {
  accountId: string;
  client: SessionClient;
  createdAt: Date;
  expiresAt: Date;
  id: string;
  revokedAt: Date | null;
  tokenHash: string;
  updatedAt: Date | null;
};

export type CreateSessionRecord = Omit<
  SessionRecord,
  "revokedAt" | "updatedAt"
>;

export type ActiveSession = Omit<SessionRecord, "tokenHash">;

export type SessionActions = {
  create(session: CreateSessionRecord): Promise<void>;
  find(input: {
    accountId: string;
    sessionId: string;
  }): Promise<SessionRecord | null>;
  findActive(input: { accountId: string; now: Date }): Promise<SessionRecord[]>;
  revoke(input: { revokedAt: Date; sessionIds: string[] }): Promise<void>;
  updateExpiry(input: {
    expiresAt: Date;
    sessionId: string;
    updatedAt: Date;
  }): Promise<void>;
};

export type RedisSessionStore = {
  create(input: {
    tokenHash: string;
    ttl: number;
    value: string;
  }): Promise<void>;
  delete(tokenHashes: string[]): Promise<void>;
  exists(tokenHashes: string[]): Promise<boolean[]>;
  get(tokenHash: string): Promise<string | null>;
  getMany(tokenHashes: string[]): Promise<(string | null)[]>;
  keep(input: { tokenHash: string; value: string }): Promise<boolean>;
  update(input: {
    tokenHash: string;
    ttl: number;
    value: string;
  }): Promise<boolean>;
};

export type SessionService<TData extends object> = {
  create(input: CreateSession<TData>): Promise<CreatedSession<TData>>;
  list(accountId: string): Promise<ActiveSession[]>;
  resolve(input: SessionInput): Promise<ResolvedSession<TData> | null>;
  validate(input: SessionInput): Promise<Session<TData> | null>;
  revoke(input: { accountId: string; sessionId: string }): Promise<string[]>;
  revokeAccount(accountId: string): Promise<string[]>;
  revokeToken(token: string): Promise<string[]>;
  sync(input: { accountId: string; data: TData }): Promise<void>;
};
