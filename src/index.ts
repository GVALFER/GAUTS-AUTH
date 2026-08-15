export { createAuth } from "./auth.js";
export type { Auth, AuthConfig, AuthDeps } from "./auth.js";
export type {
  BcryptConfig,
  Argon2idConfig,
  PasswordConfig,
  SessionConfig,
} from "./config.js";
export { isAuthError } from "./errors.js";
export type { AuthError, AuthErrorCode } from "./errors.js";
export type { PasswordService } from "./password/index.js";
export type {
  ActiveSession,
  CreateSessionRecord,
  CreatedSession,
  RedisSessionStore,
  ResolvedSession,
  Session,
  SessionRecord,
  SessionRecords,
  SessionService,
} from "./session/types.js";
export type {
  SessionClient,
  SessionClientInput,
  SessionIdentity,
  SessionIdentityInput,
} from "./client/index.js";
