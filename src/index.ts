export { createAuth } from "./auth.js";
export type { Auth, AuthConfig, AuthDeps } from "./auth.js";
export type {
    BcryptConfig,
    Argon2idConfig,
    PasswordConfig,
    SessionConfig,
    SessionValidation,
} from "./config.js";
export { isAuthError } from "./errors.js";
export type { AuthError, AuthErrorCode } from "./errors.js";
export type { PasswordService } from "./password/index.js";
export type {
    ActiveSession,
    AuthAccount,
    AuthSessionRecord,
    AuthUser,
    CreateSessionRecord,
    CreatedSession,
    DbAdapter,
    RenewedSession,
    ResolvedSession,
    Session,
    SessionInput,
    SessionRecord,
    SessionService,
} from "./session/types.js";
export type { SessionClient, SessionClientInput } from "./client/index.js";
export type { SessionCacheConfig } from "./session/cache.js";
