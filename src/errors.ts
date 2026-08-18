export type AuthErrorCode =
    | "AUTH_CONFIG_INVALID"
    | "SOCIAL_ACCOUNT_INVALID"
    | "SOCIAL_ACCOUNT_NOT_FOUND"
    | "SOCIAL_EMAIL_INVALID"
    | "SOCIAL_PROVIDER_ERROR"
    | "SOCIAL_REGISTRATION_INVALID"
    | "SOCIAL_STATE_INVALID"
    | "PASSWORD_INPUT_INVALID"
    | "SESSION_CLIENT_MISMATCH"
    | "SESSION_DATA_INVALID"
    | "SESSION_INVALID"
    | "SESSION_NOT_FOUND"
    | "DB_UNAVAILABLE";

export type AuthError = Error & {
    code: AuthErrorCode;
};

export type AuthErrorInput = {
    cause?: unknown;
    code: AuthErrorCode;
    message: string;
};

export const createError = ({ cause, code, message }: AuthErrorInput): AuthError => {
    const error = new Error(message, cause === undefined ? undefined : { cause }) as AuthError;

    error.name = "AuthError";
    error.code = code;

    return error;
};

export const isAuthError = (error: unknown): error is AuthError => {
    return (
        error instanceof Error &&
        error.name === "AuthError" &&
        "code" in error &&
        typeof error.code === "string"
    );
};
