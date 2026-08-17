import type { PasswordConfig, ResolvedSessionConfig, SessionConfig } from "./config.js";
import { resolvePasswordConfig, resolveSessionConfig } from "./config.js";
import { createError } from "./errors.js";
import { createPassword, type PasswordService } from "./password/index.js";
import { createSessionService } from "./session/service.js";
import type { DbAdapter, SessionService } from "./session/types.js";

export type AuthConfig = {
    password?: PasswordConfig;
    session?: SessionConfig;
};

export type AuthDeps = AuthConfig & {
    db: DbAdapter;
};

export type Auth = {
    readonly config: {
        readonly session: Readonly<ResolvedSessionConfig>;
    };
    password: PasswordService;
    session: SessionService;
};

type RequireMethodsInput = {
    methods: string[];
    name: string;
    value: unknown;
};

const requireMethods = ({ methods, name, value }: RequireMethodsInput): void => {
    if (typeof value !== "object" || value === null) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${name} adapter is invalid.`,
        });
    }

    const adapter = value as Record<string, unknown>;

    if (methods.some((method) => typeof adapter[method] !== "function")) {
        throw createError({
            code: "AUTH_CONFIG_INVALID",
            message: `${name} adapter is invalid.`,
        });
    }
};

export const createAuth = ({ db, password, session }: AuthDeps): Auth => {
    requireMethods({
        methods: ["create", "find", "findActive", "findToken", "revoke", "updateExpiry"],
        name: "DB",
        value: db,
    });

    const sessionConfig = resolveSessionConfig(session);

    return {
        config: {
            session: sessionConfig,
        },
        password: createPassword(resolvePasswordConfig(password)),
        session: createSessionService({
            config: sessionConfig,
            db,
        }),
    };
};
