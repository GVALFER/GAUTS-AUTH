import type { PasswordConfig, SessionConfig } from "./config.js";
import { resolvePasswordConfig, resolveSessionConfig } from "./config.js";
import { createError } from "./errors.js";
import { createPassword, type PasswordService } from "./password/index.js";
import { createSessionService } from "./session/service.js";
import type {
  RedisSessionStore,
  SessionActions,
  SessionService,
} from "./session/types.js";

export type AuthConfig = {
  password?: PasswordConfig;
  session?: SessionConfig;
};

export type AuthDeps = AuthConfig & {
  actions: SessionActions;
  redis: RedisSessionStore;
};

export type Auth<TData extends object> = {
  password: PasswordService;
  session: SessionService<TData>;
};

type RequireMethodsInput = {
  methods: string[];
  name: string;
  value: unknown;
};

const requireMethods = ({
  methods,
  name,
  value,
}: RequireMethodsInput): void => {
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

export const createAuth = <TData extends object = Record<string, unknown>>({
  actions,
  password,
  redis,
  session,
}: AuthDeps): Auth<TData> => {
  requireMethods({
    methods: ["create", "delete", "exists", "get", "getMany", "keep", "update"],
    name: "Redis",
    value: redis,
  });
  requireMethods({
    methods: ["create", "find", "findActive", "revoke", "updateExpiry"],
    name: "Session actions",
    value: actions,
  });

  return {
    password: createPassword(resolvePasswordConfig(password)),
    session: createSessionService({
      actions,
      config: resolveSessionConfig(session),
      redis,
    }),
  };
};
