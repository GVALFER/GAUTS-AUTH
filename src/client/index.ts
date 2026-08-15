import ipaddr from "ipaddr.js";
import type { SessionValidation } from "../config.js";

export type SessionClientInput = {
  ip?: string | null;
  platform?: string | null;
  userAgent?: string | null;
};

export type SessionClient = {
  ip: string | null;
  platform: string | null;
  userAgent: string | null;
};

type MatchesClientProps = {
  current: SessionClient;
  stored: SessionClient;
  validation: readonly SessionValidation[];
};

export const normalizeIp = (input?: string | null): string | null => {
  let value = input?.trim();

  if (!value) {
    return null;
  }

  if (value.startsWith("[") && value.endsWith("]")) {
    value = value.slice(1, -1);
  }

  if (!ipaddr.isValid(value)) {
    return null;
  }

  const normalized = ipaddr.process(value).toString();

  return normalized === "::1" ? "127.0.0.1" : normalized;
};

const normalizePlatform = (input?: string | null): string | null => {
  const value = input?.replace(/^"+|"+$/g, "").trim();

  return value ? value.slice(0, 255) : null;
};

const normalizeUserAgent = (input?: string | null): string | null =>
  input?.length ? input : null;

export const normalizeClient = (input: SessionClientInput): SessionClient => ({
  ip: normalizeIp(input.ip),
  platform: normalizePlatform(input.platform),
  userAgent: normalizeUserAgent(input.userAgent),
});

export const matchesClient = ({
  current,
  stored,
  validation,
}: MatchesClientProps): boolean => {
  return validation.every((field) => stored[field] === current[field]);
};
