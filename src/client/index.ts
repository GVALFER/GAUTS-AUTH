import ipaddr from "ipaddr.js";

export type SessionClientInput = {
  country?: string | null;
  ip?: string | null;
  platform?: string | null;
  userAgent?: string | null;
};

export type SessionIdentityInput = Pick<SessionClientInput, "ip" | "userAgent">;

export type SessionClient = {
  country: string | null;
  ip: string | null;
  platform: string | null;
  userAgent: string | null;
};

export type SessionIdentity = Pick<SessionClient, "ip" | "userAgent">;

type MatchesClientProps = {
  current: SessionIdentity;
  stored: SessionIdentity;
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

const normalizeCountry = (input?: string | null): string | null => {
  const value = input?.trim().toUpperCase();

  return value && /^[A-Z]{2}$/.test(value) ? value : null;
};

const normalizePlatform = (input?: string | null): string | null => {
  const value = input?.replace(/^"+|"+$/g, "").trim();

  return value ? value.slice(0, 255) : null;
};

const normalizeUserAgent = (input?: string | null): string | null =>
  input?.length ? input : null;

export const normalizeClient = (input: SessionClientInput): SessionClient => ({
  country: normalizeCountry(input.country),
  ip: normalizeIp(input.ip),
  platform: normalizePlatform(input.platform),
  userAgent: normalizeUserAgent(input.userAgent),
});

export const normalizeIdentity = (
  input: SessionIdentityInput,
): SessionIdentity => ({
  ip: normalizeIp(input.ip),
  userAgent: normalizeUserAgent(input.userAgent),
});

export const matchesClient = ({
  current,
  stored,
}: MatchesClientProps): boolean => {
  return stored.ip === current.ip && stored.userAgent === current.userAgent;
};
