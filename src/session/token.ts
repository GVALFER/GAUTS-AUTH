import { createHash, randomBytes } from "node:crypto";

export const tokenPattern = /^[A-Za-z0-9_-]{43}$/;

export const createToken = (): string => {
  return randomBytes(32).toString("base64url");
};

export const hashToken = (token: string): string => {
  return createHash("sha256").update(token).digest("hex");
};
