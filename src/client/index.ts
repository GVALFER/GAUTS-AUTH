import { isIP, SocketAddress } from "node:net";
import type { SessionValidation } from "../config.js";

export type SessionClientInput = {
    agent?: string | null;
    ip?: string | null;
    platform?: string | null;
};

export type SessionClient = {
    agent: string | null;
    ip: string | null;
    platform: string | null;
};

type MatchesClientProps = {
    current: SessionClient;
    stored: SessionClient;
    validation: readonly SessionValidation[];
};

type HasClientFieldsProps = {
    client: SessionClient;
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

    const version = isIP(value);

    if (version === 4) {
        return value;
    }

    if (version !== 6 || value.includes("%")) {
        return null;
    }

    const normalized = new SocketAddress({
        address: value,
        family: "ipv6",
        port: 0,
    }).address;

    if (normalized.startsWith("::ffff:")) {
        return normalized.slice(7);
    }

    return normalized === "::1" ? "127.0.0.1" : normalized;
};

const normalizePlatform = (input?: string | null): string | null => {
    const value = input?.replace(/^"+|"+$/g, "").trim();
    return value ? value.slice(0, 255) : null;
};

const normalizeAgent = (input?: string | null): string | null => (input?.length ? input : null);

export const normalizeClient = (input: SessionClientInput): SessionClient => ({
    agent: normalizeAgent(input.agent),
    ip: normalizeIp(input.ip),
    platform: normalizePlatform(input.platform),
});

export const hasClientFields = ({ client, validation }: HasClientFieldsProps): boolean => {
    return validation.every((field) => client[field] !== null);
};

export const matchesClient = ({ current, stored, validation }: MatchesClientProps): boolean => {
    return (
        hasClientFields({ client: current, validation }) &&
        hasClientFields({ client: stored, validation }) &&
        validation.every((field) => stored[field] === current[field])
    );
};
