import { createError } from "../errors.js";
import type { SocialNavigation } from "./types.js";

type ResolvePathInput = {
    name: string;
    optional?: boolean;
    value: string | null | undefined;
};

type ResolveNavigationInput = {
    errorTo: string | null | undefined;
    registerTo: string | null | undefined;
    returnTo: string | null | undefined;
};

type AddErrorInput = {
    code: string;
    path: string;
};

const LOCAL_ORIGIN = "https://auth.local";
const MAX_PATH_LENGTH = 1024;

const hasControlCharacter = (value: string): boolean => {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);

        if (code <= 31 || code === 127) {
            return true;
        }
    }

    return false;
};

const resolvePath = ({ name, optional = false, value }: ResolvePathInput): string | null => {
    if (optional && value === undefined) {
        return null;
    }

    if (typeof value !== "string") {
        throw createError({
            code: "SOCIAL_STATE_INVALID",
            message: `${name} must be a local path.`,
        });
    }

    const path = value.trim();

    if (
        path.length === 0 ||
        path.length > MAX_PATH_LENGTH ||
        !path.startsWith("/") ||
        path.startsWith("//") ||
        path.includes("\\") ||
        hasControlCharacter(path)
    ) {
        throw createError({
            code: "SOCIAL_STATE_INVALID",
            message: `${name} must be a local path.`,
        });
    }

    const url = new URL(path, LOCAL_ORIGIN);

    if (url.origin !== LOCAL_ORIGIN) {
        throw createError({
            code: "SOCIAL_STATE_INVALID",
            message: `${name} must be a local path.`,
        });
    }

    return `${url.pathname}${url.search}${url.hash}`;
};

const requirePath = ({ name, value }: Omit<ResolvePathInput, "optional">): string => {
    const path = resolvePath({ name, value });

    if (path === null) {
        throw createError({
            code: "SOCIAL_STATE_INVALID",
            message: `${name} must be a local path.`,
        });
    }

    return path;
};

export const resolveSocialNavigation = ({
    errorTo,
    registerTo,
    returnTo,
}: ResolveNavigationInput): SocialNavigation => ({
    errorTo: requirePath({ name: "errorTo", value: errorTo }),
    registerTo: resolvePath({ name: "registerTo", optional: true, value: registerTo }),
    returnTo: requirePath({ name: "returnTo", value: returnTo }),
});

export const addSocialError = ({ code, path }: AddErrorInput): string => {
    const url = new URL(path, LOCAL_ORIGIN);
    url.searchParams.set("error", code);
    return `${url.pathname}${url.search}${url.hash}`;
};
