import { buildForwardHeaders } from "@gauts/auth/next";
import { headers } from "next/headers.js";

const apiUrl = process.env.NEXT_PRIVATE_API_URL;

if (!apiUrl) {
    throw new Error("Missing NEXT_PRIVATE_API_URL.");
}

export const getAccount = async () => {
    const incoming = new Headers(await headers());

    const forwarded = buildForwardHeaders({
        extra: ["cookie", "authorization"],
        headers: incoming,
    });

    return fetch(new URL("/account", apiUrl), {
        cache: "no-store",
        headers: forwarded,
    });
};
