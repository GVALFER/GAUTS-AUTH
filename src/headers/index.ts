export type BuildForwardHeadersInput = {
    extra?: readonly string[];
    headers: Headers;
};

export const FORWARD_HEADERS = [
    "accept-language",
    "cf-connecting-ip",
    "origin",
    "referer",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "true-client-ip",
    "user-agent",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-real-ip",
] as const;

export const buildForwardHeaders = ({
    extra = [],
    headers: incoming,
}: BuildForwardHeadersInput): Headers => {
    const headers = new Headers();

    for (const name of [...FORWARD_HEADERS, ...extra]) {
        const value = incoming.get(name);

        if (value?.trim()) {
            headers.set(name, value);
        }
    }

    const origin = headers.get("origin")?.trim();
    const host = headers.get("x-forwarded-host")?.trim();
    const proto = headers.get("x-forwarded-proto")?.trim();

    if (!origin && host && proto) {
        headers.set("origin", `${proto}://${host}`);
    }

    return headers;
};
