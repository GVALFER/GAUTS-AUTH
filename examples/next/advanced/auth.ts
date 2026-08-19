import { createNextAuth } from "@gauts/auth/next";

const apiUrl = process.env.NEXT_PRIVATE_API_URL;

if (!apiUrl) {
    throw new Error("Missing NEXT_PRIVATE_API_URL.");
}

export const auth = createNextAuth({
    cookie: {
        contextName: "__app_ctx",
        sessionName: "__app_ses",
    },
    renewUrl: new URL("/auth/renew", apiUrl).toString(),
});
