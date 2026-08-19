import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { github } from "../src/providers/github.js";
import { google } from "../src/providers/google.js";
import { x } from "../src/providers/x.js";
import { isAuthError } from "../src/errors.js";

type MockResponse = {
    body: unknown;
    status?: number;
};

const withFetch = async <T>({
    responses,
    run,
}: {
    responses: MockResponse[];
    run: (requests: { init: RequestInit | undefined; url: string }[]) => Promise<T>;
}): Promise<T> => {
    const original = globalThis.fetch;
    const requests: { init: RequestInit | undefined; url: string }[] = [];
    const queue = [...responses];

    globalThis.fetch = async (input, init) => {
        requests.push({
            init,
            url: input instanceof Request ? input.url : input.toString(),
        });
        const response = queue.shift();
        assert.ok(response, "Unexpected provider request.");
        return new Response(JSON.stringify(response.body), {
            headers: { "content-type": "application/json" },
            status: response.status ?? 200,
        });
    };

    try {
        return await run(requests);
    } finally {
        globalThis.fetch = original;
    }
};

const providerConfig = {
    callbackUrl: "https://app.example.com/proxy/auth/callback",
    clientId: "client-id",
    clientSecret: "client-secret",
};

const assertAuthorizationUrl = ({
    authorizationUrl,
    callbackUrl,
}: {
    authorizationUrl: string;
    callbackUrl: string;
}): void => {
    const url = new URL(authorizationUrl);

    assert.equal(url.searchParams.get("client_id"), providerConfig.clientId);
    assert.equal(url.searchParams.get("redirect_uri"), callbackUrl);
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("state"), "state-value");
    assert.equal(url.searchParams.get("code_challenge"), "challenge-value");
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
};

describe("social providers", () => {
    it("builds Google authorization and normalizes its verified identity", async () => {
        const provider = google({
            ...providerConfig,
            callbackUrl: "https://app.example.com/proxy/auth/google",
        });
        const authorizationUrl = provider.getAuthorizationUrl({
            codeChallenge: "challenge-value",
            state: "state-value",
        });

        assertAuthorizationUrl({ authorizationUrl, callbackUrl: provider.callbackUrl });

        const identity = await withFetch({
            responses: [
                { body: { access_token: "google-token" } },
                {
                    body: {
                        email: "Owner@Example.com",
                        email_verified: true,
                        name: "Owner",
                        picture: "https://images.example/google.png",
                        sub: "google-1",
                    },
                },
            ],
            run: async (requests) => {
                const value = await provider.getIdentity({
                    code: "provider-code",
                    codeVerifier: "verifier-value",
                });
                const body = requests[0]?.init?.body;

                assert.ok(body instanceof URLSearchParams);
                assert.equal(body.get("code_verifier"), "verifier-value");
                assert.equal(requests[1]?.init?.headers instanceof Headers, false);
                return value;
            },
        });

        assert.deepEqual(identity, {
            avatarUrl: "https://images.example/google.png",
            email: "owner@example.com",
            name: "Owner",
            provider: "google",
            providerId: "google-1",
            username: null,
        });
    });

    it("builds GitHub authorization and chooses a verified email", async () => {
        const provider = github({
            ...providerConfig,
            callbackUrl: "https://app.example.com/proxy/auth/github",
        });
        const authorizationUrl = provider.getAuthorizationUrl({
            codeChallenge: "challenge-value",
            state: "state-value",
        });

        assertAuthorizationUrl({ authorizationUrl, callbackUrl: provider.callbackUrl });

        const identity = await withFetch({
            responses: [
                { body: { access_token: "github-token" } },
                {
                    body: {
                        avatar_url: "https://images.example/github.png",
                        id: 123,
                        login: "owner",
                        name: "Owner",
                    },
                },
                {
                    body: [
                        { email: "other@example.com", primary: false, verified: true },
                        { email: "owner@example.com", primary: true, verified: true },
                    ],
                },
            ],
            run: async () =>
                provider.getIdentity({
                    code: "provider-code",
                    codeVerifier: "verifier-value",
                }),
        });

        assert.deepEqual(identity, {
            avatarUrl: "https://images.example/github.png",
            email: "owner@example.com",
            name: "Owner",
            provider: "github",
            providerId: "123",
            username: "owner",
        });
    });

    it("builds X authorization and normalizes confirmed_email", async () => {
        const provider = x({
            ...providerConfig,
            callbackUrl: "https://app.example.com/proxy/auth/x",
        });
        const authorizationUrl = provider.getAuthorizationUrl({
            codeChallenge: "challenge-value",
            state: "state-value",
        });

        assertAuthorizationUrl({ authorizationUrl, callbackUrl: provider.callbackUrl });

        const identity = await withFetch({
            responses: [
                { body: { access_token: "x-token" } },
                {
                    body: {
                        data: {
                            confirmed_email: "owner@example.com",
                            id: "x-1",
                            name: "Owner",
                            profile_image_url: "https://images.example/x.png",
                            username: "owner",
                        },
                    },
                },
            ],
            run: async () =>
                provider.getIdentity({
                    code: "provider-code",
                    codeVerifier: "verifier-value",
                }),
        });

        assert.deepEqual(identity, {
            avatarUrl: "https://images.example/x.png",
            email: "owner@example.com",
            name: "Owner",
            provider: "x",
            providerId: "x-1",
            username: "owner",
        });
    });

    it("rejects provider errors and unverified email addresses", async () => {
        const provider = google({
            ...providerConfig,
            callbackUrl: "https://app.example.com/proxy/auth/google",
        });

        await assert.rejects(
            () =>
                withFetch({
                    responses: [{ body: { error: "invalid_grant" }, status: 400 }],
                    run: async () =>
                        provider.getIdentity({
                            code: "invalid-code",
                            codeVerifier: "verifier-value",
                        }),
                }),
            (error: unknown) => isAuthError(error) && error.code === "SOCIAL_PROVIDER_ERROR",
        );

        await assert.rejects(
            () =>
                withFetch({
                    responses: [
                        { body: { access_token: "google-token" } },
                        {
                            body: {
                                email: "owner@example.com",
                                email_verified: false,
                                name: "Owner",
                                sub: "google-1",
                            },
                        },
                    ],
                    run: async () =>
                        provider.getIdentity({
                            code: "provider-code",
                            codeVerifier: "verifier-value",
                        }),
                }),
            (error: unknown) => isAuthError(error) && error.code === "SOCIAL_EMAIL_INVALID",
        );
    });

    it("rejects missing credentials and invalid callback URLs at startup", () => {
        assert.throws(
            () => google({ ...providerConfig, clientSecret: "" }),
            (error: unknown) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
        assert.throws(
            () => github({ ...providerConfig, callbackUrl: "/auth/github" }),
            (error: unknown) => isAuthError(error) && error.code === "AUTH_CONFIG_INVALID",
        );
    });
});
