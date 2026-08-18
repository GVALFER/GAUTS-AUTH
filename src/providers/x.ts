import { isRecord } from "../session/guards.js";
import type { SocialProvider } from "../social/types.js";
import {
    createForm,
    createIdentity,
    type ProviderConfig,
    requestJson,
    requireAccessToken,
    requireProviderConfig,
} from "./common.js";

export type XConfig = ProviderConfig;

export const x = (input: XConfig): SocialProvider => {
    const config = requireProviderConfig(input);

    return {
        callbackUrl: config.callbackUrl,
        getAuthorizationUrl: ({ codeChallenge, state }) => {
            const url = new URL("https://x.com/i/oauth2/authorize");
            url.search = createForm({
                client_id: config.clientId,
                code_challenge: codeChallenge,
                code_challenge_method: "S256",
                redirect_uri: config.callbackUrl,
                response_type: "code",
                scope: "tweet.read users.read users.email",
                state,
            }).toString();
            return url.toString();
        },
        getIdentity: async ({ code, codeVerifier }) => {
            const credentials = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString(
                "base64",
            );
            const token = await requestJson({
                init: {
                    body: createForm({
                        client_id: config.clientId,
                        code,
                        code_verifier: codeVerifier,
                        grant_type: "authorization_code",
                        redirect_uri: config.callbackUrl,
                    }),
                    headers: {
                        authorization: `Basic ${credentials}`,
                        "content-type": "application/x-www-form-urlencoded",
                    },
                    method: "POST",
                },
                provider: "x",
                url: "https://api.x.com/2/oauth2/token",
            });

            const profile = await requestJson({
                init: {
                    headers: {
                        authorization: `Bearer ${requireAccessToken({ provider: "x", value: token })}`,
                    },
                },
                provider: "x",
                url: "https://api.x.com/2/users/me?user.fields=id,name,username,profile_image_url,confirmed_email",
            });

            const data = isRecord(profile) && isRecord(profile.data) ? profile.data : null;

            return createIdentity({
                avatarUrl: data?.profile_image_url,
                email: data?.confirmed_email,
                emailVerified: typeof data?.confirmed_email === "string",
                name: data?.name,
                provider: "x",
                providerId: data?.id,
                username: data?.username,
            });
        },
        id: "x",
    };
};
