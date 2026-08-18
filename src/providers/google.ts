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

export type GoogleConfig = ProviderConfig;

export const google = (input: GoogleConfig): SocialProvider => {
    const config = requireProviderConfig(input);

    return {
        callbackUrl: config.callbackUrl,
        getAuthorizationUrl: ({ codeChallenge, state }) => {
            const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
            url.search = createForm({
                client_id: config.clientId,
                code_challenge: codeChallenge,
                code_challenge_method: "S256",
                redirect_uri: config.callbackUrl,
                response_type: "code",
                scope: "openid email profile",
                state,
            }).toString();
            return url.toString();
        },
        getIdentity: async ({ code, codeVerifier }) => {
            const token = await requestJson({
                init: {
                    body: createForm({
                        client_id: config.clientId,
                        client_secret: config.clientSecret,
                        code,
                        code_verifier: codeVerifier,
                        grant_type: "authorization_code",
                        redirect_uri: config.callbackUrl,
                    }),
                    headers: { "content-type": "application/x-www-form-urlencoded" },
                    method: "POST",
                },
                provider: "google",
                url: "https://oauth2.googleapis.com/token",
            });

            const profile = await requestJson({
                init: {
                    headers: {
                        authorization: `Bearer ${requireAccessToken({ provider: "google", value: token })}`,
                    },
                },
                provider: "google",
                url: "https://openidconnect.googleapis.com/v1/userinfo",
            });

            return createIdentity({
                avatarUrl: isRecord(profile) ? profile.picture : null,
                email: isRecord(profile) ? profile.email : null,
                emailVerified: isRecord(profile) && profile.email_verified === true,
                name: isRecord(profile) ? profile.name : null,
                provider: "google",
                providerId: isRecord(profile) ? profile.sub : null,
            });
        },
        id: "google",
    };
};
