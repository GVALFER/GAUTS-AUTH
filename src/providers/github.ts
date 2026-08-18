import { createError } from "../errors.js";
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

export type GitHubConfig = ProviderConfig;

type GitHubEmail = {
    email: string;
    primary: boolean;
    verified: boolean;
};

const readEmails = (value: unknown): GitHubEmail[] => {
    if (!Array.isArray(value)) {
        throw createError({
            code: "SOCIAL_EMAIL_INVALID",
            message: "github did not return a verified email address.",
        });
    }

    return value.flatMap((item) => {
        return isRecord(item) &&
            typeof item.email === "string" &&
            typeof item.primary === "boolean" &&
            typeof item.verified === "boolean"
            ? [{ email: item.email, primary: item.primary, verified: item.verified }]
            : [];
    });
};

export const github = (input: GitHubConfig): SocialProvider => {
    const config = requireProviderConfig(input);

    return {
        callbackUrl: config.callbackUrl,
        getAuthorizationUrl: ({ codeChallenge, state }) => {
            const url = new URL("https://github.com/login/oauth/authorize");
            url.search = createForm({
                client_id: config.clientId,
                code_challenge: codeChallenge,
                code_challenge_method: "S256",
                redirect_uri: config.callbackUrl,
                response_type: "code",
                scope: "read:user user:email",
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
                        redirect_uri: config.callbackUrl,
                    }),
                    headers: {
                        accept: "application/json",
                        "content-type": "application/x-www-form-urlencoded",
                    },
                    method: "POST",
                },
                provider: "github",
                url: "https://github.com/login/oauth/access_token",
            });

            const accessToken = requireAccessToken({
                provider: "github",
                value: token,
            });

            const headers = {
                accept: "application/vnd.github+json",
                authorization: `Bearer ${accessToken}`,
                "x-github-api-version": "2022-11-28",
            };

            const [profile, emailValue] = await Promise.all([
                requestJson({
                    init: { headers },
                    provider: "github",
                    url: "https://api.github.com/user",
                }),
                requestJson({
                    init: { headers },
                    provider: "github",
                    url: "https://api.github.com/user/emails",
                }),
            ]);

            const emails = readEmails(emailValue);
            const email =
                emails.find((value) => value.primary && value.verified) ??
                emails.find((value) => value.verified);

            return createIdentity({
                avatarUrl: isRecord(profile) ? profile.avatar_url : null,
                email: email?.email,
                emailVerified: Boolean(email),
                name: isRecord(profile) ? profile.name : null,
                provider: "github",
                providerId: isRecord(profile) ? profile.id : null,
                username: isRecord(profile) ? profile.login : null,
            });
        },
        id: "github",
    };
};
