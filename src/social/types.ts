import type { AuthAccount } from "../session/types.js";

export type SocialProviderId = "github" | "google" | "x";

export type SocialIntent = "login" | "register";

export type SocialIdentity = {
    avatarUrl: string | null;
    email: string;
    name: string;
    provider: SocialProviderId;
    providerId: string;
    username: string | null;
};

export type SocialAuthorizationInput = {
    codeChallenge: string;
    state: string;
};

export type SocialCallbackInput = {
    code: string;
    codeVerifier: string;
};

export type SocialProvider = {
    callbackUrl: string;
    getAuthorizationUrl(input: SocialAuthorizationInput): string;
    getIdentity(input: SocialCallbackInput): Promise<SocialIdentity>;
    id: SocialProviderId;
};

export type SocialAccountRecord<TAccount extends AuthAccount = AuthAccount> = {
    account: TAccount;
    allowed: boolean;
};

export type CreateSocialRecord = {
    account_id: string;
    created_at: Date;
    id: string;
    provider: SocialProviderId;
    provider_id: string;
};

export type SocialDbAdapter<TAccount extends AuthAccount = AuthAccount> = {
    createAccount(input: { email: string; name: string }): Promise<string>;
    createSocial(record: CreateSocialRecord): Promise<void>;
    findAccount(account_id: string): Promise<SocialAccountRecord<TAccount> | null>;
    findEmail(email: string): Promise<SocialAccountRecord<TAccount> | null>;
    findSocial(input: {
        provider: SocialProviderId;
        provider_id: string;
    }): Promise<SocialAccountRecord<TAccount> | null>;
};

export type SocialRegistrationInput<TData> = {
    data: TData;
    identity: SocialIdentity;
};

export type SocialRegistrationResult = {
    accountId: string;
};

export type SocialRegistrationConfig<TData = undefined> = {
    createAccount?: (
        input: SocialRegistrationInput<TData>,
    ) => Promise<SocialRegistrationResult>;
    registerUrl?: string;
};

export type SocialConfig<TData = undefined> = {
    cookieName?: string;
    errorUrl: string;
    providers: readonly SocialProvider[];
    registration?: SocialRegistrationConfig<TData>;
    successUrl: string;
};

export type ResolvedSocialConfig<TData = undefined> = {
    cookieName: string;
    errorUrl: string;
    providers: ReadonlyMap<SocialProviderId, SocialProvider>;
    registration: SocialRegistrationConfig<TData> | null;
    successUrl: string;
};
