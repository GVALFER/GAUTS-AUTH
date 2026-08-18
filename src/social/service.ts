import { randomUUID } from "node:crypto";

import { createError, isAuthError } from "../errors.js";
import type { AuthAccount } from "../session/types.js";
import type {
    SocialAccountRecord,
    SocialDbAdapter,
    SocialIdentity,
    SocialRegistrationConfig,
} from "./types.js";

type SocialServiceDeps<TAccount extends AuthAccount, TData> = {
    db: SocialDbAdapter<TAccount>;
    now?: () => Date;
    registration: SocialRegistrationConfig<TData> | null;
};

type RegisterInput<TData> = {
    data: TData;
    identity: SocialIdentity;
};

export type SocialService<TAccount extends AuthAccount, TData> = {
    find(identity: SocialIdentity): Promise<TAccount | null>;
    register(input: RegisterInput<TData>): Promise<TAccount>;
};

type CreateSocial = {
    account_id: string;
    identity: SocialIdentity;
};

const requireAccount = <TAccount extends AuthAccount>(
    value: SocialAccountRecord<TAccount> | null,
): TAccount => {
    if (!value?.allowed) {
        throw createError({
            code: "SOCIAL_ACCOUNT_INVALID",
            message: "Social account is not allowed to authenticate.",
        });
    }

    return value.account;
};

export const createSocialService = <TAccount extends AuthAccount, TData>({
    db,
    now = () => new Date(),
    registration,
}: SocialServiceDeps<TAccount, TData>): SocialService<TAccount, TData> => {
    const runDb = async <T>(operation: () => Promise<T>): Promise<T> => {
        try {
            return await operation();
        } catch (error) {
            if (isAuthError(error)) {
                throw error;
            }

            throw createError({
                cause: error,
                code: "DB_UNAVAILABLE",
                message: "Social authentication database unavailable.",
            });
        }
    };

    const createSocial = async ({ account_id, identity }: CreateSocial): Promise<void> => {
        await runDb(() =>
            db.createSocial({
                account_id,
                created_at: now(),
                id: randomUUID(),
                provider: identity.provider,
                provider_id: identity.providerId,
            }),
        );
    };

    return {
        find: async (identity) => {
            const linked = await runDb(() =>
                db.findSocial({
                    provider: identity.provider,
                    provider_id: identity.providerId,
                }),
            );

            if (linked) {
                return requireAccount(linked);
            }

            const emailAccount = await runDb(() => db.findEmail(identity.email));

            if (!emailAccount) {
                return null;
            }

            const account = requireAccount(emailAccount);
            await createSocial({ account_id: account.id, identity });
            return account;
        },

        register: async ({ data, identity }) => {
            if (!registration) {
                throw createError({
                    code: "SOCIAL_ACCOUNT_NOT_FOUND",
                    message: "Social account does not exist.",
                });
            }

            const result = registration.createAccount
                ? await registration.createAccount({ data, identity })
                : {
                      accountId: await runDb(() =>
                          db.createAccount({ email: identity.email, name: identity.name }),
                      ),
                  };

            if (!result.accountId) {
                throw createError({
                    code: "SOCIAL_REGISTRATION_INVALID",
                    message: "Social registration did not return an account ID.",
                });
            }

            const account = requireAccount(await runDb(() => db.findAccount(result.accountId)));

            await createSocial({ account_id: account.id, identity });
            return account;
        },
    };
};
