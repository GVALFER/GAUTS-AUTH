import type { SocialDbAdapter } from "../../social/types.js";
import type { AuthAccount, AuthScalar, DbAdapter, SessionRecord } from "../../session/types.js";

type DelegateMeta<T> = T[Extract<keyof T, symbol>];

export type DelegateRow<T> =
    DelegateMeta<T> extends {
        types: {
            payload: { scalars: infer Result };
        };
    }
        ? Result
        : never;

type IsSessionModel<T> = [DelegateRow<T>] extends [never]
    ? false
    : DelegateRow<T> extends SessionRecord
      ? true
      : false;

type IsAccountModel<T> = [DelegateRow<T>] extends [never]
    ? false
    : DelegateRow<T> extends { email: string; id: string; user_id: string }
      ? true
      : false;

type IsUserModel<T> = [DelegateRow<T>] extends [never]
    ? false
    : DelegateRow<T> extends { id: string; name: string }
      ? DelegateRow<T> extends { email: string }
          ? false
          : true
      : false;

type IsSocialModel<T> = [DelegateRow<T>] extends [never]
    ? false
    : DelegateRow<T> extends {
            account_id: string;
            created_at: Date;
            id: string;
            provider: string;
            provider_id: string;
        }
      ? true
      : false;

type ModelName<Client, Kind extends "account" | "session" | "social" | "user"> = {
    [Key in keyof Client]: Kind extends "account"
        ? IsAccountModel<Client[Key]> extends true
            ? Key
            : never
        : Kind extends "session"
          ? IsSessionModel<Client[Key]> extends true
              ? Key
              : never
          : Kind extends "social"
            ? IsSocialModel<Client[Key]> extends true
                ? Key
                : never
            : IsUserModel<Client[Key]> extends true
              ? Key
              : never;
}[keyof Client] &
    string;

export type PrismaAccountModel<Client> = ModelName<Client, "account">;
export type PrismaSessionModel<Client> = ModelName<Client, "session">;
export type PrismaSocialModel<Client> = ModelName<Client, "social">;
export type PrismaUserModel<Client> = ModelName<Client, "user">;

type ModelRow<Client, Name extends string> = Name extends keyof Client
    ? DelegateRow<Client[Name]>
    : never;

type PrivateField = "hash" | "password" | "password_hash" | "passwordHash";

type AuthField<Row> = {
    [Key in keyof Row]: Key extends PrivateField
        ? never
        : Row[Key] extends AuthScalar
          ? Key
          : never;
}[keyof Row] &
    string;

type AccessRule<Value> = [Value] extends [AuthScalar] ? Value | readonly Value[] : never;

type ModelAccess<Row> = Partial<{
    [Key in AuthField<Row>]: AccessRule<Row[Key]>;
}>;

type DataModelConfig<Client, Name extends string> = {
    access?: ModelAccess<ModelRow<Client, Name>>;
    select?: readonly AuthField<ModelRow<Client, Name>>[];
    table?: Name;
};

type TableModelConfig<Name extends string> = {
    table?: Name;
};

type ModelChoice<
    Client,
    Name extends string,
    Default extends string,
    Data extends boolean,
> = Name extends unknown
    ? Data extends true
        ? DataModelConfig<Client, Name> &
              (Name extends Default ? { table?: Name } : { table: Name })
        : TableModelConfig<Name> & (Name extends Default ? { table?: Name } : { table: Name })
    : never;

export type PrismaUserConfig<Client> = ModelChoice<Client, PrismaUserModel<Client>, "users", true>;

export type PrismaAccountConfig<Client> = ModelChoice<
    Client,
    PrismaAccountModel<Client>,
    "user_accounts",
    true
>;

export type PrismaSessionConfig<Client> = ModelChoice<
    Client,
    PrismaSessionModel<Client>,
    "account_sessions",
    false
>;

export type PrismaSocialConfig<Client> = ModelChoice<
    Client,
    PrismaSocialModel<Client>,
    "social_accounts",
    false
>;

export type PrismaModelsConfig<Client> = {
    accounts?: PrismaAccountConfig<Client>;
    sessions?: PrismaSessionConfig<Client>;
    socials?: PrismaSocialConfig<Client>;
    users?: PrismaUserConfig<Client>;
};

type HasModel<Client, Name extends string, Kind extends "account" | "session" | "social" | "user"> =
    Name extends ModelName<Client, Kind> ? true : false;

type HasDefaults<Client> =
    HasModel<Client, "users", "user"> extends true
        ? HasModel<Client, "user_accounts", "account"> extends true
            ? HasModel<Client, "account_sessions", "session"> extends true
                ? HasModel<Client, "social_accounts", "social"> extends true
                    ? true
                    : false
                : false
            : false
        : false;

export type PrismaAdapterInput<
    Client extends object,
    Models extends PrismaModelsConfig<Client> | undefined = undefined,
> = Models extends undefined
    ? HasDefaults<Client> extends true
        ? { client: Client; models?: undefined }
        : never
    : { client: Client; models: Models };

type ModelConfig<Models, Key extends keyof PrismaModelsConfig<object>> =
    Models extends Record<Key, infer Config> ? Config : Record<never, never>;

type ConfigTable<Config, Default extends string> = Config extends {
    table: infer Name extends string;
}
    ? Name
    : Default;

type ConfigSelect<Config, Default extends string> = Config extends {
    select: readonly (infer Field extends string)[];
}
    ? Field | Default
    : Default;

type SelectedModel<
    Client,
    Config,
    DefaultTable extends string,
    DefaultSelect extends string,
> = Pick<
    ModelRow<Client, ConfigTable<Config, DefaultTable>>,
    ConfigSelect<Config, DefaultSelect> & keyof ModelRow<Client, ConfigTable<Config, DefaultTable>>
>;

export type PrismaUser<
    Client,
    Models extends PrismaModelsConfig<Client> | undefined = undefined,
> = SelectedModel<Client, ModelConfig<Models, "users">, "users", "id" | "name">;

export type PrismaAccount<
    Client,
    Models extends PrismaModelsConfig<Client> | undefined = undefined,
> = SelectedModel<Client, ModelConfig<Models, "accounts">, "user_accounts", "email" | "id"> & {
    user: PrismaUser<Client, Models>;
};

export type PrismaDelegate = {
    create(args: unknown): Promise<unknown>;
    findFirst(args: unknown): Promise<unknown>;
    findMany(args: unknown): Promise<unknown>;
    findUnique(args: unknown): Promise<unknown>;
    update(args: unknown): Promise<unknown>;
    updateMany(args: unknown): Promise<unknown>;
};

export type PrismaAccessValue = AuthScalar | readonly AuthScalar[];

export type ResolvedPrismaDataModel = {
    access: Record<string, PrismaAccessValue>;
    select: readonly string[];
    table: string;
};

export type ResolvedPrismaModels = {
    accounts: ResolvedPrismaDataModel;
    sessions: string;
    socials: string;
    users: ResolvedPrismaDataModel;
};

export type PrismaDb<
    Client extends object,
    Models extends PrismaModelsConfig<Client> | undefined,
> = DbAdapter<PrismaAccount<Client, Models> & AuthAccount> &
    SocialDbAdapter<PrismaAccount<Client, Models> & AuthAccount>;

export type CreatePrismaAdapter = {
    <Client extends object>(input: PrismaAdapterInput<Client>): PrismaDb<Client, undefined>;
    <Client extends object, const Models extends PrismaModelsConfig<Client>>(
        input: PrismaAdapterInput<Client, Models>,
    ): PrismaDb<Client, Models>;
};

export type { AuthAccount };
