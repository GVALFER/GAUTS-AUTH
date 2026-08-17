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

type IsRelationModel<T> =
    IsSessionModel<T> extends true ? false : DelegateRow<T> extends { id: string } ? true : false;

type IsAccountModel<T> =
    IsSessionModel<T> extends true
        ? false
        : DelegateRow<T> extends {
                email: string;
                id: string;
            }
          ? true
          : false;

type IsDefaultAccountModel<T> =
    IsAccountModel<T> extends true
        ? DelegateRow<T> extends { password_hash: string }
            ? true
            : false
        : false;

export type PrismaSessionModel<Client> = {
    [Key in keyof Client]: IsSessionModel<Client[Key]> extends true ? Key : never;
}[keyof Client] &
    string;

export type PrismaAccountModel<Client> = {
    [Key in keyof Client]: IsAccountModel<Client[Key]> extends true ? Key : never;
}[keyof Client] &
    string;

type PrismaRelationModel<Client> = {
    [Key in keyof Client]: IsRelationModel<Client[Key]> extends true ? Key : never;
}[keyof Client] &
    string;

type ModelRow<Client, Name extends string> = Name extends keyof Client
    ? DelegateRow<Client[Name]>
    : never;

type AuthField<Row> = {
    [Key in keyof Row]: Row[Key] extends AuthScalar ? Key : never;
}[keyof Row] &
    string;

type AccessRule<Value> = [Value] extends [AuthScalar] ? Value | readonly Value[] : never;

type ModelAccess<Row> = Partial<{
    [Key in AuthField<Row>]: AccessRule<Row[Key]>;
}>;

type ModelConfig<Client, Name extends string, NameRequired extends boolean> = {
    access?: ModelAccess<ModelRow<Client, Name>>;
    relations?: PrismaRelations<Client>;
    select?: readonly AuthField<ModelRow<Client, Name>>[];
} & (NameRequired extends true ? { name: Name } : { name?: Name });

type ModelChoice<Client, NameRequired extends boolean> = {
    [Name in PrismaRelationModel<Client>]: ModelConfig<Client, Name, NameRequired>;
}[PrismaRelationModel<Client>];

type AccountChoice<Client, NameRequired extends boolean> = {
    [Name in PrismaAccountModel<Client>]: ModelConfig<Client, Name, NameRequired>;
}[PrismaAccountModel<Client>];

type DefaultAccountConfig<Client> = "account" extends keyof Client
    ? IsDefaultAccountModel<Client["account"]> extends true
        ? Omit<ModelConfig<Client, "account", false>, "name"> & {
              name?: "account";
          }
        : never
    : never;

type CustomAccountConfig<Client> = AccountChoice<Client, true>;

export type PrismaAccountConfig<Client> =
    DefaultAccountConfig<Client> | CustomAccountConfig<Client>;

export type PrismaRelations<Client> = Record<string, ModelChoice<Client, false>>;

type DefaultSessionConfig<Client> =
    "sessions" extends PrismaSessionModel<Client> ? { name?: "sessions" } : never;

type CustomSessionConfig<Client> = {
    [Name in PrismaSessionModel<Client>]: { name: Name };
}[PrismaSessionModel<Client>];

export type PrismaSessionConfig<Client> =
    DefaultSessionConfig<Client> | CustomSessionConfig<Client>;

type AccountProperty<Client> = "account" extends keyof Client
    ? IsDefaultAccountModel<Client["account"]> extends true
        ? { account?: PrismaAccountConfig<Client> }
        : { account: CustomAccountConfig<Client> }
    : { account: CustomAccountConfig<Client> };

type SessionProperty<Client> =
    "sessions" extends PrismaSessionModel<Client>
        ? { sessions?: PrismaSessionConfig<Client> }
        : { sessions: CustomSessionConfig<Client> };

export type PrismaModelsConfig<Client> = AccountProperty<Client> & SessionProperty<Client>;

type HasDefaults<Client> = "account" extends keyof Client
    ? IsDefaultAccountModel<Client["account"]> extends true
        ? "sessions" extends PrismaSessionModel<Client>
            ? true
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

type ConfigName<Config, Default extends string> = Config extends { name: infer Name extends string }
    ? Name
    : Default;

type ConfigSelect<Config, Default extends string> = Config extends {
    select: readonly (infer Field extends string)[];
}
    ? Field | "id"
    : Default;

type ConfigRelations<Config> = Config extends { relations: infer Relations }
    ? Relations
    : Record<never, never>;

type SelectedModel<
    Client,
    Config,
    DefaultName extends string,
    DefaultSelect extends string = "id",
> =
    ConfigName<Config, DefaultName> extends infer Name extends string
        ? Pick<
              ModelRow<Client, Name>,
              ConfigSelect<Config, DefaultSelect> & keyof ModelRow<Client, Name>
          > & {
              [
                  Relation in keyof ConfigRelations<Config>
              ]: ConfigRelations<Config>[Relation] extends infer RelationConfig
                  ? SelectedModel<Client, RelationConfig, Relation & string>
                  : never;
          }
        : never;

type ModelsAccount<Models> = Models extends { account: infer Account }
    ? Account
    : Record<never, never>;

export type PrismaAccount<
    Client,
    Models extends PrismaModelsConfig<Client> | undefined = undefined,
> = SelectedModel<Client, ModelsAccount<Models>, "account", "id" | "email"> & {
    id: string;
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

export type ResolvedPrismaModel = {
    access: Record<string, PrismaAccessValue>;
    name: string;
    relation: string;
    relations: Record<string, ResolvedPrismaModel>;
    select: readonly string[];
};

export type ResolvedPrismaModels = {
    account: ResolvedPrismaModel;
    sessions: string;
};

export type PrismaDb<
    Client extends object,
    Models extends PrismaModelsConfig<Client> | undefined,
> = DbAdapter<PrismaAccount<Client, Models>>;

export type CreatePrismaAdapter = {
    <Client extends object>(input: PrismaAdapterInput<Client>): PrismaDb<Client, undefined>;
    <Client extends object, const Models extends PrismaModelsConfig<Client>>(
        input: PrismaAdapterInput<Client, Models>,
    ): PrismaDb<Client, Models>;
};

export type { AuthAccount };
