import type { MySqlDatabase } from "drizzle-orm/mysql-core/db";
import type { MySqlQueryResultHKT, PreparedQueryHKTBase } from "drizzle-orm/mysql-core/session";
import type { AnyMySqlTable } from "drizzle-orm/mysql-core/table";
import type { AdapterAccessValue } from "../model.js";
import type { SocialDbAdapter } from "../../social/types.js";
import type { AuthAccount, AuthScalar, DbAdapter, SessionRecord } from "../../session/types.js";

export type DrizzleClient = MySqlDatabase<
    MySqlQueryResultHKT,
    PreparedQueryHKTBase,
    Record<string, unknown>
>;

type TableRow<Table extends AnyMySqlTable> = Table["$inferSelect"];

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

export type DrizzleDataModelConfig<Table extends AnyMySqlTable> = {
    access?: ModelAccess<TableRow<Table>>;
    select?: readonly AuthField<TableRow<Table>>[];
    table: Table;
};

export type DrizzleTableModelConfig<Table extends AnyMySqlTable> = {
    table: Table;
};

type UserRow = {
    id: string;
    name: string;
};

type AccountRow = {
    email: string;
    id: string;
    user_id: string;
};

type SessionRow = SessionRecord & {
    country: string | null;
};

type SocialRow = {
    account_id: string;
    created_at: Date;
    id: string;
    provider: string;
    provider_id: string;
};

type DataModelInput = {
    access?: Record<string, AdapterAccessValue>;
    select?: readonly string[];
    table: AnyMySqlTable;
};

type TableModelInput = {
    table: AnyMySqlTable;
};

export type DrizzleModelsConfig = {
    accounts: DataModelInput;
    sessions: TableModelInput;
    socials?: TableModelInput;
    users: DataModelInput;
};

type ValidateDataModel<Config, Required> = Config extends {
    table: infer Table extends AnyMySqlTable;
}
    ? TableRow<Table> extends Required
        ? DrizzleDataModelConfig<Table>
        : never
    : never;

type ValidateTableModel<Config, Required> = Config extends {
    table: infer Table extends AnyMySqlTable;
}
    ? TableRow<Table> extends Required
        ? DrizzleTableModelConfig<Table>
        : never
    : never;

type ValidatedModels<Models extends DrizzleModelsConfig> = {
    accounts: ValidateDataModel<Models["accounts"], AccountRow>;
    sessions: ValidateTableModel<Models["sessions"], SessionRow>;
    users: ValidateDataModel<Models["users"], UserRow>;
} & (Models extends { socials: infer Socials }
    ? { socials: ValidateTableModel<Socials, SocialRow> }
    : { socials?: undefined });

export type DrizzleAdapterInput<Models extends DrizzleModelsConfig> = {
    client: DrizzleClient;
    models: Models & ValidatedModels<Models>;
};

type ConfigSelect<Config, Default extends string> = Config extends {
    select: readonly (infer Field extends string)[];
}
    ? Field | Default
    : Default;

type SelectedModel<Config, Default extends string> = Config extends {
    table: infer Table extends AnyMySqlTable;
}
    ? Pick<TableRow<Table>, ConfigSelect<Config, Default> & keyof TableRow<Table>>
    : never;

export type DrizzleUser<Models> = Models extends { users: infer Config }
    ? SelectedModel<Config, "id" | "name">
    : never;

export type DrizzleAccount<Models> = Models extends { accounts: infer Config }
    ? SelectedModel<Config, "email" | "id"> & { user: DrizzleUser<Models> }
    : never;

export type DrizzleDb<Models extends DrizzleModelsConfig> = DbAdapter<
    DrizzleAccount<Models> & AuthAccount
> &
    (Models extends { socials: TableModelInput }
        ? SocialDbAdapter<DrizzleAccount<Models> & AuthAccount>
        : object);

export type ResolvedDrizzleDataModel = {
    access: Record<string, AdapterAccessValue>;
    select: readonly string[];
    table: AnyMySqlTable;
};

export type ResolvedDrizzleModels = {
    accounts: ResolvedDrizzleDataModel;
    sessions: AnyMySqlTable;
    socials: AnyMySqlTable | null;
    users: ResolvedDrizzleDataModel;
};

export type CreateDrizzleAdapter = <const Models extends DrizzleModelsConfig>(
    input: DrizzleAdapterInput<Models>,
) => DrizzleDb<Models>;
