import { getTableColumns } from "drizzle-orm";
import type { MySqlColumn, SelectedFieldsFlat } from "drizzle-orm/mysql-core";
import { isRecord } from "../../session/guards.js";
import type { AuthSessionRecord, SessionRecord } from "../../session/types.js";
import { readAdapterAccount, requireSessionRecord, requireSessionRecords } from "../model.js";
import { DRIZZLE_FIELDS, getDrizzleSource } from "./config.js";
import type { ResolvedDrizzleDataModel, ResolvedDrizzleModels } from "./types.js";

type ReadAccountInput = {
    models: ResolvedDrizzleModels;
    value: unknown;
};

type CreateModelSelectInput = {
    model: ResolvedDrizzleDataModel;
};

type PickColumnsInput = {
    fields: readonly string[];
    model: ResolvedDrizzleDataModel;
};

const pickColumns = ({ fields, model }: PickColumnsInput): SelectedFieldsFlat => {
    const columns = getTableColumns(model.table) as Record<string, MySqlColumn>;

    return Object.fromEntries(fields.map((field) => [field, columns[field]])) as SelectedFieldsFlat;
};

export const createModelSelect = ({ model }: CreateModelSelectInput): SelectedFieldsFlat => {
    return pickColumns({
        fields: [...new Set([...model.select, ...Object.keys(model.access)])],
        model,
    });
};

export const createSessionSelect = (models: ResolvedDrizzleModels): SelectedFieldsFlat => {
    return pickColumns({
        fields: DRIZZLE_FIELDS.sessions.filter((field) => field !== "country"),
        model: {
            access: {},
            select: [],
            table: models.sessions,
        },
    });
};

export const readAccount = ({ models, value }: ReadAccountInput) => {
    if (!isRecord(value)) {
        throw new Error("Drizzle account relation returned invalid data.");
    }

    return readAdapterAccount({
        account: value.account,
        accounts: {
            ...models.accounts,
            source: getDrizzleSource(models.accounts.table),
        },
        adapter: "Drizzle",
        user: value.user,
        users: {
            ...models.users,
            source: getDrizzleSource(models.users.table),
        },
    });
};

export const requireRow = (value: unknown): SessionRecord => {
    return requireSessionRecord({ adapter: "Drizzle", value });
};

export const requireRows = (value: unknown): SessionRecord[] => {
    return requireSessionRecords({ adapter: "Drizzle", value });
};

export const requireAuthRow = ({ models, value }: ReadAccountInput): AuthSessionRecord => {
    if (!isRecord(value)) {
        throw new Error("Drizzle session table returned invalid data.");
    }

    const session = requireRow(value.session);
    const resolved = readAccount({ models, value });

    return {
        ...session,
        account: resolved.account,
        allowed: resolved.allowed,
    };
};
