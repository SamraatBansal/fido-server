//! @generated automatically by Diesel CLI.

diesel::table! {
    use diesel::sql_types::*;
    use crate::models::SqlTypes;

    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::models::SqlTypes;

    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        sign_count -> BigInt,
        attestation_format -> Nullable<Varchar>,
        aaguid -> Nullable<Bytea>,
        transports -> Nullable<Array<Text>>,
        created_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
        backup_eligible -> Bool,
        backup_state -> Bool,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::models::SqlTypes;

    sessions (id) {
        id -> Varchar,
        user_id -> Uuid,
        challenge -> Varchar,
        operation_type -> Varchar,
        user_verification -> Varchar,
        client_data -> Nullable<Text>,
        created_at -> Timestamp,
        expires_at -> Timestamp,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    sessions,
);