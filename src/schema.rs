//! Diesel schema file

table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
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

table! {
    sessions (id) {
        id -> Text,
        user_id -> Uuid,
        challenge -> Varchar,
        operation_type -> Varchar,
        user_verification -> Varchar,
        client_data -> Nullable<Text>,
        created_at -> Timestamp,
        expires_at -> Timestamp,
    }
}

joinable!(credentials -> users (user_id));
joinable!(sessions -> users (user_id));

allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    sessions,
);