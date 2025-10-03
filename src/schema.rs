//! Diesel database schema

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
        credential_id -> Varchar,
        public_key -> Bytea,
        sign_count -> BigInt,
        attestation_data -> Nullable<Bytea>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    user_mappings (id) {
        id -> Uuid,
        external_id -> Varchar,
        credential_id -> Varchar,
        user_id -> Uuid,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    challenges (id) {
        id -> Uuid,
        challenge -> Varchar,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    user_mappings,
    challenges,
);