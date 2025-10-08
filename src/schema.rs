//! Diesel database schema

// @generated automatically by Diesel CLI.

diesel::table! {
    challenges (id) {
        id -> Uuid,
        challenge_id -> Bytea,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        credential_public_key -> Bytea,
        aaguid -> Bytea,
        sign_count -> Int8,
        user_verification -> Bool,
        backup_eligible -> Bool,
        backup_state -> Bool,
        attestation_type -> Varchar,
        transports -> Array<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::joinable!(credentials -> users (user_id));
diesel::joinable!(challenges -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    challenges,
    credentials,
    users,
);