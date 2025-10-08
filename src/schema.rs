//! Diesel schema for FIDO2/WebAuthn server

table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_active -> Bool,
    }
}

table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        attestation_format -> Nullable<Varchar>,
        aaguid -> Nullable<Uuid>,
        sign_count -> BigInt,
        backup_eligible -> Bool,
        backup_state -> Bool,
        transports -> Nullable<Jsonb>,
        created_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
        is_active -> Bool,
    }
}

table! {
    challenges (id) {
        id -> Uuid,
        challenge_base64 -> Text,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        used_at -> Nullable<Timestamp>,
    }
}

joinable!(credentials -> users (user_id));
joinable!(challenges -> users (user_id));

allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
);