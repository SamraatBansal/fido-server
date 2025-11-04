// @generated automatically by Diesel CLI.

diesel::table! {
    challenges (id) {
        id -> Uuid,
        challenge -> Varchar,
        #[max_length = 255]
        username -> Nullable<Varchar>,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Varchar,
        public_key -> Bytea,
        sign_count -> Int4,
        #[max_length = 50]
        attestation_type -> Nullable<Varchar>,
        aaguid -> Nullable<Bytea>,
        transports -> Nullable<Jsonb>,
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

diesel::allow_tables_to_appear_in_same_query!(
    challenges,
    credentials,
    users,
);