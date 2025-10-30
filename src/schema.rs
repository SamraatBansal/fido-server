// @generated automatically by Diesel CLI.

diesel::table! {
    challenges (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        challenge -> Text,
        challenge_type -> Text,
        expires_at -> Timestamp,
        used -> Bool,
        created_at -> Timestamp,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        sign_count -> Int8,
        attestation_format -> Text,
        attestation_data -> Nullable<Bytea>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Text,
        display_name -> Text,
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