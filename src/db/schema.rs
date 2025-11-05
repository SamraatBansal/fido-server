//! Database schema using Diesel

diesel::table! {
    users (id) {
        id -> Text,
        username -> Text,
        display_name -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    credentials (id) {
        id -> Text,
        user_id -> Text,
        public_key -> Bytea,
        sign_count -> Int4,
        created_at -> Timestamptz,
        attestation_format -> Text,
        aaguid -> Nullable<Bytea>,
    }
}

diesel::table! {
    challenges (id) {
        id -> Text,
        challenge -> Text,
        username -> Text,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
);