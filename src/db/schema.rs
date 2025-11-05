//! Database schema using Diesel

table! {
    users (id) {
        id -> Text,
        username -> Text,
        display_name -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    credentials (id) {
        id -> Text,
        user_id -> Text,
        public_key -> Bytea,
        sign_count -> Int4,
        created_at -> Timestamp,
        attestation_format -> Text,
        aaguid -> Nullable<Bytea>,
    }
}

table! {
    challenges (id) {
        id -> Text,
        challenge -> Text,
        username -> Text,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
);