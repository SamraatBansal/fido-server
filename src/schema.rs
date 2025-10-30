// @generated automatically by Diesel CLI.

diesel::table! {
    challenges (id) {
        id -> Text,
        user_id -> Nullable<Text>,
        challenge -> Text,
        challenge_type -> Text,
        expires_at -> Text,
        used -> Bool,
        created_at -> Text,
    }
}

diesel::table! {
    credentials (id) {
        id -> Text,
        user_id -> Text,
        credential_id -> Blob,
        public_key -> Blob,
        sign_count -> Integer,
        attestation_format -> Text,
        attestation_data -> Nullable<Blob>,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    users (id) {
        id -> Text,
        username -> Text,
        display_name -> Text,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::joinable!(credentials -> users (user_id));
diesel::joinable!(challenges -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    challenges,
    credentials,
    users,
);