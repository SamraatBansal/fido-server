// @generated automatically by Diesel CLI.

diesel::table! {
    challenges (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        challenge_data -> Bytea,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        sign_count -> Int8,
        transports -> Nullable<Text>,
        created_at -> Timestamptz,
        last_used -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(challenges -> users (user_id));
diesel::joinable!(credentials -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    challenges,
    credentials,
    users,
);