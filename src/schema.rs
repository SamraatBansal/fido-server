// @generated automatically by Diesel CLI.

diesel::table! {
    authentication_challenges (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        challenge -> Bytea,
        state_data -> Bytea,
        expires_at -> Timestamp,
        created_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        sign_count -> Int8,
        backup_eligible -> Bool,
        backup_state -> Bool,
        attestation_format -> Nullable<Varchar>,
        created_at -> Nullable<Timestamp>,
        last_used_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    registration_challenges (id) {
        id -> Uuid,
        user_id -> Uuid,
        challenge -> Bytea,
        state_data -> Bytea,
        expires_at -> Timestamp,
        created_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        user_handle -> Bytea,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::joinable!(authentication_challenges -> users (user_id));
diesel::joinable!(credentials -> users (user_id));
diesel::joinable!(registration_challenges -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    authentication_challenges,
    credentials,
    registration_challenges,
    users,
);