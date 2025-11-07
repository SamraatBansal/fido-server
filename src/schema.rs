// @generated automatically by Diesel CLI.

diesel::table! {
    challenges (id) {
        id -> Uuid,
        challenge -> Bytea,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        session_id -> Nullable<Varchar>,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
        consumed -> Bool,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        counter -> Int8,
        aaguid -> Nullable<Uuid>,
        credential_type -> Varchar,
        transports -> Nullable<Array<Text>>,
        backup_eligible -> Nullable<Bool>,
        backup_state -> Nullable<Bool>,
        attestation_type -> Nullable<Varchar>,
        created_at -> Timestamptz,
        last_used -> Nullable<Timestamptz>,
        active -> Bool,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        user_id -> Bytea,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        active -> Bool,
    }
}

diesel::joinable!(challenges -> users (user_id));
diesel::joinable!(credentials -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    challenges,
    credentials,
    users,
);