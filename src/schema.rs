// @generated automatically by Diesel CLI.

diesel::table! {
    challenge_states (id) {
        id -> Uuid,
        challenge -> Bytea,
        user_id -> Nullable<Uuid>,
        operation -> Varchar,
        state_data -> Jsonb,
        expires_at -> Timestamptz,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    credentials (id) {
        id -> Bytea,
        user_id -> Uuid,
        public_key -> Bytea,
        sign_count -> Int8,
        credential_type -> Varchar,
        transports -> Nullable<Array<Nullable<Text>>>,
        backup_eligible -> Bool,
        backup_state -> Bool,
        attestation_type -> Nullable<Varchar>,
        attestation_trust_path -> Nullable<Jsonb>,
        created_at -> Nullable<Timestamptz>,
        last_used_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        user_id -> Bytea,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(challenge_states -> users (user_id));
diesel::joinable!(credentials -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    challenge_states,
    credentials,
    users,
);