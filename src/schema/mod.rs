// @generated automatically by Diesel CLI.

diesel::table! {
    challenges (id) {
        id -> Uuid,
        challenge -> Bytea,
        username -> Nullable<Varchar>,
        challenge_type -> Varchar,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        used_at -> Nullable<Timestamptz>,
        is_used -> Bool,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        credential_public_key -> Bytea,
        attestation_type -> Varchar,
        aaguid -> Bytea,
        sign_count -> Int8,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
        is_backup_eligible -> Bool,
        is_backed_up -> Bool,
        transports -> Nullable<Array<Varchar>>,
        user_verification_requirement -> Varchar,
        is_active -> Bool,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        is_active -> Bool,
    }
}

diesel::joinable!(credentials -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    challenges,
    credentials,
    users,
);