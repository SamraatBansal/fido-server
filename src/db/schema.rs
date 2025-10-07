// @generated automatically by Diesel CLI.

diesel::table! {
    audit_logs (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        action -> Varchar,
        resource_type -> Nullable<Varchar>,
        resource_id -> Nullable<Varchar>,
        ip_address -> Nullable<Varchar>,
        user_agent -> Nullable<Text>,
        success -> Bool,
        error_message -> Nullable<Text>,
        metadata -> Nullable<Jsonb>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    auth_sessions (id) {
        id -> Uuid,
        session_id -> Varchar,
        challenge -> Bytea,
        user_id -> Nullable<Uuid>,
        session_type -> Varchar,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        data -> Nullable<Jsonb>,
        ip_address -> Nullable<Varchar>,
        user_agent -> Nullable<Text>,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        credential_public_key -> Bytea,
        aaguid -> Nullable<Bytea>,
        sign_count -> BigInt,
        user_verified -> Bool,
        backup_eligible -> Bool,
        backup_state -> Bool,
        attestation_format -> Nullable<Varchar>,
        attestation_statement -> Nullable<Jsonb>,
        transports -> Nullable<Array<Text>>,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
        is_resident -> Bool,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        email -> Nullable<Varchar>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        last_login_at -> Nullable<Timestamptz>,
        is_active -> Bool,
    }
}

diesel::joinable!(auth_sessions -> users (user_id));
diesel::joinable!(audit_logs -> users (user_id));
diesel::joinable!(credentials -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(audit_logs, auth_sessions, credentials, users,);
