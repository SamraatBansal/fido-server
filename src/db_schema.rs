//! Diesel schema definitions

// @generated automatically by Diesel CLI.

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::{Uuid, Timestamptz};

    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::{Uuid, Jsonb, Timestamptz};

    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Varchar,
        public_key -> Jsonb,
        sign_count -> Int8,
        aaguid -> Nullable<Varchar>,
        attestation_statement -> Nullable<Jsonb>,
        backup_eligible -> Bool,
        backup_state -> Bool,
        clone_warning -> Bool,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::{Uuid, Jsonb, Timestamptz};

    challenges (id) {
        id -> Uuid,
        challenge_id -> Uuid,
        challenge_data -> Varchar,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamptz,
        used -> Bool,
        created_at -> Timestamptz,
        metadata -> Nullable<Jsonb>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::{Uuid, Timestamptz};

    sessions (id) {
        id -> Uuid,
        user_id -> Uuid,
        session_token -> Varchar,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        last_accessed_at -> Timestamptz,
        ip_address -> Nullable<Varchar>,
        user_agent -> Nullable<Varchar>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::{Uuid, Jsonb, Timestamptz};

    audit_logs (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        action -> Varchar,
        success -> Bool,
        credential_id -> Nullable<Varchar>,
        ip_address -> Nullable<Varchar>,
        user_agent -> Nullable<Varchar>,
        error_message -> Nullable<Varchar>,
        metadata -> Nullable<Jsonb>,
        created_at -> Timestamptz,
    }
}

diesel::joinable!(credentials -> users (user_id));
diesel::joinable!(sessions -> users (user_id));
diesel::joinable!(audit_logs -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
    sessions,
    audit_logs,
);

// Custom SQL types for Diesel
pub mod sql_types {
    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "uuid"))]
    pub struct Uuid;

    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "timestamptz"))]
    pub struct Timestamptz;

    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "jsonb"))]
    pub struct Jsonb;
}