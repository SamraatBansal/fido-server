//! Database Schema
//! 
//! Diesel schema definitions for FIDO2/WebAuthn server

table! {
    use diesel::sql_types::*;
    use crate::db::models::sql_types::*;

    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        credential_public_key -> Bytea,
        attestation_type -> Varchar,
        aaguid -> Nullable<Uuid>,
        sign_count -> Int8,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
        transports -> Nullable<Jsonb>,
        backup_eligible -> Bool,
        backup_state -> Bool,
    }
}

table! {
    challenges (id) {
        id -> Uuid,
        challenge -> Bytea,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

table! {
    auth_sessions (id) {
        id -> Uuid,
        user_id -> Uuid,
        session_token -> Varchar,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
        last_activity_at -> Timestamptz,
        status -> Varchar,
    }
}

table! {
    audit_logs (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        event_type -> Varchar,
        description -> Varchar,
        ip_address -> Nullable<Varchar>,
        user_agent -> Nullable<Varchar>,
        created_at -> Timestamptz,
        metadata -> Nullable<Jsonb>,
    }
}

allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
    auth_sessions,
    audit_logs,
);

#[derive(diesel::sql_types::SqlType)]
#[diesel(postgres_type(name = "uuid"))]
pub struct Uuid;

#[derive(diesel::sql_types::SqlType)]
#[diesel(postgres_type(name = "timestamptz"))]
pub struct Timestamptz;

#[derive(diesel::sql_types::SqlType)]
#[diesel(postgres_type(name = "jsonb"))]
pub struct Jsonb;