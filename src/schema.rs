//! Diesel schema definitions

// @generated automatically by Diesel CLI.

diesel::table! {
    use diesel::sql_types::*;
    use crate::db::models::sql_types::*;

    users (id) {
        id -> crate::db::models::sql_types::Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> crate::db::models::sql_types::Timestamptz,
        updated_at -> crate::db::models::sql_types::Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::db::models::sql_types::*;

    credentials (id) {
        id -> crate::db::models::sql_types::Uuid,
        user_id -> crate::db::models::sql_types::Uuid,
        credential_id -> Varchar,
        public_key -> crate::db::models::sql_types::Jsonb,
        sign_count -> Int8,
        aaguid -> Nullable<Varchar>,
        attestation_statement -> Nullable<crate::db::models::sql_types::Jsonb>,
        backup_eligible -> Bool,
        backup_state -> Bool,
        clone_warning -> Bool,
        created_at -> crate::db::models::sql_types::Timestamptz,
        last_used_at -> Nullable<crate::db::models::sql_types::Timestamptz>,
        updated_at -> crate::db::models::sql_types::Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::db::models::sql_types::*;

    challenges (id) {
        id -> crate::db::models::sql_types::Uuid,
        challenge_id -> crate::db::models::sql_types::Uuid,
        challenge_data -> Varchar,
        user_id -> Nullable<crate::db::models::sql_types::Uuid>,
        challenge_type -> Varchar,
        expires_at -> crate::db::models::sql_types::Timestamptz,
        used -> Bool,
        metadata -> Nullable<crate::db::models::sql_types::Jsonb>,
        created_at -> crate::db::models::sql_types::Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::db::models::sql_types::*;

    sessions (id) {
        id -> crate::db::models::sql_types::Uuid,
        user_id -> crate::db::models::sql_types::Uuid,
        session_token -> Varchar,
        expires_at -> crate::db::models::sql_types::Timestamptz,
        created_at -> crate::db::models::sql_types::Timestamptz,
        last_accessed_at -> crate::db::models::sql_types::Timestamptz,
        ip_address -> Nullable<Varchar>,
        user_agent -> Nullable<Varchar>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::db::models::sql_types::*;

    audit_logs (id) {
        id -> crate::db::models::sql_types::Uuid,
        user_id -> Nullable<crate::db::models::sql_types::Uuid>,
        action -> Varchar,
        success -> Bool,
        credential_id -> Nullable<Varchar>,
        ip_address -> Nullable<Varchar>,
        user_agent -> Nullable<Varchar>,
        error_message -> Nullable<Varchar>,
        metadata -> Nullable<crate::db::models::sql_types::Jsonb>,
        created_at -> crate::db::models::sql_types::Timestamptz,
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