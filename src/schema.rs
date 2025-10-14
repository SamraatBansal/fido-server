//! Database schema definitions for Diesel ORM

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        email -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_active -> Bool,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        credential_public_key -> Bytea,
        sign_count -> Int8,
        attestation_format -> Varchar,
        attestation_statement -> Bytea,
        aaguid -> Bytea,
        transports -> Array<Text>,
        backup_eligible -> Bool,
        backup_state -> Bool,
        user_verified -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_active -> Bool,
    }
}

diesel::table! {
    challenges (id) {
        id -> Uuid,
        challenge -> Varchar,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        used -> Bool,
    }
}

diesel::table! {
    attestation_metadata (id) {
        id -> Uuid,
        aaguid -> Bytea,
        metadata_statement -> Bytea,
        status_report -> Array<Text>,
        last_updated -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::table! {
    audit_logs (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        action -> Varchar,
        resource -> Varchar,
        ip_address -> Inet,
        user_agent -> Text,
        success -> Bool,
        error_message -> Nullable<Text>,
        created_at -> Timestamp,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
    attestation_metadata,
    audit_logs,
);