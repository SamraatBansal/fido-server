//! Diesel schema definitions

diesel::table! {
    use diesel::sql_types::*;
    use crate::db::models::UserVerificationTypeMapping;

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
    use crate::db::models::AttestationTypeMapping;

    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        sign_count -> Int8,
        attestation_type -> AttestationTypeMapping,
        transports -> Array<Text>,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
        backup_eligible -> Bool,
        backup_state -> Bool,
        user_verification_type -> UserVerificationTypeMapping,
        aaguid -> Nullable<Bytea>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    challenges (id) {
        id -> Uuid,
        challenge_hash -> Varchar,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        credential_id -> Nullable<Bytea>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
);