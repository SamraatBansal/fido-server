table! {
    use diesel::sql_types::*;
    use uuid::Uuid;

    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        email -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    use diesel::sql_types::*;
    use uuid::Uuid;

    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        sign_count -> BigInt,
        attestation_format -> Varchar,
        attestation_data -> Nullable<Bytea>,
        transports -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    use diesel::sql_types::*;
    use uuid::Uuid;

    challenges (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        challenge -> Varchar,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
);