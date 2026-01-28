//! Database models

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// User model
#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Credential model
#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: serde_json::Value,
    pub sign_count: i64,
    pub aaguid: Option<String>,
    pub attestation_statement: Option<serde_json::Value>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub clone_warning: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Challenge model
#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub challenge_data: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Session model
#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Audit log model
#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub success: bool,
    pub credential_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub error_message: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

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

// Implement required traits for custom types
impl diesel::sql_types::ops::Add for sql_types::Timestamptz {
    type Rhs = diesel::sql_types::Interval;
    type Output = sql_types::Timestamptz;
}

impl diesel::sql_types::ops::Sub for sql_types::Timestamptz {
    type Rhs = diesel::sql_types::Interval;
    type Output = sql_types::Timestamptz;
}