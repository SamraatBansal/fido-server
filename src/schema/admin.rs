//! Admin API request and response schemas

use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::schema::common::{PaginationParams, PaginatedResponse};
use chrono::{DateTime, Utc};

/// Request to list all users
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ListUsersRequest {
    /// Pagination parameters
    #[serde(flatten)]
    pub pagination: PaginationParams,
    /// Filter by username (optional)
    #[validate(length(min = 1))]
    pub username_filter: Option<String>,
    /// Sort by field
    #[serde(default = "default_sort_field")]
    pub sort_by: String,
    /// Sort order
    #[serde(default = "default_sort_order")]
    pub sort_order: String,
}

fn default_sort_field() -> String {
    "created_at".to_string()
}

fn default_sort_order() -> String {
    "desc".to_string()
}

/// Response for listing users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUsersResponse {
    pub users: Vec<UserInfo>,
    pub pagination: crate::schema::common::PaginationInfo,
}

/// User information for admin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// User ID
    pub id: uuid::Uuid,
    /// Username
    pub username: String,
    /// Display name
    pub display_name: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Number of credentials
    pub credential_count: i64,
    /// Last authentication timestamp
    pub last_authenticated_at: Option<DateTime<Utc>>,
    /// Account status
    pub status: UserStatus,
}

/// User status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Inactive,
    Suspended,
}

/// Request to get user details
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct GetUserDetailsRequest {
    /// User ID
    #[validate(uuid)]
    pub user_id: uuid::Uuid,
}

/// Response for user details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserDetailsResponse {
    /// User information
    pub user: UserInfo,
    /// User credentials
    pub credentials: Vec<crate::schema::credentials::CredentialInfo>,
    /// Recent audit logs
    pub recent_audit_logs: Vec<AuditLogInfo>,
}

/// Audit log information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogInfo {
    /// Log ID
    pub id: uuid::Uuid,
    /// Action
    pub action: String,
    /// Success status
    pub success: bool,
    /// Timestamp
    pub created_at: DateTime<Utc>,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Error message
    pub error_message: Option<String>,
}

/// Request to list audit logs
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ListAuditLogsRequest {
    /// Pagination parameters
    #[serde(flatten)]
    pub pagination: PaginationParams,
    /// Filter by user ID (optional)
    #[validate(uuid)]
    pub user_id: Option<uuid::Uuid>,
    /// Filter by action (optional)
    #[validate(length(min = 1))]
    pub action_filter: Option<String>,
    /// Filter by success status (optional)
    pub success_filter: Option<bool>,
    /// Start date filter (optional)
    pub start_date: Option<DateTime<Utc>>,
    /// End date filter (optional)
    pub end_date: Option<DateTime<Utc>>,
}

/// Response for audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAuditLogsResponse {
    pub audit_logs: Vec<AuditLogInfo>,
    pub pagination: crate::schema::common::PaginationInfo,
}

/// Request to get system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSystemStatsRequest {
    /// Time range in days (default: 30)
    #[serde(default = "default_time_range")]
    pub time_range_days: u32,
}

fn default_time_range() -> u32 {
    30
}

/// Response for system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSystemStatsResponse {
    /// Overview statistics
    pub overview: OverviewStats,
    /// Registration statistics
    pub registrations: RegistrationStats,
    /// Authentication statistics
    pub authentications: AuthenticationStats,
    /// Credential statistics
    pub credentials: CredentialStats,
    /// System health
    pub system_health: SystemHealthStats,
}

/// Overview statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewStats {
    /// Total users
    pub total_users: i64,
    /// Total credentials
    pub total_credentials: i64,
    /// Active sessions
    pub active_sessions: i64,
    /// Total authentications (in time range)
    pub total_authentications: i64,
}

/// Registration statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStats {
    /// New registrations (in time range)
    pub new_registrations: i64,
    /// Registration success rate
    pub success_rate: f64,
    /// Registrations by day
    pub registrations_by_day: Vec<DailyCount>,
}

/// Authentication statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStats {
    /// Total authentications (in time range)
    pub total_authentications: i64,
    /// Authentication success rate
    pub success_rate: f64,
    /// Authentications by day
    pub authentications_by_day: Vec<DailyCount>,
    /// Unique users authenticated
    pub unique_users: i64,
}

/// Credential statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStats {
    /// Credentials by type
    pub credentials_by_type: Vec<TypeCount>,
    /// Backup enabled credentials
    pub backup_enabled: i64,
    /// Clone warnings
    pub clone_warnings: i64,
}

/// System health statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthStats {
    /// Database status
    pub database_status: String,
    /// Database connection pool usage
    pub db_pool_usage: f64,
    /// Active challenges
    pub active_challenges: i64,
    /// Expired challenges cleaned
    pub expired_challenges_cleaned: i64,
}

/// Daily count for statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyCount {
    pub date: String,
    pub count: i64,
}

/// Type count for statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeCount {
    pub r#type: String,
    pub count: i64,
}

/// Request to cleanup expired data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupExpiredDataRequest {
    /// Dry run (don't actually delete)
    #[serde(default)]
    pub dry_run: bool,
}

/// Response for cleanup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupExpiredDataResponse {
    /// Challenges cleaned
    pub challenges_cleaned: i64,
    /// Sessions cleaned
    pub sessions_cleaned: i64,
    /// Whether cleanup was successful
    pub success: bool,
    /// Message
    pub message: String,
}