//! Common schema types

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use validator::Validate;

/// Standard API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<ApiError>,
    pub timestamp: DateTime<Utc>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
        }
    }

    pub fn error(error: ApiError) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            timestamp: Utc::now(),
        }
    }
}

/// API error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            details: None,
        }
    }

    pub fn with_details(code: &str, message: &str, details: serde_json::Value) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            details: Some(details),
        }
    }
}

/// Pagination parameters
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PaginationParams {
    /// Page number (1-based)
    #[validate(range(min = 1))]
    pub page: Option<u32>,
    /// Items per page
    #[validate(range(min = 1, max = 100))]
    pub limit: Option<u32>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: Some(1),
            limit: Some(20),
        }
    }
}

impl PaginationParams {
    pub fn offset(&self) -> i64 {
        let page = self.page.unwrap_or(1) as i64;
        let limit = self.limit.unwrap_or(20) as i64;
        (page - 1) * limit
    }

    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(20) as i64
    }
}

/// Paginated response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: PaginationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationInfo {
    pub page: u32,
    pub limit: u32,
    pub total: u64,
    pub total_pages: u32,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, page: u32, limit: u32, total: u64) -> Self {
        let total_pages = ((total as f64) / (limit as f64)).ceil() as u32;
        
        Self {
            items,
            pagination: PaginationInfo {
                page,
                limit,
                total,
                total_pages,
            },
        }
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub checks: HealthChecks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthChecks {
    pub database: HealthCheckStatus,
    pub webauthn: HealthCheckStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckStatus {
    pub status: String,
    pub message: Option<String>,
    pub response_time_ms: Option<u64>,
}

/// User verification policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationPolicy {
    Required,
    Preferred,
    Discouraged,
}

impl Default for UserVerificationPolicy {
    fn default() -> Self {
        Self::Preferred
    }
}

impl From<UserVerificationPolicy> for webauthn_rs::prelude::UserVerificationPolicy {
    fn from(policy: UserVerificationPolicy) -> Self {
        match policy {
            UserVerificationPolicy::Required => Self::Required,
            UserVerificationPolicy::Preferred => Self::Preferred,
            UserVerificationPolicy::Discouraged => Self::Discouraged,
        }
    }
}

/// Attestation conveyance preference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
}

impl Default for AttestationConveyancePreference {
    fn default() -> Self {
        Self::Direct
    }
}

impl From<AttestationConveyancePreference> for webauthn_rs::prelude::AttestationConveyancePreference {
    fn from(pref: AttestationConveyancePreference) -> Self {
        match pref {
            AttestationConveyancePreference::None => Self::None,
            AttestationConveyancePreference::Indirect => Self::Indirect,
            AttestationConveyancePreference::Direct => Self::Direct,
            AttestationConveyancePreference::Enterprise => Self::Enterprise,
        }
    }
}

/// Authenticator attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

/// Resident key requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}

impl Default for ResidentKeyRequirement {
    fn default() -> Self {
        Self::Discouraged
    }
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub require_resident_key: Option<bool>,
    pub user_verification: UserVerificationPolicy,
}

impl Default for AuthenticatorSelectionCriteria {
    fn default() -> Self {
        Self {
            authenticator_attachment: None,
            require_resident_key: Some(false),
            user_verification: UserVerificationPolicy::Preferred,
        }
    }
}

impl From<AuthenticatorSelectionCriteria> for webauthn_rs::prelude::AuthenticatorSelectionCriteria {
    fn from(criteria: AuthenticatorSelectionCriteria) -> Self {
        Self {
            authenticator_attachment: criteria.authenticator_attachment.map(|a| match a {
                AuthenticatorAttachment::Platform => webauthn_rs::prelude::AuthenticatorAttachment::Platform,
                AuthenticatorAttachment::CrossPlatform => webauthn_rs::prelude::AuthenticatorAttachment::CrossPlatform,
            }),
            require_resident_key: criteria.require_resident_key.unwrap_or(false),
            user_verification: criteria.user_verification.into(),
        }
    }
}