//! Request/Response schemas

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Start authentication request
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticationStartRequest {
    pub username: Option<String>,
    pub user_verification: Option<String>,
    pub origin: Option<String>,
}

/// Finish authentication request
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticationFinishRequest {
    pub challenge_id: Uuid,
    pub credential: serde_json::Value,
}

/// Start registration request
#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
    pub user_verification: Option<String>,
    pub attestation: Option<String>,
    pub origin: Option<String>,
}

/// Finish registration request
#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationFinishRequest {
    pub challenge_id: Uuid,
    pub credential: serde_json::Value,
}

/// Standard API response
#[derive(Debug, Deserialize, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: None,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            message: None,
        }
    }

    pub fn message(message: String) -> Self {
        Self {
            success: true,
            data: None,
            error: None,
            message: Some(message),
        }
    }
}

/// Pagination parameters
#[derive(Debug, Deserialize, Serialize)]
pub struct PaginationParams {
    pub page: Option<u32>,
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

pub mod auth {
    pub use super::{
        AuthenticationStartRequest, AuthenticationFinishRequest,
        RegistrationStartRequest, RegistrationFinishRequest
    };
}

pub mod common {
    pub use super::{ApiResponse, PaginationParams};
}