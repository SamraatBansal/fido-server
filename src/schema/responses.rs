//! API response schemas

use serde::{Deserialize, Serialize};

/// Standard error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ErrorResponse {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Success response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse<T> {
    pub data: T,
    pub message: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl<T> SuccessResponse<T> {
    pub fn new(data: T) -> Self {
        Self {
            data,
            message: None,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn with_message(data: T, message: &str) -> Self {
        Self {
            data,
            message: Some(message.to_string()),
            timestamp: chrono::Utc::now(),
        }
    }
}