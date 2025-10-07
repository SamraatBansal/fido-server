//! Common schema definitions

use serde::{Deserialize, Serialize};

/// API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub status: u16,
    pub timestamp: Option<String>,
    pub request_id: Option<String>,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
}

/// API success response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub status: String,
    pub message: Option<String>,
}

/// Validation error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

/// Detailed error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedErrorResponse {
    pub error: ErrorDetails,
    pub timestamp: String,
    pub request_id: String,
}

/// Error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetails {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    /// Create a new error response
    pub fn new(error: String, status: u16) -> Self {
        Self {
            error,
            status,
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
            request_id: Some(uuid::Uuid::new_v4().to_string()),
        }
    }

    /// Create a bad request error
    pub fn bad_request(message: &str) -> Self {
        Self::new(message.to_string(), 400)
    }

    /// Create a not found error
    pub fn not_found(message: &str) -> Self {
        Self::new(message.to_string(), 404)
    }

    /// Create an internal server error
    pub fn internal_error(message: &str) -> Self {
        Self::new(message.to_string(), 500)
    }
}

impl HealthResponse {
    /// Create a new health response
    pub fn new(version: String) -> Self {
        Self {
            status: "healthy".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            version,
        }
    }

    /// Create an unhealthy response
    pub fn unhealthy(version: String) -> Self {
        Self {
            status: "unhealthy".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            version,
        }
    }
}

impl SuccessResponse {
    /// Create a new success response
    pub fn new() -> Self {
        Self {
            status: "success".to_string(),
            message: None,
        }
    }

    /// Create a success response with a message
    pub fn with_message(message: &str) -> Self {
        Self {
            status: "success".to_string(),
            message: Some(message.to_string()),
        }
    }
}

impl DetailedErrorResponse {
    /// Create a new detailed error response
    pub fn new(code: String, message: String, details: Option<serde_json::Value>) -> Self {
        Self {
            error: ErrorDetails {
                code,
                message,
                details,
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_creation() {
        let error = ErrorResponse::bad_request("Invalid input");
        assert_eq!(error.status, 400);
        assert_eq!(error.error, "Invalid input");
        assert!(error.timestamp.is_some());
        assert!(error.request_id.is_some());
    }

    #[test]
    fn test_health_response_creation() {
        let health = HealthResponse::new("1.0.0".to_string());
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, "1.0.0");
        assert!(health.timestamp.len() > 0);
    }

    #[test]
    fn test_success_response_creation() {
        let success = SuccessResponse::with_message("Operation completed");
        assert_eq!(success.status, "success");
        assert_eq!(success.message, Some("Operation completed".to_string()));
    }

    #[test]
    fn test_detailed_error_response_creation() {
        let details = serde_json::json!({
            "field": "username",
            "reason": "Invalid email format"
        });

        let error = DetailedErrorResponse::new(
            "VALIDATION_ERROR".to_string(),
            "Validation failed".to_string(),
            Some(details),
        );

        assert_eq!(error.error.code, "VALIDATION_ERROR");
        assert_eq!(error.error.message, "Validation failed");
        assert!(error.error.details.is_some());
    }

    #[test]
    fn test_error_response_serialization() {
        let error = ErrorResponse::not_found("User not found");
        let serialized = serde_json::to_string(&error).unwrap();
        let deserialized: ErrorResponse = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.status, 404);
        assert_eq!(deserialized.error, "User not found");
    }
}