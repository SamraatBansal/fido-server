//! Common schema definitions

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// API error response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorResponse {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Additional error details
    pub details: Option<HashMap<String, serde_json::Value>>,
}

impl ErrorResponse {
    /// Create a new error response
    pub fn new(code: String, message: String) -> Self {
        Self {
            code,
            message,
            details: None,
        }
    }

    /// Create a new error response with details
    pub fn with_details(
        code: String,
        message: String,
        details: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            code,
            message,
            details: Some(details),
        }
    }
}

/// Success response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SuccessResponse {
    /// Status
    pub status: String,
    /// Optional data
    pub data: Option<serde_json::Value>,
}

impl SuccessResponse {
    /// Create a new success response
    pub fn new() -> Self {
        Self {
            status: "success".to_string(),
            data: None,
        }
    }

    /// Create a success response with data
    pub fn with_data(data: serde_json::Value) -> Self {
        Self {
            status: "success".to_string(),
            data: Some(data),
        }
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Service version
    pub version: String,
    /// Timestamp
    pub timestamp: String,
    /// Database status
    pub database: String,
    /// Additional checks
    pub checks: Option<HashMap<String, String>>,
}

impl HealthResponse {
    /// Create a new health response
    pub fn new(version: String, database_status: String) -> Self {
        Self {
            status: "healthy".to_string(),
            version,
            timestamp: chrono::Utc::now().to_rfc3339(),
            database: database_status,
            checks: None,
        }
    }

    /// Add a health check
    pub fn with_check(mut self, name: String, status: String) -> Self {
        if self.checks.is_none() {
            self.checks = Some(HashMap::new());
        }
        self.checks.as_mut().unwrap().insert(name, status);
        self
    }
}

/// Common error codes
pub mod error_codes {
    /// Invalid attestation
    pub const INVALID_ATTESTATION: &str = "INVALID_ATTESTATION";
    /// Invalid assertion
    pub const INVALID_ASSERTION: &str = "INVALID_ASSERTION";
    /// Invalid challenge
    pub const INVALID_CHALLENGE: &str = "INVALID_CHALLENGE";
    /// Expired challenge
    pub const EXPIRED_CHALLENGE: &str = "EXPIRED_CHALLENGE";
    /// User not found
    pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";
    /// Credential not found
    pub const CREDENTIAL_NOT_FOUND: &str = "CREDENTIAL_NOT_FOUND";
    /// Duplicate credential
    pub const DUPLICATE_CREDENTIAL: &str = "DUPLICATE_CREDENTIAL";
    /// Validation error
    pub const VALIDATION_ERROR: &str = "VALIDATION_ERROR";
    /// Internal server error
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    /// Database error
    pub const DATABASE_ERROR: &str = "DATABASE_ERROR";
    /// Rate limit exceeded
    pub const RATE_LIMIT_EXCEEDED: &str = "RATE_LIMIT_EXCEEDED";
    /// Invalid origin
    pub const INVALID_ORIGIN: &str = "INVALID_ORIGIN";
    /// Invalid RP ID
    pub const INVALID_RP_ID: &str = "INVALID_RP_ID";
    /// Counter regression
    pub const COUNTER_REGRESSION: &str = "COUNTER_REGRESSION";
}

/// Transport types
pub mod transports {
    /// USB transport
    pub const USB: &str = "usb";
    /// NFC transport
    pub const NFC: &str = "nfc";
    /// Bluetooth transport
    pub const BLE: &str = "ble";
    /// Internal transport
    pub const INTERNAL: &str = "internal";
    /// Hybrid transport
    pub const HYBRID: &str = "hybrid";
}

/// Attestation formats
pub mod attestation_formats {
    /// Packed attestation format
    pub const PACKED: &str = "packed";
    /// FIDO U2F attestation format
    pub const FIDO_U2F: &str = "fido-u2f";
    /// None attestation format
    pub const NONE: &str = "none";
    /// TPM attestation format
    pub const TPM: &str = "tpm";
    /// Android Key attestation format
    pub const ANDROID_KEY: &str = "android-key";
    /// Android SafetyNet attestation format
    pub const ANDROID_SAFETYNET: &str = "android-safetynet";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response() {
        let error = ErrorResponse::new(
            "TEST_ERROR".to_string(),
            "Test error message".to_string(),
        );

        assert_eq!(error.code, "TEST_ERROR");
        assert_eq!(error.message, "Test error message");
        assert!(error.details.is_none());
    }

    #[test]
    fn test_error_response_with_details() {
        let mut details = HashMap::new();
        details.insert("field".to_string(), serde_json::Value::String("value".to_string()));

        let error = ErrorResponse::with_details(
            "TEST_ERROR".to_string(),
            "Test error message".to_string(),
            details.clone(),
        );

        assert_eq!(error.code, "TEST_ERROR");
        assert_eq!(error.message, "Test error message");
        assert_eq!(error.details, Some(details));
    }

    #[test]
    fn test_success_response() {
        let response = SuccessResponse::new();
        assert_eq!(response.status, "success");
        assert!(response.data.is_none());
    }

    #[test]
    fn test_success_response_with_data() {
        let data = serde_json::json!({"key": "value"});
        let response = SuccessResponse::with_data(data.clone());
        assert_eq!(response.status, "success");
        assert_eq!(response.data, Some(data));
    }

    #[test]
    fn test_health_response() {
        let health = HealthResponse::new("1.0.0".to_string(), "connected".to_string());
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, "1.0.0");
        assert_eq!(health.database, "connected");
        assert!(health.checks.is_none());
    }

    #[test]
    fn test_health_response_with_checks() {
        let health = HealthResponse::new("1.0.0".to_string(), "connected".to_string())
            .with_check("cache".to_string(), "ok".to_string())
            .with_check("external_api".to_string(), "ok".to_string());

        assert_eq!(health.status, "healthy");
        assert!(health.checks.is_some());
        let checks = health.checks.unwrap();
        assert_eq!(checks.get("cache"), Some(&"ok".to_string()));
        assert_eq!(checks.get("external_api"), Some(&"ok".to_string()));
    }

    #[test]
    fn test_error_response_serialization() {
        let error = ErrorResponse::new(
            "INVALID_ATTESTATION".to_string(),
            "The attestation signature could not be verified".to_string(),
        );

        let serialized = serde_json::to_string(&error).unwrap();
        let deserialized: ErrorResponse = serde_json::from_str(&serialized).unwrap();

        assert_eq!(error, deserialized);
    }

    #[test]
    fn test_constants() {
        assert_eq!(error_codes::INVALID_ATTESTATION, "INVALID_ATTESTATION");
        assert_eq!(transports::USB, "usb");
        assert_eq!(attestation_formats::PACKED, "packed");
    }
}