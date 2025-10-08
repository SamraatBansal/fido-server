//! Unit tests for input validation and data sanitization

use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use validator::{Validate, ValidationError};

/// Test validation for attestation options requests
#[derive(Debug, Deserialize, Validate)]
struct AttestationOptionsRequest {
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(min = 1, max = 255, message = "Username must be 1-255 characters"))]
    pub username: String,

    #[validate(length(min = 1, max = 255, message = "Display name must be 1-255 characters"))]
    #[serde(rename = "displayName")]
    pub display_name: String,

    #[validate(custom(function = "validate_attestation"))]
    pub attestation: Option<String>,

    #[validate(nested)]
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
}

/// Test validation for authenticator selection criteria
#[derive(Debug, Deserialize, Validate)]
#[allow(dead_code)]
struct AuthenticatorSelectionCriteria {
    #[validate(custom(function = "validate_authenticator_attachment"))]
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,

    #[allow(dead_code)]
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,

    #[validate(custom(function = "validate_user_verification"))]
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Test validation for attestation result requests
#[derive(Debug, Deserialize, Validate)]
struct AttestationResultRequest {
    #[validate(length(min = 1, max = 1023, message = "Credential ID must be 1-1023 characters"))]
    #[validate(custom(function = "validate_base64url"))]
    pub id: String,

    #[validate(length(min = 1, max = 1023, message = "Raw ID must be 1-1023 characters"))]
    #[validate(custom(function = "validate_base64url"))]
    pub raw_id: String,

    #[validate(nested)]
    pub response: AttestationResponse,

    #[validate(custom(function = "validate_credential_type"))]
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Test validation for attestation response
#[derive(Debug, Deserialize, Validate)]
struct AttestationResponse {
    #[validate(length(min = 1, message = "Attestation object is required"))]
    #[validate(custom(function = "validate_base64url"))]
    pub attestation_object: String,

    #[validate(length(min = 1, message = "Client data JSON is required"))]
    #[validate(custom(function = "validate_base64url"))]
    pub client_data_json: String,
}

/// Test validation for assertion options requests
#[derive(Debug, Deserialize, Validate)]
struct AssertionOptionsRequest {
    #[validate(email(message = "Invalid email format"))]
    pub username: String,

    #[validate(custom(function = "validate_user_verification"))]
    pub user_verification: Option<String>,
}

/// Test validation for assertion result requests
#[derive(Debug, Deserialize, Validate)]
struct AssertionResultRequest {
    #[validate(length(min = 1, max = 1023, message = "Credential ID must be 1-1023 characters"))]
    #[validate(custom(function = "validate_base64url"))]
    pub id: String,

    #[validate(length(min = 1, max = 1023, message = "Raw ID must be 1-1023 characters"))]
    #[validate(custom(function = "validate_base64url"))]
    pub raw_id: String,

    #[validate(nested)]
    pub response: AssertionResponse,

    #[validate(custom(function = "validate_credential_type"))]
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Test validation for assertion response
#[derive(Debug, Deserialize, Validate)]
struct AssertionResponse {
    #[validate(length(min = 37, message = "Authenticator data must be at least 37 bytes"))]
    #[validate(custom(function = "validate_base64url"))]
    pub authenticator_data: String,

    #[validate(length(min = 1, message = "Client data JSON is required"))]
    #[validate(custom(function = "validate_base64url"))]
    pub client_data_json: String,

    #[validate(length(min = 1, message = "Signature is required"))]
    #[validate(custom(function = "validate_base64url"))]
    pub signature: String,

    #[validate(custom(function = "validate_base64url"))]
    pub user_handle: Option<String>,
}

/// Custom validation functions
fn validate_attestation(attestation: &str) -> Result<(), ValidationError> {
    match attestation {
        "none" | "direct" | "indirect" | "enterprise" => Ok(()),
        _ => {
            let mut error = ValidationError::new("invalid_attestation");
            error.message = Some("Attestation must be one of: none, direct, indirect, enterprise".into());
            Err(error)
        }
    }
}

fn validate_authenticator_attachment(attachment: &str) -> Result<(), ValidationError> {
    match attachment {
        "platform" | "cross-platform" => Ok(()),
        _ => {
            let mut error = ValidationError::new("invalid_attachment");
            error.message = Some("Authenticator attachment must be 'platform' or 'cross-platform'".into());
            Err(error)
        }
    }
}

fn validate_user_verification(uv: &str) -> Result<(), ValidationError> {
    match uv {
        "required" | "preferred" | "discouraged" => Ok(()),
        _ => {
            let mut error = ValidationError::new("invalid_user_verification");
            error.message = Some("User verification must be one of: required, preferred, discouraged".into());
            Err(error)
        }
    }
}

fn validate_base64url(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("empty_base64url"));
    }

    // Check for invalid base64url characters
    if value.contains('+') || value.contains('/') || value.contains('=') {
        return Err(ValidationError::new("invalid_base64url_chars"));
    }

    // Try to decode
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ValidationError::new("invalid_base64url_decode"))?;

    Ok(())
}

fn validate_credential_type(credential_type: &str) -> Result<(), ValidationError> {
    if credential_type != "public-key" {
        let mut error = ValidationError::new("invalid_credential_type");
        error.message = Some("Credential type must be 'public-key'".into());
        Err(error)
    } else {
        Ok(())
    }
}

/// Test suite for request validation
#[cfg(test)]
mod validation_tests {
    use super::*;
    use crate::common::TestDataFactory;

    #[test]
    fn test_valid_attestation_options_request() {
        let json_data = TestDataFactory::valid_attestation_options_request();
        let request: Result<AttestationOptionsRequest, _> = serde_json::from_value(json_data);

        assert!(request.is_ok());
        let validated = request.unwrap();
        assert!(validated.validate().is_ok());
    }

    #[test]
    fn test_attestation_options_missing_username() {
        let json_data = TestDataFactory::attestation_options_missing_username();
        let request: Result<AttestationOptionsRequest, _> = serde_json::from_value(json_data);

        assert!(request.is_err()); // Missing required field
    }

    #[test]
    fn test_attestation_options_invalid_email() {
        let mut json_data = TestDataFactory::valid_attestation_options_request();
        json_data["username"] = Value::String("invalid-email".to_string());

        let request: Result<AttestationOptionsRequest, _> = serde_json::from_value(json_data);
        assert!(request.is_ok());

        let validated = request.unwrap();
        assert!(validated.validate().is_err()); // Invalid email format
    }

    #[test]
    fn test_attestation_options_invalid_attestation() {
        let mut json_data = TestDataFactory::valid_attestation_options_request();
        json_data["attestation"] = Value::String("invalid_type".to_string());

        let request: Result<AttestationOptionsRequest, _> = serde_json::from_value(json_data);
        assert!(request.is_ok());

        let validated = request.unwrap();
        assert!(validated.validate().is_err()); // Invalid attestation type
    }

    #[test]
    fn test_attestation_options_display_name_too_long() {
        let mut json_data = TestDataFactory::valid_attestation_options_request();
        json_data["displayName"] = Value::String("x".repeat(256)); // Exceeds 255 chars

        let request: Result<AttestationOptionsRequest, _> = serde_json::from_value(json_data);
        assert!(request.is_ok());

        let validated = request.unwrap();
        assert!(validated.validate().is_err()); // Display name too long
    }

    #[test]
    fn test_valid_attestation_result_request() {
        let json_data = TestDataFactory::valid_attestation_result_request();
        let request: Result<AttestationResultRequest, _> = serde_json::from_value(json_data);

        assert!(request.is_ok());
        let validated = request.unwrap();
        assert!(validated.validate().is_ok());
    }

    #[test]
    fn test_attestation_result_missing_response() {
        let json_data = TestDataFactory::attestation_result_missing_response();
        let request: Result<AttestationResultRequest, _> = serde_json::from_value(json_data);

        assert!(request.is_err()); // Missing required field
    }

    #[test]
    fn test_attestation_result_invalid_type() {
        let json_data = TestDataFactory::attestation_result_invalid_type();
        let request: Result<AttestationResultRequest, _> = serde_json::from_value(json_data);

        assert!(request.is_ok());
        let validated = request.unwrap();
        assert!(validated.validate().is_err()); // Invalid credential type
    }

    #[test]
    fn test_attestation_result_invalid_base64url() {
        let mut json_data = TestDataFactory::valid_attestation_result_request();
        json_data["response"]["attestationObject"] = Value::String("invalid_base64url!".to_string());

        let request: Result<AttestationResultRequest, _> = serde_json::from_value(json_data);
        assert!(request.is_ok());

        let validated = request.unwrap();
        assert!(validated.validate().is_err()); // Invalid base64url
    }

    #[test]
    fn test_attestation_result_empty_credential_id() {
        let mut json_data = TestDataFactory::valid_attestation_result_request();
        json_data["id"] = Value::String(String::new());

        let request: Result<AttestationResultRequest, _> = serde_json::from_value(json_data);
        assert!(request.is_ok());

        let validated = request.unwrap();
        assert!(validated.validate().is_err()); // Empty credential ID
    }

    #[test]
    fn test_valid_assertion_options_request() {
        let json_data = TestDataFactory::valid_assertion_options_request();
        let request: Result<AssertionOptionsRequest, _> = serde_json::from_value(json_data);

        assert!(request.is_ok());
        let validated = request.unwrap();
        assert!(validated.validate().is_ok());
    }

    #[test]
    fn test_assertion_options_missing_username() {
        let json_data = TestDataFactory::assertion_options_missing_username();
        let request: Result<AssertionOptionsRequest, _> = serde_json::from_value(json_data);

        assert!(request.is_err()); // Missing required field
    }

    #[test]
    fn test_valid_assertion_result_request() {
        let json_data = TestDataFactory::valid_assertion_result_request();
        let request: Result<AssertionResultRequest, _> = serde_json::from_value(json_data);

        assert!(request.is_ok());
        let validated = request.unwrap();
        assert!(validated.validate().is_ok());
    }

    #[test]
    fn test_assertion_result_missing_signature() {
        let json_data = TestDataFactory::assertion_result_missing_signature();
        let request: Result<AssertionResultRequest, _> = serde_json::from_value(json_data);

        assert!(request.is_err()); // Missing required field
    }

    #[test]
    fn test_assertion_result_invalid_authenticator_data() {
        let mut json_data = TestDataFactory::valid_assertion_result_request();
        json_data["response"]["authenticatorData"] = Value::String("short".to_string());

        let request: Result<AssertionResultRequest, _> = serde_json::from_value(json_data);
        assert!(request.is_ok());

        let validated = request.unwrap();
        assert!(validated.validate().is_err()); // Authenticator data too short
    }

    #[test]
    fn test_oversized_payload_validation() {
        let oversized = TestDataFactory::oversized_payload();
        let request: Result<AttestationOptionsRequest, _> = serde_json::from_value(oversized);

        assert!(request.is_ok());
        let validated = request.unwrap();
        assert!(validated.validate().is_err()); // Display name too long
    }

    #[test]
    fn test_payload_with_nulls() {
        let null_payload = TestDataFactory::payload_with_nulls();
        let request: Result<AttestationOptionsRequest, _> = serde_json::from_value(null_payload);

        assert!(request.is_err()); // Null username should fail deserialization
    }

    #[test]
    fn test_base64url_validation() {
        // Valid base64url
        assert!(validate_base64url("dGVzdA").is_ok());
        assert!(validate_base64url("dGVzdF9kYXRh").is_ok());

        // Invalid base64url
        assert!(validate_base64url("dGVzdA=").is_err()); // Contains padding
        assert!(validate_base64url("dGVzdA+").is_err()); // Contains + character
        assert!(validate_base64url("dGVzdA/").is_err()); // Contains / character
        assert!(validate_base64url("").is_err()); // Empty string
        assert!(validate_base64url("!@#$%^&*()").is_err()); // Invalid characters
    }

    #[test]
    fn test_attestation_validation() {
        assert!(validate_attestation("none").is_ok());
        assert!(validate_attestation("direct").is_ok());
        assert!(validate_attestation("indirect").is_ok());
        assert!(validate_attestation("enterprise").is_ok());
        assert!(validate_attestation("invalid").is_err());
    }

    #[test]
    fn test_authenticator_attachment_validation() {
        assert!(validate_authenticator_attachment("platform").is_ok());
        assert!(validate_authenticator_attachment("cross-platform").is_ok());
        assert!(validate_authenticator_attachment("invalid").is_err());
    }

    #[test]
    fn test_user_verification_validation() {
        assert!(validate_user_verification("required").is_ok());
        assert!(validate_user_verification("preferred").is_ok());
        assert!(validate_user_verification("discouraged").is_ok());
        assert!(validate_user_verification("invalid").is_err());
    }

    #[test]
    fn test_credential_type_validation() {
        assert!(validate_credential_type("public-key").is_ok());
        assert!(validate_credential_type("invalid").is_err());
    }
}