//! Common test utilities and factories for FIDO2/WebAuthn testing

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Standard server response format
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub error_message: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

/// Factory for creating test data
pub struct TestDataFactory;

impl TestDataFactory {
    /// Generate a valid base64url string
    pub fn valid_base64url(length: usize) -> String {
        let bytes: Vec<u8> = (0..length).map(|_| rand::random::<u8>()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate an invalid base64url string
    pub fn invalid_base64url() -> String {
        "invalid@base64#url!".to_string()
    }

    /// Create a valid attestation options request
    pub fn valid_attestation_options_request() -> AttestationOptionsRequest {
        AttestationOptionsRequest {
            username: "alice@example.com".to_string(),
            display_name: "Alice Smith".to_string(),
            attestation: Some("direct".to_string()),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: Some("platform".to_string()),
                require_resident_key: Some(false),
                user_verification: Some("preferred".to_string()),
            }),
        }
    }

    /// Create an invalid attestation options request (missing username)
    pub fn invalid_attestation_options_request_missing_username() -> AttestationOptionsRequest {
        let mut req = Self::valid_attestation_options_request();
        req.username = "".to_string();
        req
    }

    /// Create a valid attestation result request
    pub fn valid_attestation_result_request() -> AttestationResultRequest {
        AttestationResultRequest {
            id: Self::valid_base64url(32),
            raw_id: Self::valid_base64url(32),
            response: AttestationResponse {
                attestation_object: Self::valid_base64url(500),
                client_data_json: Self::valid_base64url(200),
            },
            credential_type: "public-key".to_string(),
        }
    }

    /// Create an invalid attestation result request (invalid base64url)
    pub fn invalid_attestation_result_request() -> AttestationResultRequest {
        AttestationResultRequest {
            id: Self::invalid_base64url(),
            raw_id: Self::valid_base64url(32),
            response: AttestationResponse {
                attestation_object: Self::valid_base64url(500),
                client_data_json: Self::valid_base64url(200),
            },
            credential_type: "public-key".to_string(),
        }
    }

    /// Create a valid assertion options request
    pub fn valid_assertion_options_request() -> AssertionOptionsRequest {
        AssertionOptionsRequest {
            username: "alice@example.com".to_string(),
            user_verification: Some("preferred".to_string()),
        }
    }

    /// Create a valid assertion result request
    pub fn valid_assertion_result_request() -> AssertionResultRequest {
        AssertionResultRequest {
            id: Self::valid_base64url(32),
            raw_id: Self::valid_base64url(32),
            response: AssertionResponse {
                authenticator_data: Self::valid_base64url(37),
                client_data_json: Self::valid_base64url(200),
                signature: Self::valid_base64url(64),
                user_handle: Some(Self::valid_base64url(16)),
            },
            credential_type: "public-key".to_string(),
        }
    }

    /// Create an assertion result request with replayed challenge
    pub fn replayed_assertion_result_request() -> AssertionResultRequest {
        let mut req = Self::valid_assertion_result_request();
        // Use old/expired challenge data
        req.response.client_data_json = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "challenge": "old_replayed_challenge_12345",
                "origin": "https://example.com",
                "type": "webauthn.get"
            }).to_string()
        );
        req
    }

    /// Create an assertion result with tampered signature
    pub fn tampered_assertion_result_request() -> AssertionResultRequest {
        let mut req = Self::valid_assertion_result_request();
        req.response.signature = Self::invalid_base64url();
        req
    }

    /// Create oversized payload
    pub fn oversized_payload() -> String {
        "a".repeat(1000000) // 1MB string
    }
}

// Request/Response types matching FIDO2 Conformance Test API

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub attestation: Option<String>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationOptionsResponse {
    pub challenge: String,
    pub rp: RelyingParty,
    pub user: User,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub attestation: String,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelyingParty {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResultRequest {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: AttestationResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionOptionsResponse {
    pub challenge: String,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    pub timeout: u32,
    #[serde(rename = "userVerification")]
    pub user_verification: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionResultRequest {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: AssertionResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// Security test vectors
pub struct SecurityVectors;

impl SecurityVectors {
    /// Create client data JSON with invalid origin
    pub fn invalid_origin_client_data() -> String {
        URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "challenge": TestDataFactory::valid_base64url(32),
                "origin": "https://malicious.com",
                "type": "webauthn.create"
            }).to_string()
        )
    }

    /// Create client data JSON with mismatched type
    pub fn mismatched_type_client_data() -> String {
        URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "challenge": TestDataFactory::valid_base64url(32),
                "origin": "https://example.com",
                "type": "webauthn.get" // Wrong type for attestation
            }).to_string()
        )
    }

    /// Create malformed CBOR data
    pub fn malformed_cbor() -> String {
        "invalid_cbor_data".to_string()
    }

    /// Create truncated client data JSON
    pub fn truncated_client_data() -> String {
        URL_SAFE_NO_PAD.encode("{\"incomplete\": \"json".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_response_creation() {
        let success = ServerResponse::success();
        assert_eq!(success.status, "ok");
        assert_eq!(success.error_message, "");

        let error = ServerResponse::error("Test error");
        assert_eq!(error.status, "failed");
        assert_eq!(error.error_message, "Test error");
    }

    #[test]
    fn test_base64url_generation() {
        let valid = TestDataFactory::valid_base64url(32);
        assert_eq!(valid.len(), 43); // Base64url encoding of 32 bytes
        assert!(URL_SAFE_NO_PAD.decode(valid.as_bytes()).is_ok());

        let invalid = TestDataFactory::invalid_base64url();
        assert!(URL_SAFE_NO_PAD.decode(invalid.as_bytes()).is_err());
    }

    #[test]
    fn test_attestation_options_request() {
        let req = TestDataFactory::valid_attestation_options_request();
        assert_eq!(req.username, "alice@example.com");
        assert_eq!(req.display_name, "Alice Smith");
        assert_eq!(req.attestation, Some("direct".to_string()));
    }

    #[test]
    fn test_security_vectors() {
        let invalid_origin = SecurityVectors::invalid_origin_client_data();
        assert!(URL_SAFE_NO_PAD.decode(invalid_origin.as_bytes()).is_ok());

        let malformed = SecurityVectors::malformed_cbor();
        assert_eq!(malformed, "invalid_cbor_data");
    }
}