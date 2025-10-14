//! Common test utilities and fixtures for FIDO2/WebAuthn testing

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Common test constants
pub mod constants {
    pub const TEST_RP_ID: &str = "example.com";
    pub const TEST_RP_NAME: &str = "Example RP";
    pub const TEST_ORIGIN: &str = "https://example.com";
    pub const DEFAULT_TIMEOUT: u64 = 60000;
    pub const CHALLENGE_LENGTH: usize = 32;
    
    // Test user data
    pub const TEST_USERNAME: &str = "alice";
    pub const TEST_DISPLAY_NAME: &str = "Alice Smith";
    pub const TEST_USER_ID: &str = "dGVzdHVzZXJpZA=="; // base64 of "testuserid"
}

/// Test data factory for generating valid and invalid payloads
pub struct TestDataFactory;

impl TestDataFactory {
    /// Generate a valid base64url-encoded challenge
    pub fn valid_challenge() -> String {
        let challenge: Vec<u8> = (0..constants::CHALLENGE_LENGTH)
            .map(|_| rand::random::<u8>())
            .collect();
        BASE64.encode(challenge)
    }

    /// Generate an invalid challenge (too short)
    pub fn invalid_challenge_short() -> String {
        BASE64.encode("short")
    }

    /// Generate an invalid challenge (invalid base64)
    pub fn invalid_challenge_base64() -> String {
        "invalid!base64@challenge".to_string()
    }

    /// Generate valid attestation options request
    pub fn valid_attestation_options_request() -> AttestationOptionsRequest {
        AttestationOptionsRequest {
            username: constants::TEST_USERNAME.to_string(),
            displayName: constants::TEST_DISPLAY_NAME.to_string(),
            attestation: Some("direct".to_string()),
            authenticatorSelection: Some(AuthenticatorSelection {
                authenticatorAttachment: Some("platform".to_string()),
                requireResidentKey: Some(false),
                userVerification: Some("preferred".to_string()),
            }),
        }
    }

    /// Generate invalid attestation options request (missing username)
    pub fn invalid_attestation_options_request_no_username() -> serde_json::Value {
        serde_json::json!({
            "displayName": constants::TEST_DISPLAY_NAME,
            "attestation": "direct"
        })
    }

    /// Generate valid attestation result request
    pub fn valid_attestation_result_request() -> AttestationResultRequest {
        AttestationResultRequest {
            id: Self::valid_credential_id(),
            rawId: Self::valid_credential_id(),
            response: AuthenticatorAttestationResponse {
                attestationObject: Self::valid_attestation_object(),
                clientDataJSON: Self::valid_client_data_json("webauthn.create"),
            },
            type_: "public-key".to_string(),
        }
    }

    /// Generate invalid attestation result request (missing id)
    pub fn invalid_attestation_result_request_no_id() -> serde_json::Value {
        serde_json::json!({
            "rawId": Self::valid_credential_id(),
            "response": {
                "attestationObject": Self::valid_attestation_object(),
                "clientDataJSON": Self::valid_client_data_json("webauthn.create")
            },
            "type": "public-key"
        })
    }

    /// Generate valid assertion options request
    pub fn valid_assertion_options_request() -> AssertionOptionsRequest {
        AssertionOptionsRequest {
            username: Some(constants::TEST_USERNAME.to_string()),
            userVerification: Some("preferred".to_string()),
        }
    }

    /// Generate valid assertion result request
    pub fn valid_assertion_result_request() -> AssertionResultRequest {
        AssertionResultRequest {
            id: Self::valid_credential_id(),
            rawId: Self::valid_credential_id(),
            response: AuthenticatorAssertionResponse {
                authenticatorData: Self::valid_authenticator_data(),
                clientDataJSON: Self::valid_client_data_json("webauthn.get"),
                signature: Self::valid_signature(),
                userHandle: Some(constants::TEST_USER_ID.to_string()),
            },
            type_: "public-key".to_string(),
        }
    }

    /// Generate a valid credential ID
    pub fn valid_credential_id() -> String {
        BASE64.encode("valid-credential-id-12345")
    }

    /// Generate valid attestation object (mock)
    pub fn valid_attestation_object() -> String {
        "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ".to_string()
    }

    /// Generate valid client data JSON
    pub fn valid_client_data_json(typ: &str) -> String {
        let client_data = ClientData {
            challenge: Self::valid_challenge(),
            origin: constants::TEST_ORIGIN.to_string(),
            type_: typ.to_string(),
            ..Default::default()
        };
        BASE64.encode(serde_json::to_string(&client_data).unwrap())
    }

    /// Generate valid authenticator data
    pub fn valid_authenticator_data() -> String {
        "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string()
    }

    /// Generate valid signature
    pub fn valid_signature() -> String {
        "MEUCIQDz5YiZK_jqK8Z9rM5r6s7p8q9r8m5n6k7j8l9k0i1j2h3g4f5e6d7c8b9a0".to_string()
    }

    /// Generate malformed base64 data
    pub fn malformed_base64() -> String {
        "invalid!base64@data".to_string()
    }

    /// Generate oversized payload
    pub fn oversized_string() -> String {
        "a".repeat(100_000)
    }
}

/// Request/Response data structures matching FIDO2 Conformance Test API

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationOptionsRequest {
    pub username: String,
    pub displayName: String,
    #[serde(rename = "attestation", skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticatorSelection: Option<AuthenticatorSelection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticatorAttachment: Option<String>,
    #[serde(rename = "requireResidentKey", skip_serializing_if = "Option::is_none")]
    pub requireResidentKey: Option<bool>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub userVerification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage", skip_serializing_if = "String::is_empty")]
    pub errorMessage: String,
    pub challenge: String,
    pub rp: RpEntity,
    pub user: UserEntity,
    #[serde(rename = "pubKeyCredParams")]
    pub pubKeyCredParams: Vec<PubKeyCredParam>,
    pub timeout: u64,
    #[serde(rename = "excludeCredentials", default, skip_serializing_if = "Vec::is_empty")]
    pub excludeCredentials: Vec<CredentialDescriptor>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticatorSelection: Option<AuthenticatorSelection>,
    pub attestation: String,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResultRequest {
    pub id: String,
    #[serde(rename = "rawId")]
    pub rawId: String,
    pub response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub clientDataJSON: String,
    #[serde(rename = "attestationObject")]
    pub attestationObject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionOptionsRequest {
    pub username: Option<String>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub userVerification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage", skip_serializing_if = "String::is_empty")]
    pub errorMessage: String,
    pub challenge: String,
    #[serde(rename = "rpId")]
    pub rpId: String,
    #[serde(rename = "allowCredentials")]
    pub allowCredentials: Vec<CredentialDescriptor>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub userVerification: Option<String>,
    pub timeout: u64,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResultRequest {
    pub id: String,
    #[serde(rename = "rawId")]
    pub rawId: String,
    pub response: AuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticatorData: String,
    #[serde(rename = "clientDataJSON")]
    pub clientDataJSON: String,
    pub signature: String,
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub userHandle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage", skip_serializing_if = "String::is_empty")]
    pub errorMessage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpEntity {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub displayName: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub type_: String,
    pub alg: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientData {
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "tokenBinding", skip_serializing_if = "Option::is_none")]
    pub tokenBinding: Option<serde_json::Value>,
    #[serde(rename = "clientExtensions", skip_serializing_if = "Option::is_none")]
    pub clientExtensions: Option<serde_json::Value>,
    #[serde(rename = "hashAlgorithm", default = "default_hash_algorithm")]
    pub hashAlgorithm: String,
}

fn default_hash_algorithm() -> String {
    "SHA-256".to_string()
}

/// Test helper functions
pub mod helpers {
    use super::*;
    use actix_web::{test, App};
    use fido_server::configure_app;

    /// Create test app instance
    pub async fn create_test_app() -> impl actix_web::dev::Service<
        actix_web::dev::ServiceRequest,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    > {
        test::init_service(
            App::new().configure(configure_app),
        )
        .await
    }

    /// Make POST request with JSON body
    pub async fn post_json(
        app: &impl actix_web::dev::Service<
            actix_web::dev::ServiceRequest,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >,
        path: &str,
        body: serde_json::Value,
    ) -> actix_web::dev::ServiceResponse {
        let req = test::TestRequest::post()
            .uri(path)
            .set_json(&body)
            .to_request();
        test::call_service(app, req).await
    }

    /// Extract response JSON
    pub async fn response_json<T: for<'de> Deserialize<'de>>(
        resp: actix_web::dev::ServiceResponse,
    ) -> Result<T, actix_web::Error> {
        test::read_body_json(resp).await
    }

    /// Assert successful response
    pub fn assert_success_response(response: &ServerResponse) {
        assert_eq!(response.status, "ok");
        assert!(response.errorMessage.is_empty());
    }

    /// Assert failed response
    pub fn assert_failed_response(response: &ServerResponse, expected_error: &str) {
        assert_eq!(response.status, "failed");
        assert!(!response.errorMessage.is_empty());
        if !expected_error.is_empty() {
            assert!(response.errorMessage.contains(expected_error));
        }
    }
}

/// Security test utilities
pub mod security {
    use super::*;

    /// Generate replay attack data (reuse old challenge)
    pub fn replay_attack_data() -> (String, String) {
        let old_challenge = "old-reused-challenge-12345";
        let client_data = ClientData {
            challenge: old_challenge.to_string(),
            origin: constants::TEST_ORIGIN.to_string(),
            type_: "webauthn.create".to_string(),
            ..Default::default()
        };
        (old_challenge.to_string(), BASE64.encode(serde_json::to_string(&client_data).unwrap()))
    }

    /// Generate tampered client data JSON
    pub fn tampered_client_data_json() -> String {
        let mut client_data = ClientData {
            challenge: TestDataFactory::valid_challenge(),
            origin: "https://malicious.com".to_string(), // Tampered origin
            type_: "webauthn.create".to_string(),
            ..Default::default()
        };
        BASE64.encode(serde_json::to_string(&client_data).unwrap())
    }

    /// Generate invalid signature
    pub fn invalid_signature() -> String {
        "invalid-signature-data-12345".to_string()
    }

    /// Generate malformed CBOR data
    pub fn malformed_cbor() -> String {
        BASE64.encode("malformed-cbor-data")
    }

    /// Generate truncated client data
    pub fn truncated_client_data() -> String {
        BASE64.encode("{\"incomplete\": \"json")
    }
}