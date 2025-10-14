//! Test data factories for generating valid and invalid FIDO2/WebAuthn payloads
//!
//! This module provides factories for creating test data that covers:
//! - Valid request/response payloads
//! - Invalid/malformed data for negative testing
//! - Edge cases and boundary conditions
//! - Security attack vectors

use fake::{Fake, Faker};
use serde_json::{json, Value};
use uuid::Uuid;
use super::base64url;
use rand::{Rng, thread_rng};

/// Factory for creating attestation options requests
pub struct AttestationOptionsRequestFactory;

impl AttestationOptionsRequestFactory {
    /// Create a valid attestation options request
    pub fn valid() -> Value {
        json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        })
    }
    
    /// Create request with minimal required fields
    pub fn minimal() -> Value {
        json!({
            "username": "alice@example.com",
            "displayName": "Alice Smith"
        })
    }
    
    /// Create request with all optional fields
    pub fn complete() -> Value {
        json!({
            "username": "bob@example.com",
            "displayName": "Bob Johnson",
            "authenticatorSelection": {
                "requireResidentKey": true,
                "authenticatorAttachment": "platform",
                "userVerification": "required"
            },
            "attestation": "indirect"
        })
    }
    
    /// Create request with missing username
    pub fn missing_username() -> Value {
        json!({
            "displayName": "Missing Username"
        })
    }
    
    /// Create request with missing display name
    pub fn missing_display_name() -> Value {
        json!({
            "username": "missing@example.com"
        })
    }
    
    /// Create request with empty username
    pub fn empty_username() -> Value {
        json!({
            "username": "",
            "displayName": "Empty Username"
        })
    }
    
    /// Create request with invalid attestation value
    pub fn invalid_attestation() -> Value {
        json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "attestation": "invalid_value"
        })
    }
    
    /// Create request with oversized username
    pub fn oversized_username() -> Value {
        let long_username = "a".repeat(1000) + "@example.com";
        json!({
            "username": long_username,
            "displayName": "Oversized Username"
        })
    }
    
    /// Create request with special characters
    pub fn special_characters() -> Value {
        json!({
            "username": "test+user@example.com",
            "displayName": "Test User 测试用户 🔐"
        })
    }
}

/// Factory for creating attestation options responses
pub struct AttestationOptionsResponseFactory;

impl AttestationOptionsResponseFactory {
    /// Create a valid attestation options response
    pub fn valid() -> Value {
        let challenge = Self::generate_challenge();
        let user_id = Self::generate_user_id();
        
        json!({
            "status": "ok",
            "errorMessage": "",
            "rp": {
                "name": "Example Corporation",
                "id": "example.com"
            },
            "user": {
                "id": user_id,
                "name": "johndoe@example.com",
                "displayName": "John Doe"
            },
            "challenge": challenge,
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -35},
                {"type": "public-key", "alg": -36},
                {"type": "public-key", "alg": -257}
            ],
            "timeout": 60000,
            "excludeCredentials": [],
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        })
    }
    
    /// Create response with exclude credentials
    pub fn with_exclude_credentials() -> Value {
        let mut response = Self::valid();
        response["excludeCredentials"] = json!([
            {
                "type": "public-key",
                "id": Self::generate_credential_id(),
                "transports": ["usb", "nfc"]
            }
        ]);
        response
    }
    
    /// Generate a valid challenge (16-64 bytes, base64url encoded)
    pub fn generate_challenge() -> String {
        let mut rng = thread_rng();
        let size = rng.gen_range(16..=64);
        let challenge_bytes: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        base64url::encode(&challenge_bytes)
    }
    
    /// Generate a valid user ID
    pub fn generate_user_id() -> String {
        let uuid = Uuid::new_v4();
        base64url::encode(uuid.as_bytes())
    }
    
    /// Generate a valid credential ID
    pub fn generate_credential_id() -> String {
        let mut rng = thread_rng();
        let id_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        base64url::encode(&id_bytes)
    }
}

/// Factory for creating attestation result requests
pub struct AttestationResultRequestFactory;

impl AttestationResultRequestFactory {
    /// Create a valid attestation result request
    pub fn valid() -> Value {
        json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "rawId": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": Self::generate_client_data_json("webauthn.create"),
                "attestationObject": Self::generate_attestation_object()
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        })
    }
    
    /// Create request with missing ID
    pub fn missing_id() -> Value {
        let mut request = Self::valid();
        request.as_object_mut().unwrap().remove("id");
        request
    }
    
    /// Create request with invalid type
    pub fn invalid_type() -> Value {
        let mut request = Self::valid();
        request["type"] = json!("invalid-type");
        request
    }
    
    /// Create request with malformed client data JSON
    pub fn malformed_client_data() -> Value {
        let mut request = Self::valid();
        request["response"]["clientDataJSON"] = json!("invalid-base64!");
        request
    }
    
    /// Create request with tampered attestation object
    pub fn tampered_attestation_object() -> Value {
        let mut request = Self::valid();
        // Flip some bits in the attestation object
        let mut attestation = Self::generate_attestation_object();
        attestation.push('X'); // Invalid base64url
        request["response"]["attestationObject"] = json!(attestation);
        request
    }
    
    /// Generate valid client data JSON
    pub fn generate_client_data_json(type_field: &str) -> String {
        let client_data = json!({
            "type": type_field,
            "challenge": AttestationOptionsResponseFactory::generate_challenge(),
            "origin": "https://example.com",
            "crossOrigin": false
        });
        base64url::encode(client_data.to_string().as_bytes())
    }
    
    /// Generate mock attestation object (simplified for testing)
    pub fn generate_attestation_object() -> String {
        // This is a simplified mock - in real implementation, this would be a proper CBOR-encoded attestation object
        let mock_attestation = json!({
            "fmt": "none",
            "attStmt": {},
            "authData": base64url::encode(&[0u8; 37]) // Minimum auth data length
        });
        base64url::encode(mock_attestation.to_string().as_bytes())
    }
}

/// Factory for creating assertion options requests
pub struct AssertionOptionsRequestFactory;

impl AssertionOptionsRequestFactory {
    /// Create a valid assertion options request
    pub fn valid() -> Value {
        json!({
            "username": "johndoe@example.com",
            "userVerification": "preferred"
        })
    }
    
    /// Create request with required user verification
    pub fn required_user_verification() -> Value {
        json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        })
    }
    
    /// Create request with discouraged user verification
    pub fn discouraged_user_verification() -> Value {
        json!({
            "username": "johndoe@example.com",
            "userVerification": "discouraged"
        })
    }
    
    /// Create request with missing username
    pub fn missing_username() -> Value {
        json!({
            "userVerification": "preferred"
        })
    }
    
    /// Create request with invalid user verification
    pub fn invalid_user_verification() -> Value {
        json!({
            "username": "johndoe@example.com",
            "userVerification": "invalid_value"
        })
    }
    
    /// Create request for non-existent user
    pub fn non_existent_user() -> Value {
        json!({
            "username": "nonexistent@example.com",
            "userVerification": "preferred"
        })
    }
}

/// Factory for creating assertion options responses
pub struct AssertionOptionsResponseFactory;

impl AssertionOptionsResponseFactory {
    /// Create a valid assertion options response
    pub fn valid() -> Value {
        json!({
            "status": "ok",
            "errorMessage": "",
            "challenge": AttestationOptionsResponseFactory::generate_challenge(),
            "timeout": 60000,
            "rpId": "example.com",
            "allowCredentials": [
                {
                    "id": AttestationOptionsResponseFactory::generate_credential_id(),
                    "type": "public-key",
                    "transports": ["usb", "nfc"]
                }
            ],
            "userVerification": "preferred"
        })
    }
    
    /// Create response with no allowed credentials
    pub fn no_credentials() -> Value {
        let mut response = Self::valid();
        response["allowCredentials"] = json!([]);
        response
    }
    
    /// Create response with multiple credentials
    pub fn multiple_credentials() -> Value {
        let mut response = Self::valid();
        response["allowCredentials"] = json!([
            {
                "id": AttestationOptionsResponseFactory::generate_credential_id(),
                "type": "public-key",
                "transports": ["usb"]
            },
            {
                "id": AttestationOptionsResponseFactory::generate_credential_id(),
                "type": "public-key",
                "transports": ["nfc", "ble"]
            }
        ]);
        response
    }
}

/// Factory for creating assertion result requests
pub struct AssertionResultRequestFactory;

impl AssertionResultRequestFactory {
    /// Create a valid assertion result request
    pub fn valid() -> Value {
        json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "rawId": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": Self::generate_authenticator_data(),
                "clientDataJSON": AttestationResultRequestFactory::generate_client_data_json("webauthn.get"),
                "signature": Self::generate_signature(),
                "userHandle": base64url::encode(b"user123")
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        })
    }
    
    /// Create request with empty user handle
    pub fn empty_user_handle() -> Value {
        let mut request = Self::valid();
        request["response"]["userHandle"] = json!("");
        request
    }
    
    /// Create request with invalid signature
    pub fn invalid_signature() -> Value {
        let mut request = Self::valid();
        request["response"]["signature"] = json!("invalid-signature!");
        request
    }
    
    /// Create request with tampered authenticator data
    pub fn tampered_authenticator_data() -> Value {
        let mut request = Self::valid();
        request["response"]["authenticatorData"] = json!("tampered-data");
        request
    }
    
    /// Generate mock authenticator data
    pub fn generate_authenticator_data() -> String {
        // Mock authenticator data (37+ bytes minimum)
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // User present flag
        base64url::encode(&auth_data)
    }
    
    /// Generate mock signature
    pub fn generate_signature() -> String {
        let mut rng = thread_rng();
        let signature_bytes: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
        base64url::encode(&signature_bytes)
    }
}

/// Factory for creating error responses
pub struct ErrorResponseFactory;

impl ErrorResponseFactory {
    /// Create a generic error response
    pub fn generic(message: &str) -> Value {
        json!({
            "status": "failed",
            "errorMessage": message
        })
    }
    
    /// Create validation error response
    pub fn validation_error(field: &str) -> Value {
        Self::generic(&format!("Validation failed for field: {}", field))
    }
    
    /// Create user not found error
    pub fn user_not_found() -> Value {
        Self::generic("User does not exist!")
    }
    
    /// Create invalid challenge error
    pub fn invalid_challenge() -> Value {
        Self::generic("Invalid or expired challenge!")
    }
    
    /// Create signature verification error
    pub fn signature_verification_failed() -> Value {
        Self::generic("Can not validate response signature!")
    }
}