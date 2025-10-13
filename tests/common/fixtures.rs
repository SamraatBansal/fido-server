//! Test fixtures for FIDO2/WebAuthn testing

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

/// Valid attestation options request fixture
pub fn valid_attestation_options_request() -> Value {
    json!({
        "username": "alice",
        "displayName": "Alice Smith",
        "attestation": "direct",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": false,
            "userVerification": "preferred"
        }
    })
}

/// Valid attestation options response fixture
pub fn valid_attestation_options_response() -> Value {
    json!({
        "challenge": URL_SAFE_NO_PAD.encode("secure_random_challenge_32_bytes_long"),
        "rp": { 
            "name": "Example RP", 
            "id": "example.com" 
        },
        "user": { 
            "id": URL_SAFE_NO_PAD.encode("alice_user_id"),
            "name": "alice", 
            "displayName": "Alice Smith" 
        },
        "pubKeyCredParams": [{ 
            "type": "public-key", 
            "alg": -7 
        }],
        "timeout": 60000,
        "attestation": "direct",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": false,
            "userVerification": "preferred"
        }
    })
}

/// Valid attestation result request fixture
pub fn valid_attestation_result_request() -> Value {
    json!({
        "id": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
        "response": {
            "attestationObject": URL_SAFE_NO_PAD.encode("mock_attestation_object_data"),
            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"secure_challenge\",\"origin\":\"https://example.com\"}")
        },
        "type": "public-key"
    })
}

/// Valid assertion options request fixture
pub fn valid_assertion_options_request() -> Value {
    json!({
        "username": "alice",
        "userVerification": "preferred"
    })
}

/// Valid assertion options response fixture
pub fn valid_assertion_options_response() -> Value {
    json!({
        "challenge": URL_SAFE_NO_PAD.encode("secure_auth_challenge_32_bytes_long"),
        "rpId": "example.com",
        "allowCredentials": [{ 
            "type": "public-key", 
            "id": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!")
        }],
        "timeout": 60000,
        "userVerification": "preferred"
    })
}

/// Valid assertion result request fixture
pub fn valid_assertion_result_request() -> Value {
    json!({
        "id": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode("mock_authenticator_data"),
            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\",\"challenge\":\"secure_auth_challenge\",\"origin\":\"https://example.com\"}"),
            "signature": URL_SAFE_NO_PAD.encode("mock_signature_data"),
            "userHandle": URL_SAFE_NO_PAD.encode("alice_user_id")
        },
        "type": "public-key"
    })
}

/// Invalid request fixtures for negative testing
pub mod invalid {
    use super::*;
    use serde_json::{json, Value};

    /// Empty request
    pub fn empty_request() -> Value {
        json!({})
    }

    /// Request with missing username
    pub fn missing_username() -> Value {
        json!({
            "displayName": "Alice Smith",
            "attestation": "direct"
        })
    }

    /// Request with invalid username
    pub fn invalid_username() -> Value {
        json!({
            "username": "",
            "displayName": "Alice Smith",
            "attestation": "direct"
        })
    }

    /// Request with oversized payload
    pub fn oversized_payload() -> Value {
        let large_string = "x".repeat(2 * 1024 * 1024); // 2MB
        json!({
            "username": large_string,
            "displayName": "Alice Smith",
            "attestation": "direct"
        })
    }

    /// Request with invalid base64url
    pub fn invalid_base64url() -> Value {
        json!({
            "id": "invalid_base64!@#",
            "rawId": "invalid_base64!@#",
            "response": {
                "attestationObject": "invalid_base64!@#",
                "clientDataJSON": "invalid_base64!@#"
            },
            "type": "public-key"
        })
    }

    /// Request with malformed JSON
    pub fn malformed_json() -> String {
        "{ invalid json }".to_string()
    }

    /// Request with truncated client data
    pub fn truncated_client_data() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "rawId": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode("mock_attestation_object_data"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("truncated")
            },
            "type": "public-key"
        })
    }
}

/// Security test fixtures
pub mod security {
    use super::*;
    use serde_json::{json, Value};

    /// Request with replayed challenge
    pub fn replayed_challenge(old_challenge: &str) -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "rawId": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode("mock_attestation_object_data"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&format!(
                    "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://example.com\"}}",
                    old_challenge
                ))
            },
            "type": "public-key"
        })
    }

    /// Request with mismatched origin
    pub fn mismatched_origin() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "rawId": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode("mock_attestation_object_data"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"secure_challenge\",\"origin\":\"https://malicious.com\"}")
            },
            "type": "public-key"
        })
    }

    /// Request with tampered signature
    pub fn tampered_signature() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "rawId": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode("mock_authenticator_data"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\",\"challenge\":\"secure_auth_challenge\",\"origin\":\"https://example.com\"}"),
                "signature": URL_SAFE_NO_PAD.encode("tampered_signature_data"),
                "userHandle": URL_SAFE_NO_PAD.encode("alice_user_id")
            },
            "type": "public-key"
        })
    }

    /// Request with invalid RP ID
    pub fn invalid_rp_id() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "rawId": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!"),
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode("mock_authenticator_data"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\",\"challenge\":\"secure_auth_challenge\",\"origin\":\"https://invalid.com\"}"),
                "signature": URL_SAFE_NO_PAD.encode("mock_signature_data"),
                "userHandle": URL_SAFE_NO_PAD.encode("alice_user_id")
            },
            "type": "public-key"
        })
    }
}

/// Performance test fixtures
pub mod performance {
    use serde_json::{json, Value};

    /// Generate multiple concurrent requests
    pub fn generate_concurrent_requests(count: usize) -> Vec<Value> {
        (0..count)
            .map(|i| {
                json!({
                    "username": format!("user{}", i),
                    "displayName": format!("User {}", i),
                    "attestation": "direct"
                })
            })
            .collect()
    }

    /// Large batch request
    pub fn large_batch_request() -> Vec<Value> {
        (0..1000)
            .map(|i| {
                json!({
                    "username": format!("batch_user_{}", i),
                    "displayName": format!("Batch User {}", i),
                    "attestation": "direct"
                })
            })
            .collect()
    }
}

/// Compliance test fixtures for FIDO2 specification
pub mod compliance {
    use serde_json::{json, Value};

    /// Request with all supported algorithms
    pub fn all_algorithms_request() -> Value {
        json!({
            "username": "alice",
            "displayName": "Alice Smith",
            "attestation": "direct",
            "pubKeyCredParams": [
                { "type": "public-key", "alg": -7 },   // ES256
                { "type": "public-key", "alg": -257 }, // RS256
                { "type": "public-key", "alg": -37 },  // ES384
                { "type": "public-key", "alg": -8 }    // Ed25519
            ]
        })
    }

    /// Request with resident key requirement
    pub fn resident_key_request() -> Value {
        json!({
            "username": "alice",
            "displayName": "Alice Smith",
            "attestation": "direct",
            "authenticatorSelection": {
                "requireResidentKey": true,
                "userVerification": "required"
            }
        })
    }

    /// Request with user verification requirements
    pub fn user_verification_required() -> Value {
        json!({
            "username": "alice",
            "displayName": "Alice Smith",
            "authenticatorSelection": {
                "userVerification": "required"
            }
        })
    }
}