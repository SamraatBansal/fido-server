//! Test fixtures and mock data for FIDO2/WebAuthn testing

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

/// Test user fixture
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

impl TestUser {
    pub fn new(username: &str, display_name: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            created_at: Utc::now(),
        }
    }

    pub fn alice() -> Self {
        Self::new("alice@example.com", "Alice Smith")
    }

    pub fn bob() -> Self {
        Self::new("bob@example.com", "Bob Johnson")
    }
}

/// Test credential fixture
#[derive(Debug, Clone)]
pub struct TestCredential {
    pub id: Vec<u8>,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub sign_count: u64,
    pub aaguid: Option<Vec<u8>>,
    pub attestation_type: String,
    pub transports: Vec<String>,
}

impl TestCredential {
    pub fn new(user_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4().as_bytes().to_vec(),
            user_id,
            public_key: vec![0x04, 0x01, 0x02, 0x03], // Mock public key
            sign_count: 0,
            aaguid: Some(vec![0x00; 16]),
            attestation_type: "packed".to_string(),
            transports: vec!["internal".to_string()],
        }
    }
}

/// Test challenge fixture
#[derive(Debug, Clone)]
pub struct TestChallenge {
    pub id: Uuid,
    pub challenge_hash: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl TestChallenge {
    pub fn new_registration(user_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            challenge_hash: Uuid::new_v4().as_bytes().to_vec(),
            user_id: Some(user_id),
            challenge_type: "registration".to_string(),
            expires_at: now + chrono::Duration::minutes(5),
            created_at: now,
        }
    }

    pub fn new_authentication(user_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            challenge_hash: Uuid::new_v4().as_bytes().to_vec(),
            user_id: Some(user_id),
            challenge_type: "authentication".to_string(),
            expires_at: now + chrono::Duration::minutes(5),
            created_at: now,
        }
    }

    pub fn expired() -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            challenge_hash: Uuid::new_v4().as_bytes().to_vec(),
            user_id: None,
            challenge_type: "registration".to_string(),
            expires_at: now - chrono::Duration::minutes(1),
            created_at: now - chrono::Duration::minutes(6),
        }
    }
}

/// Valid attestation options response fixture
pub fn valid_attestation_options_response() -> serde_json::Value {
    json!({
        "challenge": URL_SAFE_NO_PAD.encode("valid_challenge_12345"),
        "rp": {
            "name": "Test RP",
            "id": "localhost"
        },
        "user": {
            "id": URL_SAFE_NO_PAD.encode("user_id_123"),
            "name": "alice@example.com",
            "displayName": "Alice Smith"
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257}
        ],
        "timeout": 60000,
        "attestation": "direct",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": false,
            "userVerification": "preferred"
        }
    })
}

/// Valid assertion options response fixture
pub fn valid_assertion_options_response() -> serde_json::Value {
    json!({
        "challenge": URL_SAFE_NO_PAD.encode("valid_challenge_67890"),
        "rpId": "localhost",
        "allowCredentials": [
            {
                "type": "public-key",
                "id": URL_SAFE_NO_PAD.encode("credential_id_123"),
                "transports": ["internal", "usb"]
            }
        ],
        "timeout": 60000,
        "userVerification": "preferred"
    })
}

/// Valid attestation result request fixture
pub fn valid_attestation_result_request() -> serde_json::Value {
    json!({
        "id": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "response": {
            "attestationObject": URL_SAFE_NO_PAD.encode("mock_attestation_object"),
            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"valid_challenge_12345\",\"origin\":\"http://localhost:8080\"}")
        },
        "type": "public-key"
    })
}

/// Valid assertion result request fixture
pub fn valid_assertion_result_request() -> serde_json::Value {
    json!({
        "id": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode("mock_authenticator_data"),
            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\",\"challenge\":\"valid_challenge_67890\",\"origin\":\"http://localhost:8080\"}"),
            "signature": URL_SAFE_NO_PAD.encode("mock_signature"),
            "userHandle": URL_SAFE_NO_PAD.encode("user_id_123")
        },
        "type": "public-key"
    })
}

/// Invalid attestation result request with malformed base64
pub fn invalid_attestation_result_malformed_base64() -> serde_json::Value {
    json!({
        "id": "invalid_base64!",
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "response": {
            "attestationObject": "invalid_base64!",
            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
        },
        "type": "public-key"
    })
}

/// Invalid assertion result request with missing fields
pub fn invalid_assertion_result_missing_fields() -> serde_json::Value {
    json!({
        "id": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode("mock_authenticator_data"),
            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\"}")
            // Missing signature and userHandle
        },
        "type": "public-key"
    })
}

/// Oversized payload fixture for testing size limits
pub fn oversized_payload() -> serde_json::Value {
    let large_string = "x".repeat(2_000_000); // 2MB string
    json!({
        "id": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "response": {
            "attestationObject": URL_SAFE_NO_PAD.encode(&large_string),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&format!("{{\"type\":\"webauthn.create\",\"data\":\"{}\"}}", large_string))
        },
        "type": "public-key"
    })
}

/// Empty values fixture for testing validation
pub fn empty_values_payload() -> serde_json::Value {
    json!({
        "id": "",
        "rawId": "",
        "response": {
            "attestationObject": "",
            "clientDataJSON": ""
        },
        "type": ""
    })
}

/// Tampered client data fixture for security testing
pub fn tampered_client_data() -> serde_json::Value {
    json!({
        "id": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "response": {
            "attestationObject": URL_SAFE_NO_PAD.encode("mock_attestation_object"),
            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"different_challenge\",\"origin\":\"http://malicious.com\"}")
        },
        "type": "public-key"
    })
}

/// Replay attack fixture with old challenge
pub fn replay_attack_payload() -> serde_json::Value {
    json!({
        "id": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode("mock_authenticator_data"),
            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\",\"challenge\":\"old_used_challenge\",\"origin\":\"http://localhost:8080\"}"),
            "signature": URL_SAFE_NO_PAD.encode("mock_signature"),
            "userHandle": URL_SAFE_NO_PAD.encode("user_id_123")
        },
        "type": "public-key"
    })
}

/// Invalid RP ID fixture for testing origin validation
pub fn invalid_rp_id_payload() -> serde_json::Value {
    json!({
        "id": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "rawId": URL_SAFE_NO_PAD.encode("credential_id_123"),
        "response": {
            "attestationObject": URL_SAFE_NO_PAD.encode("mock_attestation_object"),
            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"valid_challenge_12345\",\"origin\":\"http://evil.com\"}")
        },
        "type": "public-key"
    })
}

/// Test database configuration
pub fn test_database_config() -> HashMap<String, String> {
    let mut config = HashMap::new();
    config.insert("database_url".to_string(), "postgresql://test:test@localhost:5432/fido_test".to_string());
    config.insert("max_connections".to_string(), "5".to_string());
    config.insert("min_connections".to_string(), "1".to_string());
    config
}

/// Test WebAuthn configuration
pub fn test_webauthn_config() -> HashMap<String, String> {
    let mut config = HashMap::new();
    config.insert("rp_name".to_string(), "Test RP".to_string());
    config.insert("rp_id".to_string(), "localhost".to_string());
    config.insert("rp_origin".to_string(), "http://localhost:8080".to_string());
    config.insert("challenge_timeout_seconds".to_string(), "300".to_string());
    config
}