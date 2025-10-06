//! Test data factory for generating various test scenarios

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// Factory for generating test data
pub struct TestDataFactory;

impl TestDataFactory {
    /// Generate a random base64url string
    pub fn random_base64url(length: usize) -> String {
        let rng = rand::thread_rng();
        let random_string: String = rng
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        URL_SAFE_NO_PAD.encode(random_string.as_bytes())
    }

    /// Generate a valid attestation options request
    pub fn attestation_options_request(
        username: Option<&str>,
        display_name: Option<&str>,
        attestation: Option<&str>,
        user_verification: Option<&str>,
    ) -> Value {
        json!({
            "username": username.unwrap_or("test@example.com"),
            "displayName": display_name.unwrap_or("Test User"),
            "attestation": attestation.unwrap_or("direct"),
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": user_verification.unwrap_or("preferred")
            }
        })
    }

    /// Generate an invalid attestation options request
    pub fn invalid_attestation_options_request(error_type: &str) -> Value {
        match error_type {
            "missing_username" => json!({
                "displayName": "Test User",
                "attestation": "direct"
            }),
            "missing_display_name" => json!({
                "username": "test@example.com",
                "attestation": "direct"
            }),
            "invalid_attestation" => json!({
                "username": "test@example.com",
                "displayName": "Test User",
                "attestation": "invalid_attestation"
            }),
            "invalid_user_verification" => json!({
                "username": "test@example.com",
                "displayName": "Test User",
                "attestation": "direct",
                "authenticatorSelection": {
                    "userVerification": "invalid_verification"
                }
            }),
            "empty_username" => json!({
                "username": "",
                "displayName": "Test User",
                "attestation": "direct"
            }),
            "oversized_username" => {
                let oversized = "x".repeat(1000);
                json!({
                    "username": oversized,
                    "displayName": "Test User",
                    "attestation": "direct"
                })
            }
            _ => json!({}),
        }
    }

    /// Generate a valid assertion options request
    pub fn assertion_options_request(
        username: Option<&str>,
        user_verification: Option<&str>,
    ) -> Value {
        json!({
            "username": username.unwrap_or("test@example.com"),
            "userVerification": user_verification.unwrap_or("preferred")
        })
    }

    /// Generate an invalid assertion options request
    pub fn invalid_assertion_options_request(error_type: &str) -> Value {
        match error_type {
            "missing_username" => json!({
                "userVerification": "preferred"
            }),
            "invalid_user_verification" => json!({
                "username": "test@example.com",
                "userVerification": "invalid_verification"
            }),
            "empty_username" => json!({
                "username": "",
                "userVerification": "preferred"
            }),
            _ => json!({}),
        }
    }

    /// Generate a valid attestation result request
    pub fn attestation_result_request(
        credential_id: Option<&str>,
        client_data_json: Option<&str>,
        attestation_object: Option<&str>,
    ) -> Value {
        let challenge = Self::random_base64url(32);
        let client_data = client_data_json.unwrap_or(&format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"http://localhost:8080\"}}",
            challenge
        ));

        json!({
            "id": credential_id.unwrap_or(&Self::random_base64url(32)),
            "rawId": credential_id.unwrap_or(&Self::random_base64url(32)),
            "response": {
                "attestationObject": attestation_object.unwrap_or(&Self::random_base64url(256)),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data)
            },
            "type": "public-key"
        })
    }

    /// Generate an invalid attestation result request
    pub fn invalid_attestation_result_request(error_type: &str) -> Value {
        match error_type {
            "missing_id" => json!({
                "rawId": Self::random_base64url(32),
                "response": {
                    "attestationObject": Self::random_base64url(256),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
                },
                "type": "public-key"
            }),
            "missing_response" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "type": "public-key"
            }),
            "missing_attestation_object" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
                },
                "type": "public-key"
            }),
            "missing_client_data" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "attestationObject": Self::random_base64url(256)
                },
                "type": "public-key"
            }),
            "invalid_type" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "attestationObject": Self::random_base64url(256),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
                },
                "type": "invalid-type"
            }),
            "malformed_base64_id" => json!({
                "id": "invalid_base64!",
                "rawId": Self::random_base64url(32),
                "response": {
                    "attestationObject": Self::random_base64url(256),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
                },
                "type": "public-key"
            }),
            "malformed_base64_attestation" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "attestationObject": "invalid_base64!",
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
                },
                "type": "public-key"
            }),
            "malformed_base64_client_data" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "attestationObject": Self::random_base64url(256),
                    "clientDataJSON": "invalid_base64!"
                },
                "type": "public-key"
            }),
            _ => json!({}),
        }
    }

    /// Generate a valid assertion result request
    pub fn assertion_result_request(
        credential_id: Option<&str>,
        client_data_json: Option<&str>,
        authenticator_data: Option<&str>,
        signature: Option<&str>,
        user_handle: Option<&str>,
    ) -> Value {
        let challenge = Self::random_base64url(32);
        let client_data = client_data_json.unwrap_or(&format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"http://localhost:8080\"}}",
            challenge
        ));

        json!({
            "id": credential_id.unwrap_or(&Self::random_base64url(32)),
            "rawId": credential_id.unwrap_or(&Self::random_base64url(32)),
            "response": {
                "authenticatorData": authenticator_data.unwrap_or(&Self::random_base64url(128)),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
                "signature": signature.unwrap_or(&Self::random_base64url(256)),
                "userHandle": user_handle.unwrap_or(&Self::random_base64url(32))
            },
            "type": "public-key"
        })
    }

    /// Generate an invalid assertion result request
    pub fn invalid_assertion_result_request(error_type: &str) -> Value {
        match error_type {
            "missing_id" => json!({
                "rawId": Self::random_base64url(32),
                "response": {
                    "authenticatorData": Self::random_base64url(128),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\"}"),
                    "signature": Self::random_base64url(256),
                    "userHandle": Self::random_base64url(32)
                },
                "type": "public-key"
            }),
            "missing_signature" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "authenticatorData": Self::random_base64url(128),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\"}"),
                    "userHandle": Self::random_base64url(32)
                },
                "type": "public-key"
            }),
            "missing_authenticator_data" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\"}"),
                    "signature": Self::random_base64url(256),
                    "userHandle": Self::random_base64url(32)
                },
                "type": "public-key"
            }),
            "invalid_client_data_type" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "authenticatorData": Self::random_base64url(128),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}"),
                    "signature": Self::random_base64url(256),
                    "userHandle": Self::random_base64url(32)
                },
                "type": "public-key"
            }),
            "mismatched_origin" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "authenticatorData": Self::random_base64url(128),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\",\"origin\":\"http://evil.com\"}"),
                    "signature": Self::random_base64url(256),
                    "userHandle": Self::random_base64url(32)
                },
                "type": "public-key"
            }),
            _ => json!({}),
        }
    }

    /// Generate malformed JSON for testing
    pub fn malformed_json(error_type: &str) -> String {
        match error_type {
            "invalid_syntax" => "{ invalid json }".to_string(),
            "truncated" => "{\"id\": \"test\"".to_string(),
            "extra_comma" => "{\"id\": \"test\",}".to_string(),
            "missing_quotes" => "{id: test}".to_string(),
            "null_bytes" => "{\"id\": \"test\u{0}\"}".to_string(),
            _ => String::new(),
        }
    }

    /// Generate oversized payloads for testing limits
    pub fn oversized_payload(payload_type: &str) -> Value {
        let large_string = "x".repeat(2_000_000); // 2MB
        match payload_type {
            "large_username" => json!({
                "username": large_string,
                "displayName": "Test User",
                "attestation": "direct"
            }),
            "large_display_name" => json!({
                "username": "test@example.com",
                "displayName": large_string,
                "attestation": "direct"
            }),
            "large_credential_id" => {
                let large_id = URL_SAFE_NO_PAD.encode(&large_string);
                json!({
                    "id": large_id,
                    "rawId": large_id,
                    "response": {
                        "attestationObject": Self::random_base64url(256),
                        "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
                    },
                    "type": "public-key"
                })
            },
            "large_attestation_object" => json!({
                "id": Self::random_base64url(32),
                "rawId": Self::random_base64url(32),
                "response": {
                    "attestationObject": URL_SAFE_NO_PAD.encode(&large_string),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
                },
                "type": "public-key"
            }),
            _ => json!({}),
        }
    }

    /// Generate edge case values
    pub fn edge_case_values(value_type: &str) -> Value {
        match value_type {
            "null_values" => json!({
                "username": null,
                "displayName": null,
                "attestation": null
            }),
            "empty_strings" => json!({
                "username": "",
                "displayName": "",
                "attestation": ""
            }),
            "whitespace_only" => json!({
                "username": "   ",
                "displayName": "\t\n",
                "attestation": "  "
            }),
            "unicode_characters" => json!({
                "username": "tëst@éxample.com",
                "displayName": "Tëst Üser 🦀",
                "attestation": "direct"
            }),
            "special_characters" => json!({
                "username": "test!@#$%^&*()_+-=[]{}|;':\",./<>?",
                "displayName": "Test User \\/*-+",
                "attestation": "direct"
            }),
            _ => json!({}),
        }
    }

    /// Generate security test vectors
    pub fn security_vector(vector_type: &str) -> Value {
        match vector_type {
            "sql_injection" => json!({
                "username": "'; DROP TABLE users; --",
                "displayName": "Test User",
                "attestation": "direct"
            }),
            "xss_attempt" => json!({
                "username": "<script>alert('xss')</script>@example.com",
                "displayName": "<img src=x onerror=alert('xss')>",
                "attestation": "direct"
            }),
            "path_traversal" => json!({
                "username": "../../../etc/passwd",
                "displayName": "Test User",
                "attestation": "direct"
            }),
            "command_injection" => json!({
                "username": "`rm -rf /`",
                "displayName": "Test User",
                "attestation": "direct"
            }),
            _ => json!({}),
        }
    }

    /// Generate performance test data
    pub fn performance_data(data_type: &str, count: usize) -> Vec<Value> {
        match data_type {
            "bulk_users" => (0..count)
                .map(|i| {
                    json!({
                        "username": format!("user{}@example.com", i),
                        "displayName": format!("User {}", i),
                        "attestation": "direct"
                    })
                })
                .collect(),
            "bulk_credentials" => (0..count)
                .map(|_| {
                    json!({
                        "id": Self::random_base64url(32),
                        "rawId": Self::random_base64url(32),
                        "response": {
                            "attestationObject": Self::random_base64url(256),
                            "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
                        },
                        "type": "public-key"
                    })
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}