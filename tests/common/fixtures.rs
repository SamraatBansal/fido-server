//! Test fixtures for FIDO2/WebAuthn API testing

use crate::common::{TestContext, TestResult, constants::*};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Registration start request fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStartRequestFixture {
    pub username: String,
    pub display_name: String,
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelectionFixture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionFixture {
    pub authenticator_attachment: Option<String>,
    pub require_resident_key: bool,
    pub user_verification: String,
}

impl RegistrationStartRequestFixture {
    pub fn valid() -> Self {
        Self {
            username: TEST_USERNAME.to_string(),
            display_name: TEST_DISPLAY_NAME.to_string(),
            attestation: "direct".to_string(),
            authenticator_selection: AuthenticatorSelectionFixture {
                authenticator_attachment: Some("platform".to_string()),
                require_resident_key: false,
                user_verification: "preferred".to_string(),
            },
        }
    }

    pub fn with_username(username: &str) -> Self {
        let mut fixture = Self::valid();
        fixture.username = username.to_string();
        fixture
    }

    pub fn with_attestation(attestation: &str) -> Self {
        let mut fixture = Self::valid();
        fixture.attestation = attestation.to_string();
        fixture
    }

    pub fn invalid_missing_username() -> Self {
        let mut fixture = Self::valid();
        fixture.username = "".to_string();
        fixture
    }

    pub fn invalid_missing_display_name() -> Self {
        let mut fixture = Self::valid();
        fixture.display_name = "".to_string();
        fixture
    }

    pub fn invalid_attestation_format() -> Self {
        let mut fixture = Self::valid();
        fixture.attestation = "invalid_format".to_string();
        fixture
    }

    pub fn oversized_username() -> Self {
        let mut fixture = Self::valid();
        fixture.username = "a".repeat(300); // Exceed typical limits
        fixture
    }
}

/// Registration start response fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStartResponseFixture {
    pub challenge: String,
    pub rp: RpEntityFixture,
    pub user: UserEntityFixture,
    pub pub_key_cred_params: Vec<PubKeyCredParamFixture>,
    pub timeout: u32,
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelectionFixture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpEntityFixture {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntityFixture {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParamFixture {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

impl RegistrationStartResponseFixture {
    pub fn from_context(context: &TestContext) -> Self {
        Self {
            challenge: context.challenge.clone(),
            rp: RpEntityFixture {
                name: TEST_RP_NAME.to_string(),
                id: TEST_RP_ID.to_string(),
            },
            user: UserEntityFixture {
                id: general_purpose::URL_SAFE.encode(context.user_id.as_bytes()),
                name: context.username.clone(),
                display_name: context.display_name.clone(),
            },
            pub_key_cred_params: vec![
                PubKeyCredParamFixture {
                    cred_type: "public-key".to_string(),
                    alg: -7, // ES256
                },
                PubKeyCredParamFixture {
                    cred_type: "public-key".to_string(),
                    alg: -257, // RS256
                },
            ],
            timeout: 60000,
            attestation: "direct".to_string(),
            authenticator_selection: AuthenticatorSelectionFixture {
                authenticator_attachment: Some("platform".to_string()),
                require_resident_key: false,
                user_verification: "preferred".to_string(),
            },
        }
    }

    pub fn invalid_missing_challenge() -> Self {
        let mut fixture = Self::from_context(&TestContext::default());
        fixture.challenge = "".to_string();
        fixture
    }

    pub fn invalid_missing_rp() -> Self {
        let mut fixture = Self::from_context(&TestContext::default());
        fixture.rp.id = "".to_string();
        fixture
    }

    pub fn invalid_timeout() -> Self {
        let mut fixture = Self::from_context(&TestContext::default());
        fixture.timeout = 0;
        fixture
    }
}

/// Registration finish request fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishRequestFixture {
    pub id: String,
    pub raw_id: String,
    pub response: AttestationResponseFixture,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponseFixture {
    pub attestation_object: String,
    pub client_data_json: String,
}

impl RegistrationFinishRequestFixture {
    pub fn valid(context: &TestContext) -> Self {
        Self {
            id: context.credential_id.clone(),
            raw_id: context.credential_id.clone(),
            response: AttestationResponseFixture {
                attestation_object: create_mock_attestation_object(),
                client_data_json: create_mock_client_data_json(&context.challenge, "webauthn.create"),
            },
            cred_type: "public-key".to_string(),
        }
    }

    pub fn with_credential_id(credential_id: &str) -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.id = credential_id.to_string();
        fixture.raw_id = credential_id.to_string();
        fixture
    }

    pub fn invalid_missing_id() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.id = "".to_string();
        fixture
    }

    pub fn invalid_missing_attestation() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.response.attestation_object = "".to_string();
        fixture
    }

    pub fn invalid_missing_client_data() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.response.client_data_json = "".to_string();
        fixture
    }

    pub fn invalid_base64_attestation() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.response.attestation_object = "invalid_base64!".to_string();
        fixture
    }

    pub fn invalid_base64_client_data() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.response.client_data_json = "invalid_base64!".to_string();
        fixture
    }

    pub fn malformed_client_data_json() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.response.client_data_json = general_purpose::URL_SAFE.encode(b"invalid json");
        fixture
    }
}

/// Registration finish response fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishResponseFixture {
    pub status: String,
    pub error_message: String,
}

impl RegistrationFinishResponseFixture {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            status: "error".to_string(),
            error_message: message.to_string(),
        }
    }
}

/// Authentication start request fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStartRequestFixture {
    pub username: String,
    pub user_verification: String,
}

impl AuthenticationStartRequestFixture {
    pub fn valid() -> Self {
        Self {
            username: TEST_USERNAME.to_string(),
            user_verification: "preferred".to_string(),
        }
    }

    pub fn with_username(username: &str) -> Self {
        let mut fixture = Self::valid();
        fixture.username = username.to_string();
        fixture
    }

    pub fn invalid_missing_username() -> Self {
        let mut fixture = Self::valid();
        fixture.username = "".to_string();
        fixture
    }

    pub fn invalid_user_verification() -> Self {
        let mut fixture = Self::valid();
        fixture.user_verification = "invalid".to_string();
        fixture
    }
}

/// Authentication start response fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStartResponseFixture {
    pub challenge: String,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredentialFixture>,
    pub timeout: u32,
    pub user_verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowCredentialFixture {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
}

impl AuthenticationStartResponseFixture {
    pub fn from_context(context: &TestContext) -> Self {
        Self {
            challenge: context.challenge.clone(),
            rp_id: TEST_RP_ID.to_string(),
            allow_credentials: vec![AllowCredentialFixture {
                cred_type: "public-key".to_string(),
                id: context.credential_id.clone(),
            }],
            timeout: 60000,
            user_verification: "preferred".to_string(),
        }
    }

    pub fn invalid_missing_challenge() -> Self {
        let mut fixture = Self::from_context(&TestContext::default());
        fixture.challenge = "".to_string();
        fixture
    }

    pub fn invalid_missing_rp_id() -> Self {
        let mut fixture = Self::from_context(&TestContext::default());
        fixture.rp_id = "".to_string();
        fixture
    }

    pub fn invalid_empty_credentials() -> Self {
        let mut fixture = Self::from_context(&TestContext::default());
        fixture.allow_credentials = vec![];
        fixture
    }
}

/// Authentication finish request fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFinishRequestFixture {
    pub id: String,
    pub raw_id: String,
    pub response: AssertionResponseFixture,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResponseFixture {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: String,
}

impl AuthenticationFinishRequestFixture {
    pub fn valid(context: &TestContext) -> Self {
        Self {
            id: context.credential_id.clone(),
            raw_id: context.credential_id.clone(),
            response: AssertionResponseFixture {
                authenticator_data: create_mock_authenticator_data(),
                client_data_json: create_mock_client_data_json(&context.challenge, "webauthn.get"),
                signature: create_mock_signature(),
                user_handle: general_purpose::URL_SAFE.encode(context.user_id.as_bytes()),
            },
            cred_type: "public-key".to_string(),
        }
    }

    pub fn with_credential_id(credential_id: &str) -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.id = credential_id.to_string();
        fixture.raw_id = credential_id.to_string();
        fixture
    }

    pub fn invalid_missing_id() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.id = "".to_string();
        fixture
    }

    pub fn invalid_missing_signature() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.response.signature = "".to_string();
        fixture
    }

    pub fn invalid_missing_authenticator_data() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.response.authenticator_data = "".to_string();
        fixture
    }

    pub fn invalid_base64_signature() -> Self {
        let mut fixture = Self::valid(&TestContext::default());
        fixture.response.signature = "invalid_base64!".to_string();
        fixture
    }
}

/// Authentication finish response fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFinishResponseFixture {
    pub status: String,
    pub error_message: String,
}

impl AuthenticationFinishResponseFixture {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            status: "error".to_string(),
            error_message: message.to_string(),
        }
    }
}

// Helper functions to create mock data
fn create_mock_attestation_object() -> String {
    // Mock CBOR-encoded attestation object (simplified for testing)
    let mock_data = vec![
        0xa3, // Map with 3 items
        0x01, 0x26, // fmt: "packed"
        0x02, 0x58, 0x40, // attStmt: bytes(64)
    ];
    general_purpose::URL_SAFE.encode(&mock_data)
}

fn create_mock_client_data_json(challenge: &str, ceremony_type: &str) -> String {
    let client_data = serde_json::json!({
        "type": ceremony_type,
        "challenge": challenge,
        "origin": "http://localhost:8080",
        "crossOrigin": false
    });
    general_purpose::URL_SAFE.encode(client_data.to_string().as_bytes())
}

fn create_mock_authenticator_data() -> String {
    // Mock authenticator data (37 bytes minimum)
    let mock_data = vec![
        0x49960de5880e8c687434170f6476605b, // RP ID hash (mock)
        0x01, // Flags (user present)
        0x00, 0x00, 0x00, 0x01, // Sign count
    ];
    general_purpose::URL_SAFE.encode(&mock_data)
}

fn create_mock_signature() -> String {
    // Mock ECDSA signature
    let mock_sig = vec![0u8; 64]; // 64 bytes for ECDSA signature
    general_purpose::URL_SAFE.encode(&mock_sig)
}