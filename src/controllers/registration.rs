//! Registration controller

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct AttestationOptionsRequest {
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(default)]
    pub require_resident_key: Option<bool>,
    #[serde(default)]
    pub authenticator_attachment: Option<String>,
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
}

fn default_attestation() -> String {
    "none".to_string()
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

#[derive(Debug, Serialize)]
pub struct AttestationOptionsResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct AttestationResultRequest {
    pub id: String,
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(default)]
    pub get_client_extension_results: HashMap<String, serde_json::Value>,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Debug, Serialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

// In-memory challenge store for testing (in production, use Redis or database)
static mut CHALLENGE_STORE: Option<HashMap<String, (String, chrono::DateTime<chrono::Utc>)>> = None;

pub fn get_challenge_store() -> &'static mut HashMap<String, (String, chrono::DateTime<chrono::Utc>)> {
    unsafe {
        if CHALLENGE_STORE.is_none() {
            CHALLENGE_STORE = Some(HashMap::new());
        }
        CHALLENGE_STORE.as_mut().unwrap()
    }
}

pub async fn attestation_options(
    req: web::Json<AttestationOptionsRequest>,
) -> impl Responder {
    // Validate required fields
    if req.username.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "status": "failed",
            "errorMessage": "Missing username field!"
        }));
    }

    if req.display_name.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "status": "failed",
            "errorMessage": "Missing displayName field!"
        }));
    }

    // Generate challenge
    let challenge = general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    
    // Store challenge with expiration (5 minutes)
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    get_challenge_store().insert(challenge.clone(), ("registration".to_string(), expires_at));

    // Generate user ID
    let user_id = general_purpose::URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());

    let response = AttestationOptionsResponse {
        status: "ok".to_string(),
        error_message: None,
        rp: PublicKeyCredentialRpEntity {
            name: "Example Corporation".to_string(),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: user_id,
            name: req.username.clone(),
            display_name: req.display_name.clone(),
        },
        challenge: challenge.clone(),
        pub_key_cred_params: vec![
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            },
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -257, // RS256
            },
        ],
        timeout: Some(60000),
        exclude_credentials: Some(vec![]), // Empty for new registration
        authenticator_selection: req.authenticator_selection.clone(),
        attestation: Some(req.attestation.clone()),
    };

    HttpResponse::Ok().json(response)
}

pub async fn attestation_result(
    req: web::Json<AttestationResultRequest>,
) -> impl Responder {
    // Validate required fields
    if req.response.client_data_json.is_empty() || req.response.attestation_object.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "status": "failed",
            "errorMessage": "Missing required response fields!"
        }));
    }

    // Parse client data JSON to extract challenge
    let client_data: serde_json::Value = match serde_json::from_str(&req.response.client_data_json) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::BadRequest().json(json!({
                "status": "failed",
                "errorMessage": "Invalid clientDataJSON format!"
            }));
        }
    };

    let challenge = client_data.get("challenge")
        .and_then(|c| c.as_str())
        .unwrap_or("");

    // Validate challenge
    let challenge_store = get_challenge_store();
    if let Some((challenge_type, expires_at)) = challenge_store.get(challenge) {
        if *challenge_type != "registration" {
            return HttpResponse::BadRequest().json(json!({
                "status": "failed",
                "errorMessage": "Invalid challenge type!"
            }));
        }

        if chrono::Utc::now() > *expires_at {
            challenge_store.remove(challenge);
            return HttpResponse::BadRequest().json(json!({
                "status": "failed",
                "errorMessage": "Challenge has expired!"
            }));
        }

        // Remove used challenge
        challenge_store.remove(challenge);
    } else {
        return HttpResponse::BadRequest().json(json!({
            "status": "failed",
            "errorMessage": "Invalid or expired challenge!"
        }));
    }

    // In a real implementation, we would:
    // 1. Verify the attestation object
    // 2. Validate the signature
    // 3. Store the credential
    // For now, we'll just return success

    HttpResponse::Ok().json(ServerResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
    })
}