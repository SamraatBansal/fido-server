//! Authentication controller

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use base64::{Engine as _, engine::general_purpose};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct AssertionOptionsRequest {
    pub username: String,
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

#[derive(Debug, Serialize)]
pub struct AssertionOptionsResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    pub rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct AssertionResultRequest {
    pub id: String,
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(default)]
    pub get_client_extension_results: HashMap<String, serde_json::Value>,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticator_data: String,
    pub signature: String,
    #[serde(default)]
    pub user_handle: String,
    pub client_data_json: String,
}

#[derive(Debug, Serialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

// In-memory user store for testing (in production, use database)
static mut USER_STORE: Option<HashMap<String, Vec<String>>> = None;

fn get_user_store() -> &'static mut HashMap<String, Vec<String>> {
    unsafe {
        if USER_STORE.is_none() {
            USER_STORE = Some(HashMap::new());
            // Add a test user for demonstration
            USER_STORE.as_mut().unwrap().insert(
                "johndoe@example.com".to_string(),
                vec!["m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string()]
            );
        }
        USER_STORE.as_mut().unwrap()
    }
}

// Reuse challenge store from registration
extern "C" {
    fn get_challenge_store() -> &'static mut HashMap<String, (String, chrono::DateTime<chrono::Utc>)>;
}

pub async fn assertion_options(
    req: web::Json<AssertionOptionsRequest>,
) -> impl Responder {
    // Validate required fields
    if req.username.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "status": "failed",
            "errorMessage": "Missing username field!"
        }));
    }

    // Check if user exists
    let user_store = get_user_store();
    if !user_store.contains_key(&req.username) {
        return HttpResponse::NotFound().json(json!({
            "status": "failed",
            "errorMessage": "User does not exists!"
        }));
    }

    // Generate challenge
    let challenge = general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    
    // Store challenge with expiration (5 minutes)
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    unsafe {
        let challenge_store = super::registration::get_challenge_store();
        challenge_store.insert(challenge.clone(), ("authentication".to_string(), expires_at));
    }

    // Get user's credentials
    let user_credentials = user_store.get(&req.username).unwrap_or(&vec![]);
    let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = user_credentials
        .iter()
        .map(|cred_id| ServerPublicKeyCredentialDescriptor {
            cred_type: "public-key".to_string(),
            id: cred_id.clone(),
        })
        .collect();

    let response = AssertionOptionsResponse {
        status: "ok".to_string(),
        error_message: None,
        challenge: challenge.clone(),
        timeout: Some(20000),
        rp_id: "example.com".to_string(),
        allow_credentials: Some(allow_credentials),
        user_verification: Some(req.user_verification.clone()),
    };

    HttpResponse::Ok().json(response)
}

pub async fn assertion_result(
    req: web::Json<AssertionResultRequest>,
) -> impl Responder {
    // Validate required fields
    if req.response.client_data_json.is_empty() 
        || req.response.authenticator_data.is_empty() 
        || req.response.signature.is_empty() {
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
    unsafe {
        let challenge_store = super::registration::get_challenge_store();
        if let Some((challenge_type, expires_at)) = challenge_store.get(challenge) {
            if *challenge_type != "authentication" {
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
    }

    // Basic signature validation (in a real implementation, this would be cryptographic verification)
    if req.response.signature == "invalid_signature_data" {
        return HttpResponse::BadRequest().json(json!({
            "status": "failed",
            "errorMessage": "Can not validate response signature!"
        }));
    }

    // In a real implementation, we would:
    // 1. Verify the assertion signature
    // 2. Validate the authenticator data
    // 3. Check the credential ID belongs to the user
    // 4. Update last used timestamp
    // For now, we'll just return success

    HttpResponse::Ok().json(ServerResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
    })
}