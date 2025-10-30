//! Simplified FIDO2 server implementation

#![allow(dead_code)]

use actix_web::{web, App, HttpResponse, HttpServer, Result, middleware::Logger};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose};

/// Simple server state
pub struct SimpleState {
    users: Arc<Mutex<HashMap<String, SimpleUser>>>,
    credentials: Arc<Mutex<HashMap<String, SimpleCredential>>>,
    challenges: Arc<Mutex<HashMap<String, SimpleChallenge>>>,
}

#[derive(Debug, Clone)]
pub struct SimpleUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SimpleCredential {
    pub id: String,
    pub user_id: String,
    pub credential_id: String,
    pub public_key: String,
    pub sign_count: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SimpleChallenge {
    pub challenge: String,
    pub user_id: String,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

/// Standard server response
#[derive(Debug, Serialize)]
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

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
        }
    }
}

/// Registration options request
#[derive(Debug, Deserialize)]
pub struct RegistrationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelection>,
    pub attestation: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct AuthenticatorSelection {
    pub require_resident_key: Option<bool>,
    pub authenticator_attachment: Option<String>,
    pub user_verification: Option<String>,
}

/// Registration options response
#[derive(Debug, Serialize)]
pub struct RegistrationOptionsResponse {
    #[serde(flatten)]
    pub response: ServerResponse,
    pub rp: RpEntity,
    pub user: UserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout: u32,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    pub authenticator_selection: Option<AuthenticatorSelection>,
    pub attestation: String,
}

#[derive(Debug, Serialize)]
pub struct RpEntity {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

#[derive(Debug, Serialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
}

/// Registration result request
#[derive(Debug, Deserialize)]
pub struct RegistrationResultRequest {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: RegistrationResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Registration result response
#[derive(Debug, Serialize)]
pub struct RegistrationResultResponse {
    #[serde(flatten)]
    pub response: ServerResponse,
    pub credential_id: Option<String>,
}

/// Authentication options request
#[derive(Debug, Deserialize)]
pub struct AuthenticationOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Authentication options response
#[derive(Debug, Serialize)]
pub struct AuthenticationOptionsResponse {
    #[serde(flatten)]
    pub response: ServerResponse,
    pub challenge: String,
    pub timeout: u32,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Authentication result request
#[derive(Debug, Deserialize)]
pub struct AuthenticationResultRequest {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: AuthenticationResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Authentication result response
#[derive(Debug, Serialize)]
pub struct AuthenticationResultResponse {
    #[serde(flatten)]
    pub response: ServerResponse,
}

impl SimpleState {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            credentials: Arc::new(Mutex::new(HashMap::new())),
            challenges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn generate_challenge(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
    }

    fn store_challenge(&self, challenge: String, user_id: String, challenge_type: String) {
        let stored_challenge = SimpleChallenge {
            challenge: challenge.clone(),
            user_id,
            challenge_type,
            expires_at: Utc::now() + Duration::minutes(5),
        };
        self.challenges.lock().unwrap().insert(challenge, stored_challenge);
    }

    fn consume_challenge(&self, challenge: &str, challenge_type: &str) -> Option<SimpleChallenge> {
        let mut challenges = self.challenges.lock().unwrap();
        if let Some(stored_challenge) = challenges.remove(challenge) {
            if stored_challenge.challenge_type == challenge_type && stored_challenge.expires_at > Utc::now() {
                return Some(stored_challenge);
            }
        }
        None
    }

    fn get_or_create_user(&self, username: &str, display_name: &str) -> SimpleUser {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get(username) {
            user.clone()
        } else {
            let user = SimpleUser {
                id: general_purpose::URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
                username: username.to_string(),
                display_name: display_name.to_string(),
                created_at: Utc::now(),
            };
            users.insert(username.to_string(), user.clone());
            user
        }
    }

    fn get_user_credentials(&self, user_id: &str) -> Vec<SimpleCredential> {
        let credentials = self.credentials.lock().unwrap();
        credentials
            .values()
            .filter(|cred| cred.user_id == user_id)
            .cloned()
            .collect()
    }

    fn store_credential(&self, user_id: &str, credential_id: &str, public_key: &str) {
        let credential = SimpleCredential {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            credential_id: credential_id.to_string(),
            public_key: public_key.to_string(),
            sign_count: 0,
            created_at: Utc::now(),
        };
        self.credentials.lock().unwrap().insert(credential_id.to_string(), credential);
    }

    fn get_credential(&self, credential_id: &str) -> Option<SimpleCredential> {
        self.credentials.lock().unwrap().get(credential_id).cloned()
    }

    fn update_credential_sign_count(&self, credential_id: &str, sign_count: u32) {
        if let Some(credential) = self.credentials.lock().unwrap().get_mut(credential_id) {
            credential.sign_count = sign_count;
        }
    }
}

/// Generate registration options
pub async fn generate_registration_options(
    state: web::Data<SimpleState>,
    request: web::Json<RegistrationOptionsRequest>,
) -> Result<HttpResponse> {
    // Validate input
    if request.username.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Username is required")));
    }
    if request.display_name.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Display name is required")));
    }

    // Get or create user
    let user = state.get_or_create_user(&request.username, &request.display_name);

    // Get existing credentials for exclusion
    let existing_credentials = state.get_user_credentials(&user.id);
    let exclude_credentials: Vec<CredentialDescriptor> = existing_credentials
        .into_iter()
        .map(|cred| CredentialDescriptor {
            cred_type: "public-key".to_string(),
            id: cred.credential_id,
        })
        .collect();

    // Generate challenge
    let challenge = state.generate_challenge();
    state.store_challenge(challenge.clone(), user.id.clone(), "registration".to_string());

    let response = RegistrationOptionsResponse {
        response: ServerResponse::success(),
        rp: RpEntity {
            name: "FIDO Server".to_string(),
        },
        user: UserEntity {
            id: user.id,
            name: user.username,
            display_name: user.display_name,
        },
        challenge,
        pub_key_cred_params: vec![
            PubKeyCredParam {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            },
        ],
        timeout: 60000,
        exclude_credentials,
        authenticator_selection: request.authenticator_selection.clone(),
        attestation: request.attestation.clone().unwrap_or_else(|| "none".to_string()),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Verify registration
pub async fn verify_registration(
    state: web::Data<SimpleState>,
    request: web::Json<RegistrationResultRequest>,
) -> Result<HttpResponse> {
    // Decode client data JSON to get challenge
    let client_data_json = general_purpose::URL_SAFE_NO_PAD.decode(&request.response.client_data_json);
    if client_data_json.is_err() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid client data JSON")));
    }

    let client_data: serde_json::Value = serde_json::from_slice(&client_data_json.unwrap())
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid client data JSON format"))?;

    let challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Consume challenge
    let stored_challenge = state.consume_challenge(challenge, "registration");
    if stored_challenge.is_none() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid or expired challenge")));
    }

    // In a real implementation, we would verify the attestation here
    // For now, we'll just store the credential
    let user_id = stored_challenge.unwrap().user_id;
    state.store_credential(&user_id, &request.id, "mock_public_key");

    let response = RegistrationResultResponse {
        response: ServerResponse::success(),
        credential_id: Some(request.id.clone()),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Generate authentication options
pub async fn generate_authentication_options(
    state: web::Data<SimpleState>,
    request: web::Json<AuthenticationOptionsRequest>,
) -> Result<HttpResponse> {
    // Validate input
    if request.username.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Username is required")));
    }

    // Get user
    let users = state.users.lock().unwrap();
    let user = users.get(&request.username);
    if user.is_none() {
        return Ok(HttpResponse::NotFound().json(ServerResponse::error("User not found")));
    }
    let user = user.unwrap();

    // Get user credentials
    let credentials = state.get_user_credentials(&user.id);
    if credentials.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("No credentials found for user")));
    }

    // Convert to allow credentials format
    let allow_credentials: Vec<CredentialDescriptor> = credentials
        .into_iter()
        .map(|cred| CredentialDescriptor {
            cred_type: "public-key".to_string(),
            id: cred.credential_id,
        })
        .collect();

    // Generate challenge
    let challenge = state.generate_challenge();
    state.store_challenge(challenge.clone(), user.id.clone(), "authentication".to_string());

    let response = AuthenticationOptionsResponse {
        response: ServerResponse::success(),
        challenge,
        timeout: 60000,
        rp_id: "localhost".to_string(),
        allow_credentials,
        user_verification: request.user_verification.clone(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Verify authentication
pub async fn verify_authentication(
    state: web::Data<SimpleState>,
    request: web::Json<AuthenticationResultRequest>,
) -> Result<HttpResponse> {
    // Decode client data JSON to get challenge
    let client_data_json = general_purpose::URL_SAFE_NO_PAD.decode(&request.response.client_data_json);
    if client_data_json.is_err() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid client data JSON")));
    }

    let client_data: serde_json::Value = serde_json::from_slice(&client_data_json.unwrap())
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid client data JSON format"))?;

    let challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Consume challenge
    let stored_challenge = state.consume_challenge(challenge, "authentication");
    if stored_challenge.is_none() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid or expired challenge")));
    }

    // Get credential
    let credential = state.get_credential(&request.id);
    if credential.is_none() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Credential not found")));
    }

    // In a real implementation, we would verify the signature here
    // For now, we'll just update the sign count
    state.update_credential_sign_count(&request.id, 1);

    let response = AuthenticationResultResponse {
        response: ServerResponse::success(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Health check
pub async fn health_check() -> Result<HttpResponse> {
    let response = serde_json::json!({
        "status": "healthy",
        "timestamp": Utc::now(),
        "version": env!("CARGO_PKG_VERSION")
    });
    Ok(HttpResponse::Ok().json(response))
}

/// Configure routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/attestation")
            .route("/options", web::post().to(generate_registration_options))
            .route("/result", web::post().to(verify_registration))
    )
    .service(
        web::scope("/assertion")
            .route("/options", web::post().to(generate_authentication_options))
            .route("/result", web::post().to(verify_authentication))
    )
    .route("/health", web::get().to(health_check));
}

/// Create simple server
pub async fn create_simple_server() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let state = web::Data::new(SimpleState::new());

    log::info!("Starting FIDO Server on http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            .configure(configure_routes)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}