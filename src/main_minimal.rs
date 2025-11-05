use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;
use webauthn_rs::prelude::*;

// Error types
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::WebauthnError),
    
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    
    #[error("Validation error: {message}")]
    Validation { message: String },
    
    #[error("User not found: {username}")]
    UserNotFound { username: String },
    
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    
    #[error("Missing required field: {field}")]
    MissingField { field: String },
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status_code, error_message) = match &self {
            AppError::WebAuthn(_) => (StatusCode::BAD_REQUEST, "WebAuthn operation failed"),
            AppError::Serde(_) => (StatusCode::BAD_REQUEST, "Invalid JSON format"),
            AppError::Validation { .. } => (StatusCode::BAD_REQUEST, &self.to_string()),
            AppError::UserNotFound { .. } => (StatusCode::NOT_FOUND, "User not found"),
            AppError::ChallengeNotFound => (StatusCode::BAD_REQUEST, "Invalid or expired challenge"),
            AppError::MissingField { .. } => (StatusCode::BAD_REQUEST, &self.to_string()),
        };

        let error_response = serde_json::json!({
            "status": "failed",
            "errorMessage": error_message
        });

        tracing::error!("API Error: {} - {}", status_code, self);
        (status_code, Json(error_response)).into_response()
    }
}

// Request/Response types matching FIDO conformance format
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationOptionsRequest {
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default)]
    pub attestation: Option<AttestationConveyancePreference>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: UserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials", default)]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionOptionsRequest {
    pub username: String,
    #[serde(default)]
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials", default)]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialRequest {
    pub id: String,
    pub response: ResponseData,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResponseData {
    Attestation(AttestationResponseData),
    Assertion(AssertionResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponseData {
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponseData {
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
    pub client_data_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl SimpleResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
        }
    }
}

// In-memory storage
#[derive(Debug, Clone)]
pub struct StoredUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_id: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub passkey: Passkey,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChallenge {
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub state: serde_json::Value,
    pub expires_at: DateTime<Utc>,
}

// Application state
#[derive(Clone)]
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
    pub users: Arc<DashMap<String, StoredUser>>, // username -> user
    pub credentials: Arc<DashMap<String, Vec<StoredCredential>>>, // username -> credentials
    pub challenges: Arc<DashMap<String, StoredChallenge>>, // challenge_value -> challenge_state
}

impl AppState {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let rp_id = "localhost";
        let rp_origin = url::Url::parse("http://localhost:3000")?;
        let rp_name = "FIDO2 Test Server";

        let webauthn = WebauthnBuilder::new(rp_id, &rp_origin)?
            .rp_name(rp_name)
            .build()?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
            users: Arc::new(DashMap::new()),
            credentials: Arc::new(DashMap::new()),
            challenges: Arc::new(DashMap::new()),
        })
    }

    fn find_or_create_user(&self, username: &str, display_name: &str) -> StoredUser {
        if let Some(user) = self.users.get(username) {
            user.clone()
        } else {
            let user_id = rand::random::<[u8; 64]>().to_vec();
            let user = StoredUser {
                id: Uuid::new_v4(),
                username: username.to_string(),
                display_name: display_name.to_string(),
                user_id,
                created_at: Utc::now(),
            };
            self.users.insert(username.to_string(), user.clone());
            user
        }
    }

    fn get_user_credentials(&self, username: &str) -> Vec<StoredCredential> {
        self.credentials.get(username).map(|c| c.clone()).unwrap_or_default()
    }

    fn store_credential(&self, username: &str, user_id: Uuid, passkey: Passkey) {
        let credential = StoredCredential {
            id: Uuid::new_v4(),
            user_id,
            passkey,
            created_at: Utc::now(),
        };

        self.credentials.entry(username.to_string()).or_insert_with(Vec::new).push(credential);
    }

    fn find_credential(&self, credential_id: &[u8]) -> Option<StoredCredential> {
        for entry in self.credentials.iter() {
            for cred in entry.value() {
                if cred.passkey.cred_id() == credential_id {
                    return Some(cred.clone());
                }
            }
        }
        None
    }
}

// Helper functions
fn generate_random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}

fn extract_challenge_from_client_data(client_data_json: &str) -> Result<String, AppError> {
    let client_data_bytes = base64::decode_config(client_data_json, base64::URL_SAFE_NO_PAD)
        .map_err(|_| AppError::Validation { message: "Invalid clientDataJSON encoding".to_string() })?;
    
    let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
        .map_err(|_| AppError::Validation { message: "Invalid clientDataJSON format".to_string() })?;
    
    client_data
        .get("challenge")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Validation { message: "Missing challenge in clientDataJSON".to_string() })
}

// API endpoints
async fn post_attestation_options(
    State(state): State<AppState>,
    Json(request): Json<AttestationOptionsRequest>,
) -> Result<Json<AttestationOptionsResponse>, AppError> {
    tracing::info!("Registration request for user: {}", request.username);

    if request.username.is_empty() {
        return Err(AppError::MissingField { field: "username".to_string() });
    }
    if request.display_name.is_empty() {
        return Err(AppError::MissingField { field: "displayName".to_string() });
    }

    // Find or create user
    let user = state.find_or_create_user(&request.username, &request.display_name);

    // Get existing credentials for exclude list
    let existing_credentials = state.get_user_credentials(&request.username);
    let exclude_credentials: Option<Vec<CredentialID>> = if existing_credentials.is_empty() {
        None
    } else {
        Some(existing_credentials.iter().map(|c| c.passkey.cred_id().to_vec()).collect())
    };

    // Convert user_id to Uuid for WebAuthn
    let user_uuid = if user.user_id.len() >= 16 {
        Uuid::from_slice(&user.user_id[..16]).unwrap_or_else(|_| Uuid::new_v4())
    } else {
        Uuid::new_v4()
    };

    // Start WebAuthn registration
    let (creation_challenge, registration_state) = state.webauthn.start_passkey_registration(
        user_uuid,
        &user.username,
        &user.display_name,
        exclude_credentials,
    )?;

    // Store challenge state using the challenge value
    let challenge_id = creation_challenge.challenge.clone();
    let expires_at = Utc::now() + Duration::minutes(5);

    let stored_challenge = StoredChallenge {
        user_id: Some(user.id),
        challenge_type: "registration".to_string(),
        state: serde_json::to_value(&registration_state)?,
        expires_at,
    };

    state.challenges.insert(challenge_id, stored_challenge);

    // Build response
    let response = AttestationOptionsResponse {
        status: "ok".to_string(),
        error_message: String::new(),
        rp: creation_challenge.rp,
        user: UserEntity {
            id: base64::encode_config(&user.user_id, base64::URL_SAFE_NO_PAD),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
        },
        challenge: creation_challenge.challenge,
        pub_key_cred_params: creation_challenge.pub_key_cred_params,
        timeout: Some(60000),
        exclude_credentials: creation_challenge.exclude_credentials.iter().map(|cred| {
            CredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: base64::encode_config(&cred.id, base64::URL_SAFE_NO_PAD),
                transports: None,
            }
        }).collect(),
        authenticator_selection: request.authenticator_selection,
        attestation: request.attestation,
    };

    Ok(Json(response))
}

async fn post_attestation_result(
    State(state): State<AppState>,
    Json(credential): Json<CredentialRequest>,
) -> Result<Json<SimpleResponse>, AppError> {
    tracing::info!("Registration result for credential: {}", credential.id);

    // Extract challenge from clientDataJSON
    if let ResponseData::Attestation(response) = &credential.response {
        let challenge_value = extract_challenge_from_client_data(&response.client_data_json)?;

        // Find stored challenge
        let stored_challenge = state.challenges.get(&challenge_value)
            .ok_or(AppError::ChallengeNotFound)?
            .clone();

        // Check expiration
        if stored_challenge.expires_at < Utc::now() {
            state.challenges.remove(&challenge_value);
            return Err(AppError::ChallengeNotFound);
        }

        // Remove challenge (one-time use)
        state.challenges.remove(&challenge_value);

        // Parse registration state
        let registration_state: PasskeyRegistration = serde_json::from_value(stored_challenge.state)?;

        // Get user
        let user_id = stored_challenge.user_id.ok_or(AppError::ChallengeNotFound)?;
        let user = state.users.iter()
            .find(|entry| entry.value().id == user_id)
            .map(|entry| entry.value().clone())
            .ok_or(AppError::UserNotFound { username: "unknown".to_string() })?;

        // Convert to RegisterPublicKeyCredential
        let client_data_json = base64::decode_config(&response.client_data_json, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::Validation { message: "Invalid clientDataJSON encoding".to_string() })?;
        
        let attestation_object = base64::decode_config(&response.attestation_object, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::Validation { message: "Invalid attestationObject encoding".to_string() })?;

        let credential_id_bytes = base64::decode_config(&credential.id, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::Validation { message: "Invalid credential ID encoding".to_string() })?;

        let reg_credential = RegisterPublicKeyCredential {
            id: credential.id.clone(),
            raw_id: credential_id_bytes,
            response: AuthenticatorAttestationResponseRaw {
                client_data_json,
                attestation_object,
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        };

        // Complete WebAuthn registration
        let passkey = state.webauthn.finish_passkey_registration(&reg_credential, &registration_state)?;

        // Store credential
        state.store_credential(&user.username, user.id, passkey);

        tracing::info!("Successfully registered credential for user: {}", user.username);
        Ok(Json(SimpleResponse::ok()))
    } else {
        Err(AppError::Validation { message: "Expected attestation response".to_string() })
    }
}

async fn post_assertion_options(
    State(state): State<AppState>,
    Json(request): Json<AssertionOptionsRequest>,
) -> Result<Json<AssertionOptionsResponse>, AppError> {
    tracing::info!("Authentication request for user: {}", request.username);

    if request.username.is_empty() {
        return Err(AppError::MissingField { field: "username".to_string() });
    }

    // Get user credentials
    let credentials = state.get_user_credentials(&request.username);
    if credentials.is_empty() {
        return Err(AppError::UserNotFound { username: request.username });
    }

    // Convert to CredentialID format
    let allow_credentials: Vec<CredentialID> = credentials
        .iter()
        .map(|c| c.passkey.cred_id().to_vec())
        .collect();

    // Start WebAuthn authentication
    let (request_challenge, auth_state) = state.webauthn.start_passkey_authentication(&allow_credentials)?;

    // Store challenge state
    let challenge_id = request_challenge.challenge.clone();
    let expires_at = Utc::now() + Duration::minutes(5);

    let stored_challenge = StoredChallenge {
        user_id: None, // Not tied to specific user initially
        challenge_type: "authentication".to_string(),
        state: serde_json::to_value(&(auth_state, request.username.clone()))?, // Store both state and username
        expires_at,
    };

    state.challenges.insert(challenge_id, stored_challenge);

    // Build response
    let response = AssertionOptionsResponse {
        status: "ok".to_string(),
        error_message: String::new(),
        challenge: request_challenge.challenge,
        timeout: Some(60000),
        rp_id: Some("localhost".to_string()),
        allow_credentials: credentials.iter().map(|cred| {
            CredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: base64::encode_config(&cred.passkey.cred_id(), base64::URL_SAFE_NO_PAD),
                transports: None,
            }
        }).collect(),
        user_verification: request.user_verification,
    };

    Ok(Json(response))
}

async fn post_assertion_result(
    State(state): State<AppState>,
    Json(credential): Json<CredentialRequest>,
) -> Result<Json<SimpleResponse>, AppError> {
    tracing::info!("Authentication result for credential: {}", credential.id);

    // Extract challenge from clientDataJSON
    if let ResponseData::Assertion(response) = &credential.response {
        let challenge_value = extract_challenge_from_client_data(&response.client_data_json)?;

        // Find stored challenge
        let stored_challenge = state.challenges.get(&challenge_value)
            .ok_or(AppError::ChallengeNotFound)?
            .clone();

        // Check expiration
        if stored_challenge.expires_at < Utc::now() {
            state.challenges.remove(&challenge_value);
            return Err(AppError::ChallengeNotFound);
        }

        // Remove challenge (one-time use)
        state.challenges.remove(&challenge_value);

        // Parse authentication state and username
        let (auth_state, username): (PasskeyAuthentication, String) = serde_json::from_value(stored_challenge.state)?;

        // Get the credential from storage
        let credential_id_bytes = base64::decode_config(&credential.id, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::Validation { message: "Invalid credential ID encoding".to_string() })?;

        let stored_credential = state.find_credential(&credential_id_bytes)
            .ok_or(AppError::Validation { message: "Credential not found".to_string() })?;

        // Convert to PublicKeyCredential
        let client_data_json = base64::decode_config(&response.client_data_json, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::Validation { message: "Invalid clientDataJSON encoding".to_string() })?;
        
        let authenticator_data = base64::decode_config(&response.authenticator_data, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::Validation { message: "Invalid authenticatorData encoding".to_string() })?;

        let signature = base64::decode_config(&response.signature, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::Validation { message: "Invalid signature encoding".to_string() })?;

        let user_handle = if let Some(uh) = &response.user_handle {
            if !uh.is_empty() {
                Some(base64::decode_config(uh, base64::URL_SAFE_NO_PAD)
                    .map_err(|_| AppError::Validation { message: "Invalid userHandle encoding".to_string() })?)
            } else {
                None
            }
        } else {
            None
        };

        let auth_credential = PublicKeyCredential {
            id: credential.id.clone(),
            raw_id: credential_id_bytes,
            response: AuthenticatorAssertionResponseRaw {
                client_data_json,
                authenticator_data,
                signature,
                user_handle,
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        };

        // Complete WebAuthn authentication
        let _auth_result = state.webauthn.finish_passkey_authentication(&auth_credential, &auth_state)?;

        tracing::info!("Successfully authenticated credential for user: {}", username);
        Ok(Json(SimpleResponse::ok()))
    } else {
        Err(AppError::Validation { message: "Expected assertion response".to_string() })
    }
}

// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "fido2-minimal",
        "timestamp": Utc::now().to_rfc3339()
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fido2_minimal=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize application state
    let app_state = AppState::new()?;
    tracing::info!("FIDO2 minimal server initialized");

    // Build CORS layer
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::OPTIONS])
        .allow_headers(tower_http::cors::Any)
        .allow_credentials(true);

    // Build the application router
    let app = Router::new()
        .route("/attestation/options", post(post_attestation_options))
        .route("/attestation/result", post(post_attestation_result))
        .route("/assertion/options", post(post_assertion_options))
        .route("/assertion/result", post(post_assertion_result))
        .route("/health", axum::routing::get(health_check))
        .with_state(app_state)
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    // Start server
    let addr = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("FIDO2 minimal server listening on {}", addr);

    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received, starting graceful shutdown");
}