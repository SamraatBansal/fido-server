use crate::error::{AppError, Result};
use crate::schema::{
    ServerPublicKeyCredential, ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse, ServerResponse,
};
use crate::services::{ChallengeService, CredentialService, UserService, WebAuthnService};
use axum::{extract::State, http::HeaderMap, Json};
use std::sync::Arc;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct AppState {
    pub webauthn_service: Arc<WebAuthnService>,
    pub user_service: Arc<UserService>,
    pub credential_service: Arc<CredentialService>,
    pub challenge_service: Arc<ChallengeService>,
}

pub async fn get_assertion_options(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(request): Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<Json<ServerPublicKeyCredentialGetOptionsResponse>> {
    tracing::info!("Starting assertion options for user: {}", request.username);

    // Validate input
    if request.username.is_empty() {
        return Err(AppError::missing_field("username"));
    }

    // Get user credentials
    let credentials = state
        .credential_service
        .get_credentials_for_user(&request.username)
        .await?;

    if credentials.is_empty() {
        return Err(AppError::UserNotFound {
            username: request.username.clone(),
        });
    }

    // Convert credentials to CredentialID format for WebAuthn
    let allow_credentials = state
        .credential_service
        .convert_to_credential_ids(&credentials);

    // Start WebAuthn authentication
    let (request_challenge, auth_state) = state
        .webauthn_service
        .start_passkey_authentication(allow_credentials)
        .await?;

    // Store challenge state
    let challenge_id = state
        .challenge_service
        .store_authentication_challenge(request.username.clone(), auth_state)
        .await?;

    // Convert credentials to server format
    let allow_credentials_server = state
        .credential_service
        .create_credential_descriptors(&credentials);

    // Build response
    let response = ServerPublicKeyCredentialGetOptionsResponse {
        status: "ok".to_string(),
        error_message: String::new(),
        challenge: request_challenge.challenge,
        timeout: Some(state.webauthn_service.get_timeout()),
        rp_id: Some(state.webauthn_service.get_rp_id().to_string()),
        allow_credentials: allow_credentials_server,
        user_verification: request.user_verification,
        extensions: None,
    };

    tracing::info!(
        "Generated assertion options for user: {}, challenge_id: {}, credentials: {}",
        request.username,
        challenge_id,
        credentials.len()
    );

    Ok(Json(response))
}

pub async fn post_assertion_result(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(credential): Json<ServerPublicKeyCredential>,
) -> Result<Json<ServerResponse>> {
    tracing::info!("Processing assertion result for credential: {}", credential.id);

    // Extract challenge from clientDataJSON
    let client_data = extract_client_data_json(&credential)?;

    // Find the challenge by its value
    let challenge = state
        .challenge_service
        .find_authentication_challenge_by_value(&client_data.challenge)
        .await?;

    // Get the stored authentication challenge
    let stored_auth: crate::services::challenge::StoredAuthenticationChallenge =
        serde_json::from_value(challenge.challenge_data)?;

    // Get the credential from database
    let credential_id_bytes = base64::decode_config(&credential.id, base64::URL_SAFE_NO_PAD)
        .map_err(|_| AppError::validation("Invalid credential ID encoding"))?;

    let db_credential = state
        .credential_service
        .get_credential_by_id(&credential_id_bytes)
        .await?
        .ok_or(AppError::InvalidCredential)?;

    // Convert database credential to Passkey
    let passkey = state
        .credential_service
        .convert_to_passkey(&db_credential)?;

    // Retrieve and remove challenge state
    let auth_state = state
        .challenge_service
        .retrieve_and_remove_authentication_challenge(&challenge.id, &stored_auth.username)
        .await?;

    // Complete WebAuthn authentication
    let auth_result = state
        .webauthn_service
        .finish_passkey_authentication(&credential, &auth_state, &passkey)
        .await?;

    // Update sign count
    state
        .credential_service
        .update_sign_count(&credential_id_bytes, auth_result.counter())
        .await?;

    tracing::info!(
        "Successfully authenticated credential: {} for user: {}",
        credential.id,
        stored_auth.username
    );

    Ok(Json(ServerResponse::ok()))
}

// Helper functions
#[derive(serde::Deserialize)]
struct ClientData {
    challenge: String,
    origin: String,
    #[serde(rename = "type")]
    client_type: String,
}

fn extract_client_data_json(credential: &ServerPublicKeyCredential) -> Result<ClientData> {
    if let crate::schema::ServerAuthenticatorResponse::Assertion(response) = &credential.response {
        let client_data_bytes = base64::decode_config(&response.client_data_json, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::validation("Invalid clientDataJSON encoding"))?;
        
        let client_data: ClientData = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::validation("Invalid clientDataJSON format"))?;
        
        Ok(client_data)
    } else {
        Err(AppError::validation("Expected assertion response"))
    }
}