use crate::error::{AppError, Result};
use crate::schema::{
    ServerPublicKeyCredential, ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse, ServerPublicKeyCredentialDescriptor,
    ServerPublicKeyCredentialUserEntity, ServerResponse,
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

pub async fn get_attestation_options(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(request): Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<Json<ServerPublicKeyCredentialCreationOptionsResponse>> {
    tracing::info!("Starting attestation options for user: {}", request.username);

    // Validate input
    if request.username.is_empty() {
        return Err(AppError::missing_field("username"));
    }
    if request.display_name.is_empty() {
        return Err(AppError::missing_field("displayName"));
    }

    // Find or create user
    let user = state
        .user_service
        .find_or_create_user(&request.username, &request.display_name)
        .await?;

    // Get existing credentials to exclude
    let existing_credentials = state.credential_service.get_user_credentials(user.id).await?;

    // Start WebAuthn registration
    let (creation_challenge, registration_state) = state
        .webauthn_service
        .start_passkey_registration(
            &user.user_id,
            &user.username,
            &user.display_name,
            if existing_credentials.is_empty() {
                None
            } else {
                Some(existing_credentials)
            },
            request.authenticator_selection,
            request.attestation,
        )
        .await?;

    // Store challenge state
    let challenge_id = state
        .challenge_service
        .store_registration_challenge(user.id, registration_state)
        .await?;

    // Convert exclude credentials to server format
    let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = creation_challenge
        .exclude_credentials
        .iter()
        .map(|cred| ServerPublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: base64::encode_config(&cred.id, base64::URL_SAFE_NO_PAD),
            transports: None, // Transports are optional in exclude list
        })
        .collect();

    // Build response with challenge ID embedded in extensions
    let mut extensions = serde_json::Map::new();
    extensions.insert("challengeId".to_string(), serde_json::Value::String(challenge_id.clone()));

    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        status: "ok".to_string(),
        error_message: String::new(),
        rp: creation_challenge.rp,
        user: ServerPublicKeyCredentialUserEntity {
            id: base64::encode_config(&user.user_id, base64::URL_SAFE_NO_PAD),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
        },
        challenge: creation_challenge.challenge,
        pub_key_cred_params: creation_challenge.pub_key_cred_params,
        timeout: Some(state.webauthn_service.get_timeout()),
        exclude_credentials,
        authenticator_selection: request.authenticator_selection,
        attestation: request.attestation,
        extensions: Some(serde_json::Value::Object(extensions)),
    };

    tracing::info!(
        "Generated attestation options for user: {}, challenge_id: {}",
        request.username,
        challenge_id
    );

    Ok(Json(response))
}

pub async fn post_attestation_result(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(credential): Json<ServerPublicKeyCredential>,
) -> Result<Json<ServerResponse>> {
    tracing::info!("Processing attestation result for credential: {}", credential.id);

    // Extract challenge from clientDataJSON
    let client_data = extract_client_data_json(&credential)?;

    // Find the challenge by its value
    let challenge = state
        .challenge_service
        .find_registration_challenge_by_value(&client_data.challenge)
        .await?;

    // Retrieve and remove challenge state
    let registration_state = state
        .challenge_service
        .retrieve_and_remove_registration_challenge(&challenge.id, challenge.user_id)
        .await?;

    // Complete WebAuthn registration
    let passkey = state
        .webauthn_service
        .finish_passkey_registration(&credential, &registration_state)
        .await?;

    // Store the new credential
    let _credential_id = state
        .credential_service
        .create_credential(challenge.user_id, passkey)
        .await?;

    tracing::info!(
        "Successfully registered credential: {} for user_id: {}",
        credential.id,
        challenge.user_id
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
    if let crate::schema::ServerAuthenticatorResponse::Attestation(response) = &credential.response {
        let client_data_bytes = base64::decode_config(&response.client_data_json, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::validation("Invalid clientDataJSON encoding"))?;
        
        let client_data: ClientData = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::validation("Invalid clientDataJSON format"))?;
        
        Ok(client_data)
    } else {
        Err(AppError::validation("Expected attestation response"))
    }
}

#[derive(Debug)]
struct StoredChallengeInfo {
    id: String,
    user_id: uuid::Uuid,
}

fn generate_challenge_id_from_value(challenge: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    challenge.hash(&mut hasher);
    let hash = hasher.finish();
    
    format!("chal_{:x}", hash)
}