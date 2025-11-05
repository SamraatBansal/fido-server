use axum::{
    extract::State,
    response::{IntoResponse, Json},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use webauthn_rs::prelude::*;

use crate::{
    error::{AppError, AppResult},
    models::{
        AttestationOptionsRequest, AttestationOptionsResponse,
        ServerPublicKeyCredential, ServerPublicKeyCredentialUserEntity,
        ServerPublicKeyCredentialDescriptor, ServerResponse,
        ServerAuthenticatorResponse, ServerAuthenticatorAttestationResponse,
    },
    AppState,
};

pub async fn options(
    State(state): State<AppState>,
    Json(req): Json<AttestationOptionsRequest>,
) -> AppResult<impl IntoResponse> {
    tracing::info!("Registration options request for user: {}", req.username);

    // Get or create user
    let user = state.user_service
        .get_or_create_user(&req.username, &req.display_name)
        .await?;

    // Get existing credentials for exclude list
    let exclude_credentials = state.credential_service
        .get_exclude_list(user.id)
        .await?;

    // Start WebAuthn registration
    let (creation_challenge, reg_state) = state.webauthn_service
        .start_passkey_registration(&user, Some(exclude_credentials))
        .await?;

    // Store challenge state
    let challenge_id = state.challenge_service
        .store_registration_challenge(user.id, reg_state)
        .await?;
    
    // Store mappings for challenge lookup
    let challenge_bytes = &creation_challenge.public_key.challenge;
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_bytes);
    
    // Store mapping from challenge value to user ID
    state.challenge_service
        .store_challenge_to_user_mapping(&challenge_b64, user.id)
        .await?;
    
    // Store mapping from challenge value to challenge ID for state retrieval
    let challenge_mapping_key = format!("reg_challenge_{}", challenge_b64);
    let mapping_challenge = crate::models::StoredChallenge {
        id: challenge_mapping_key,
        user_id,
        challenge_type: crate::models::ChallengeType::Registration,
        challenge_data: challenge_id.clone(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        created_at: chrono::Utc::now(),
    };
    state.challenge_service.storage.store_challenge(mapping_challenge).await?;

    // Convert to FIDO conformance format
    let response = AttestationOptionsResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        rp: creation_challenge.public_key.rp,
        user: ServerPublicKeyCredentialUserEntity {
            id: URL_SAFE_NO_PAD.encode(&user.user_id),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
        },
        challenge: URL_SAFE_NO_PAD.encode(&creation_challenge.public_key.challenge),
        pub_key_cred_params: creation_challenge.public_key.pub_key_cred_params,
        timeout: Some(state.webauthn_service.timeout_ms()),
        exclude_credentials: creation_challenge.public_key.exclude_credentials
            .unwrap_or_default()
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: URL_SAFE_NO_PAD.encode(cred.id),
                transports: cred.transports,
            })
            .collect(),
        authenticator_selection: req.authenticator_selection,
        attestation: req.attestation,
    };

    tracing::info!("Registration options created for user: {}, challenge stored with ID: {}", 
                   req.username, challenge_id);

    Ok(Json(response))
}

pub async fn result(
    State(state): State<AppState>,
    Json(credential): Json<ServerPublicKeyCredential>,
) -> AppResult<impl IntoResponse> {
    tracing::info!("Registration result received for credential: {}", credential.id);

    // Decode credential
    let credential_id = URL_SAFE_NO_PAD.decode(&credential.id)
        .map_err(|_| AppError::Validation {
            message: "Invalid credential ID encoding".to_string(),
        })?;

    // Extract attestation response
    let attestation_response = match credential.response {
        ServerAuthenticatorResponse::Attestation(attestation) => attestation,
        _ => return Err(AppError::Validation {
            message: "Expected attestation response".to_string(),
        }),
    };

    // Decode attestation data
    let client_data_json = URL_SAFE_NO_PAD.decode(&attestation_response.client_data_json)
        .map_err(|_| AppError::Validation {
            message: "Invalid clientDataJSON encoding".to_string(),
        })?;

    let attestation_object = URL_SAFE_NO_PAD.decode(&attestation_response.attestation_object)
        .map_err(|_| AppError::Validation {
            message: "Invalid attestationObject encoding".to_string(),
        })?;

    // Parse client data to extract challenge
    let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
        .map_err(|_| AppError::Validation {
            message: "Invalid clientDataJSON format".to_string(),
        })?;

    let challenge_b64 = client_data.get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| AppError::Validation {
            message: "Missing challenge in clientDataJSON".to_string(),
        })?;

    let challenge_bytes = URL_SAFE_NO_PAD.decode(challenge_b64)
        .map_err(|_| AppError::Validation {
            message: "Invalid challenge encoding".to_string(),
        })?;

    // Find user by attempting to parse all stored challenges
    // In a production system, you'd want a more efficient lookup mechanism
    let mut found_user_id = None;
    let mut challenge_id = None;

    // Look up user by challenge value
    let user_id = state.challenge_service
        .get_user_by_challenge_value(challenge_b64)
        .await?
        .ok_or_else(|| AppError::Validation {
            message: "Invalid or expired challenge".to_string(),
        })?;

    // Convert to webauthn-rs format
    let reg_credential = RegisterPublicKeyCredential {
        id: credential.id.clone(),
        raw_id: credential_id.into(),
        response: AuthenticatorAttestationResponseRaw {
            client_data_json,
            attestation_object,
        },
        type_: credential.type_.clone(),
        extensions: None,
    };

    // We need to find the stored challenge state using the challenge value
    // Since webauthn-rs requires the full PasskeyRegistration state, we need to
    // search through our stored challenges to find the matching one
    // In a production system, you'd want a more efficient lookup mechanism

    // Get all challenges for this user and find the matching one
    let mut matching_challenge_id = None;
    // This is a simplified search - in production you'd have better indexing
    
    // Instead of searching all challenges, let's create a deterministic mapping
    // from challenge value to challenge ID
    let challenge_mapping_key = format!("reg_challenge_{}", challenge_b64);
    
    // Try to get the challenge ID from our mapping
    if let Some(mapping) = state.challenge_service
        .storage
        .get_challenge(&challenge_mapping_key)
        .await? {
        matching_challenge_id = Some(mapping.challenge_data.clone());
    }
    
    let challenge_id = matching_challenge_id
        .ok_or_else(|| AppError::Validation {
            message: "Challenge state not found".to_string(),
        })?;

    // Retrieve and remove challenge state
    let reg_state = state.challenge_service
        .retrieve_and_remove_registration_challenge(&challenge_id, user_id)
        .await?;

    // Finish WebAuthn registration
    let passkey = state.webauthn_service
        .finish_passkey_registration(&reg_credential, &reg_state)
        .await?;

    // Store new credential
    state.credential_service
        .create_credential(user_id, passkey)
        .await?;

    tracing::info!("Registration completed successfully for user ID: {}", user_id);

    Ok(Json(ServerResponse::success()))
}