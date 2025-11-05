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

    // Store challenge state with challenge value as lookup key
    let challenge_id = state.challenge_service
        .store_registration_challenge(user.id, reg_state)
        .await?;
    
    // Also store a mapping from challenge value to user for result lookup
    let challenge_bytes = &creation_challenge.public_key.challenge;
    let challenge_key = URL_SAFE_NO_PAD.encode(challenge_bytes);
    state.challenge_service
        .store_challenge_to_user_mapping(&challenge_key, user.id)
        .await?;

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

    // Extract challenge from client data for lookup
    // We need to implement a way to associate the challenge with a user
    // For now, we'll look through recent challenges to find the matching one
    // This is a simplified approach - in production, you'd want better indexing

    // Convert to webauthn-rs format
    let reg_credential = RegisterPublicKeyCredential {
        id: credential.id.clone(),
        raw_id: credential_id,
        response: AuthenticatorAttestationResponseRaw {
            client_data_json,
            attestation_object,
        },
        type_: credential.type_.clone(),
    };

    // We need to find the user and challenge state
    // For this simplified implementation, we'll need to search through challenges
    // In a real implementation, you'd have a better indexing mechanism

    // Try to find challenge by looking for the challenge value in our stored challenges
    // This is inefficient but works for the demo
    let challenge_hex = hex::encode(&challenge_bytes);
    
    // For now, let's try to extract username from the credential ID or use a simpler approach
    // We'll modify this to store challenge IDs in a more accessible way
    
    // Since we can't easily link back to user without additional data,
    // let's implement a simpler approach where we search for matching challenges
    // This would be much more efficient with proper database indexing

    // Temporary: return error asking for username
    return Err(AppError::Validation {
        message: "Cannot complete registration without user context. Consider including username in the request.".to_string(),
    });

    // The following code would work if we could identify the user:
    /*
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

    Ok(Json(ServerResponse::success()))
    */
}