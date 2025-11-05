use axum::{
    extract::State,
    response::{IntoResponse, Json},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use webauthn_rs::prelude::*;

use crate::{
    error::AppError,
    models::{
        AssertionOptionsRequest, AssertionOptionsResponse,
        ServerPublicKeyCredential, ServerPublicKeyCredentialDescriptor,
        ServerResponse, ServerAuthenticatorResponse,
    },
    AppState,
};

pub async fn options(
    State(state): State<AppState>,
    Json(req): Json<AssertionOptionsRequest>,
) -> Result<Json<AssertionOptionsResponse>, AppError> {
    tracing::info!("Authentication options request for user: {}", req.username);

    // Get user
    let user = state.user_service
        .get_user_by_username(&req.username)
        .await?
        .ok_or_else(|| AppError::UserNotFound {
            username: req.username.clone(),
        })?;

    // Get user's passkeys
    let passkeys = state.credential_service
        .get_user_passkeys(user.id)
        .await?;

    if passkeys.is_empty() {
        return Err(AppError::Validation {
            message: "No credentials registered for user".to_string(),
        });
    }

    // Start WebAuthn authentication
    let (request_challenge, auth_state) = state.webauthn_service
        .start_passkey_authentication(passkeys)
        .await?;

    // Store challenge state
    let challenge_id = state.challenge_service
        .store_authentication_challenge(user.id, auth_state)
        .await?;

    // Store mappings for challenge lookup
    let challenge_bytes = &request_challenge.public_key.challenge;
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_bytes);
    
    // Store mapping from challenge value to user ID
    state.challenge_service
        .store_challenge_to_user_mapping(&challenge_b64, user.id)
        .await?;
    
    // Store mapping from challenge value to challenge ID for state retrieval
    let challenge_mapping_key = format!("auth_challenge_{}", challenge_b64);
    let mapping_challenge = crate::models::StoredChallenge {
        id: challenge_mapping_key,
        user_id: user.id,
        challenge_type: crate::models::ChallengeType::Authentication,
        challenge_data: challenge_id.clone(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        created_at: chrono::Utc::now(),
    };
    state.challenge_service.storage.store_challenge(mapping_challenge).await?;

    // Convert to FIDO conformance format
    let response = AssertionOptionsResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        challenge: challenge_b64,
        timeout: Some(state.webauthn_service.timeout_ms()),
        rp_id: Some(state.webauthn_service.rp_id().to_string()),
        allow_credentials: request_challenge.public_key.allow_credentials.unwrap_or_default()
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: URL_SAFE_NO_PAD.encode(cred.id),
                transports: cred.transports.map(|t| t.into_iter().map(|tr| format!("{:?}", tr).to_lowercase()).collect()),
            })
            .collect(),
        user_verification: req.user_verification,
    };

    tracing::info!("Authentication options created for user: {}, challenge stored with ID: {}", 
                   req.username, challenge_id);

    Ok(Json(response))
}

pub async fn result(
    State(state): State<AppState>,
    Json(credential): Json<ServerPublicKeyCredential>,
) -> Result<Json<ServerResponse>, AppError> {
    tracing::info!("Authentication result received for credential: {}", credential.id);

    // Decode credential
    let credential_id = URL_SAFE_NO_PAD.decode(&credential.id)
        .map_err(|_| AppError::Validation {
            message: "Invalid credential ID encoding".to_string(),
        })?;

    // Extract assertion response
    let assertion_response = match credential.response {
        ServerAuthenticatorResponse::Assertion(assertion) => assertion,
        _ => return Err(AppError::Validation {
            message: "Expected assertion response".to_string(),
        }),
    };

    // Decode assertion data
    let client_data_json = URL_SAFE_NO_PAD.decode(&assertion_response.client_data_json)
        .map_err(|_| AppError::Validation {
            message: "Invalid clientDataJSON encoding".to_string(),
        })?;

    let authenticator_data = URL_SAFE_NO_PAD.decode(&assertion_response.authenticator_data)
        .map_err(|_| AppError::Validation {
            message: "Invalid authenticatorData encoding".to_string(),
        })?;

    let signature = URL_SAFE_NO_PAD.decode(&assertion_response.signature)
        .map_err(|_| AppError::Validation {
            message: "Invalid signature encoding".to_string(),
        })?;

    let user_handle = assertion_response.user_handle
        .as_ref()
        .map(|uh| URL_SAFE_NO_PAD.decode(uh))
        .transpose()
        .map_err(|_| AppError::Validation {
            message: "Invalid userHandle encoding".to_string(),
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

    // Look up user by challenge value
    let user_id = state.challenge_service
        .get_user_by_challenge_value(challenge_b64)
        .await?
        .ok_or_else(|| AppError::Validation {
            message: "Invalid or expired challenge".to_string(),
        })?;

    // Convert to webauthn-rs format
    let auth_credential = PublicKeyCredential {
        id: credential.id.clone(),
        raw_id: credential_id.into(),
        response: webauthn_rs_proto::auth::AuthenticatorAssertionResponseRaw {
            client_data_json: client_data_json.into(),
            authenticator_data: authenticator_data.into(),
            signature: signature.into(),
            user_handle: user_handle.map(|uh| uh.into()),
        },
        type_: credential.type_.clone(),
        extensions: Default::default(),
    };

    // Get the challenge ID from our mapping
    let challenge_mapping_key = format!("auth_challenge_{}", challenge_b64);
    let challenge_id = if let Some(mapping) = state.challenge_service
        .storage
        .get_challenge(&challenge_mapping_key)
        .await? {
        mapping.challenge_data.clone()
    } else {
        return Err(AppError::Validation {
            message: "Challenge state not found".to_string(),
        });
    };

    // Retrieve and remove challenge state
    let auth_state = state.challenge_service
        .retrieve_and_remove_authentication_challenge(&challenge_id, user_id)
        .await?;

    // Finish WebAuthn authentication
    let auth_result = state.webauthn_service
        .finish_passkey_authentication(&auth_credential, &auth_state)
        .await?;

    // Update credential last used time
    state.credential_service
        .update_credential_last_used(&auth_result.cred_id())
        .await?;

    tracing::info!("Authentication completed successfully for user ID: {}", user_id);

    Ok(Json(ServerResponse::success()))
}