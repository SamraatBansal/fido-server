//! FIDO/WebAuthn service implementation

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::config::WebAuthnSettings;
use crate::db::{models::*, DbPool};
use crate::dto::*;
use crate::error::{AppError, Result};
use crate::schema::{challenges, credentials, users};
use crate::services::UserService;

/// FIDO service for WebAuthn operations
#[derive(Clone)]
pub struct FidoService {
    webauthn: Webauthn,
    pool: DbPool,
    user_service: UserService,
}

/// Stored challenge state for registration
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationState {
    pub reg_state: PasskeyRegistration,
    pub user_id: Uuid,
}

/// Stored challenge state for authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationState {
    pub auth_state: PasskeyAuthentication,
    pub user_id: Uuid,
}

impl FidoService {
    /// Create a new FIDO service
    pub fn new(
        settings: &WebAuthnSettings,
        pool: DbPool,
        user_service: UserService,
    ) -> Result<Self> {
        let rp_origin = Url::parse(&settings.origin)
            .map_err(|e| AppError::ValidationError(format!("Invalid origin URL: {}", e)))?;

        let webauthn = WebauthnBuilder::new(&settings.rp_id, &rp_origin)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?
            .rp_name(&settings.rp_name)
            .build()
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        Ok(Self {
            webauthn,
            pool,
            user_service,
        })
    }

    /// Start passkey registration
    pub async fn start_registration(
        &self,
        request: &ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Get or create user
        let user = self
            .user_service
            .get_or_create_user(&request.username, &request.display_name)
            .await?;

        // Get existing credentials to exclude
        let existing_creds = self.get_user_credentials(user.id).await?;
        let exclude_credentials: Vec<CredentialID> = existing_creds
            .into_iter()
            .map(|cred| CredentialID::from(cred.credential_id))
            .collect();

        // Start registration
        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                Uuid::from(user.id),
                &user.username,
                &user.display_name,
                Some(exclude_credentials),
            )
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Store challenge state
        let challenge_data = serde_json::to_vec(&RegistrationState {
            reg_state,
            user_id: user.id,
        })
        .map_err(|e| AppError::InternalError(format!("Failed to serialize challenge: {}", e)))?;

        let new_challenge = NewChallenge {
            user_id: user.id,
            challenge_type: "registration".to_string(),
            challenge_data,
            expires_at: Utc::now() + Duration::minutes(5), // 5-minute expiry
        };

        let mut conn = self.pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // Convert webauthn-rs response to our DTO
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            server_response: ServerResponse::ok(),
            rp: ccr.public_key.rp.clone(),
            user: ServerPublicKeyCredentialUserEntity {
                id: URL_SAFE_NO_PAD.encode(ccr.public_key.user.id.as_ref()),
                name: ccr.public_key.user.name.clone(),
                display_name: ccr.public_key.user.display_name.clone(),
            },
            challenge: URL_SAFE_NO_PAD.encode(&ccr.public_key.challenge),
            pub_key_cred_params: ccr.public_key.pub_key_cred_params.clone(),
            timeout: ccr.public_key.timeout,
            exclude_credentials: ccr
                .public_key
                .exclude_credentials
                .unwrap_or_default()
                .iter()
                .map(|cred| ServerPublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: URL_SAFE_NO_PAD.encode(&cred.id),
                    transports: cred.transports.clone(),
                })
                .collect(),
            authenticator_selection: request.authenticator_selection.clone(),
            attestation: request.attestation.clone(),
            extensions: ccr.public_key.extensions.clone(),
        };

        Ok(response)
    }

    /// Finish passkey registration
    pub async fn finish_registration(
        &self,
        request: &RegistrationResultRequest,
    ) -> Result<RegistrationResultResponse> {
        // Decode the credential
        let credential_id = URL_SAFE_NO_PAD
            .decode(&request.credential.id)
            .map_err(|e| AppError::ValidationError(format!("Invalid credential ID: {}", e)))?;

        // Get the attestation response
        let attestation_response = match &request.credential.response {
            ServerCredentialResponse::Attestation(response) => response,
            _ => return Err(AppError::ValidationError("Expected attestation response".to_string())),
        };

        // Decode client data and attestation object
        let client_data_json = URL_SAFE_NO_PAD
            .decode(&attestation_response.client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON: {}", e)))?;

        let attestation_object = URL_SAFE_NO_PAD
            .decode(&attestation_response.attestation_object)
            .map_err(|e| AppError::ValidationError(format!("Invalid attestation object: {}", e)))?;

        // Create RegisterPublicKeyCredential
        let reg_credential = RegisterPublicKeyCredential {
            id: request.credential.id.clone(),
            raw_id: credential_id,
            response: AuthenticatorAttestationResponseRaw {
                client_data_json,
                attestation_object,
            },
            type_: "public-key".to_string(),
        };

        // Find and verify challenge
        let mut conn = self.pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        let stored_challenge = challenges::table
            .filter(challenges::challenge_type.eq("registration"))
            .filter(challenges::expires_at.gt(Utc::now()))
            .first::<Challenge>(&mut conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AppError::ValidationError("No valid challenge found".to_string()))?;

        // Deserialize challenge state
        let reg_state: RegistrationState = serde_json::from_slice(&stored_challenge.challenge_data)
            .map_err(|e| AppError::InternalError(format!("Failed to deserialize challenge: {}", e)))?;

        // Complete registration
        let passkey = self
            .webauthn
            .finish_passkey_registration(&reg_credential, &reg_state.reg_state)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Store credential
        let new_credential = NewCredential {
            id: Uuid::new_v4(),
            user_id: reg_state.user_id,
            credential_id: passkey.cred_id().as_ref().to_vec(),
            public_key: serde_json::to_vec(passkey.cred())
                .map_err(|e| AppError::InternalError(format!("Failed to serialize public key: {}", e)))?,
            sign_count: passkey.counter() as i32,
            transports: passkey.transports().map(|t| serde_json::to_string(t).ok()).flatten(),
        };

        diesel::insert_into(credentials::table)
            .values(&new_credential)
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // Delete used challenge
        diesel::delete(challenges::table.find(stored_challenge.id))
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        Ok(ServerResponse::ok())
    }

    /// Start passkey authentication
    pub async fn start_authentication(
        &self,
        request: &ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Find user
        let user = self
            .user_service
            .find_by_username(&request.username)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Get user credentials
        let user_creds = self.get_user_credentials(user.id).await?;
        if user_creds.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Convert to Passkey objects
        let passkeys: Result<Vec<Passkey>> = user_creds
            .iter()
            .map(|cred| {
                let passkey: Passkey = serde_json::from_slice(&cred.public_key)
                    .map_err(|e| AppError::InternalError(format!("Failed to deserialize credential: {}", e)))?;
                Ok(passkey)
            })
            .collect();
        let passkeys = passkeys?;

        // Start authentication
        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Store challenge state
        let challenge_data = serde_json::to_vec(&AuthenticationState {
            auth_state,
            user_id: user.id,
        })
        .map_err(|e| AppError::InternalError(format!("Failed to serialize challenge: {}", e)))?;

        let new_challenge = NewChallenge {
            user_id: user.id,
            challenge_type: "authentication".to_string(),
            challenge_data,
            expires_at: Utc::now() + Duration::minutes(5), // 5-minute expiry
        };

        let mut conn = self.pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // Convert webauthn-rs response to our DTO
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            server_response: ServerResponse::ok(),
            challenge: URL_SAFE_NO_PAD.encode(&rcr.public_key.challenge),
            timeout: rcr.public_key.timeout,
            rp_id: Some(rcr.public_key.rp_id.clone()),
            allow_credentials: rcr
                .public_key
                .allow_credentials
                .iter()
                .map(|cred| ServerPublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: URL_SAFE_NO_PAD.encode(&cred.id),
                    transports: cred.transports.clone(),
                })
                .collect(),
            user_verification: request.user_verification.clone(),
            extensions: rcr.public_key.extensions.clone(),
        };

        Ok(response)
    }

    /// Finish passkey authentication
    pub async fn finish_authentication(
        &self,
        request: &AuthenticationResultRequest,
    ) -> Result<AuthenticationResultResponse> {
        // Decode the credential
        let credential_id = URL_SAFE_NO_PAD
            .decode(&request.credential.id)
            .map_err(|e| AppError::ValidationError(format!("Invalid credential ID: {}", e)))?;

        // Get the assertion response
        let assertion_response = match &request.credential.response {
            ServerCredentialResponse::Assertion(response) => response,
            _ => return Err(AppError::ValidationError("Expected assertion response".to_string())),
        };

        // Decode response data
        let client_data_json = URL_SAFE_NO_PAD
            .decode(&assertion_response.client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON: {}", e)))?;

        let authenticator_data = URL_SAFE_NO_PAD
            .decode(&assertion_response.authenticator_data)
            .map_err(|e| AppError::ValidationError(format!("Invalid authenticator data: {}", e)))?;

        let signature = URL_SAFE_NO_PAD
            .decode(&assertion_response.signature)
            .map_err(|e| AppError::ValidationError(format!("Invalid signature: {}", e)))?;

        let user_handle = if assertion_response.user_handle.is_empty() {
            None
        } else {
            Some(
                URL_SAFE_NO_PAD
                    .decode(&assertion_response.user_handle)
                    .map_err(|e| AppError::ValidationError(format!("Invalid user handle: {}", e)))?,
            )
        };

        // Create PublicKeyCredential
        let auth_credential = PublicKeyCredential {
            id: request.credential.id.clone(),
            raw_id: credential_id.clone(),
            response: AuthenticatorAssertionResponseRaw {
                client_data_json,
                authenticator_data,
                signature,
                user_handle,
            },
            type_: "public-key".to_string(),
        };

        // Find and verify challenge
        let mut conn = self.pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        let stored_challenge = challenges::table
            .filter(challenges::challenge_type.eq("authentication"))
            .filter(challenges::expires_at.gt(Utc::now()))
            .first::<Challenge>(&mut conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AppError::ValidationError("No valid challenge found".to_string()))?;

        // Deserialize challenge state
        let auth_state: AuthenticationState = serde_json::from_slice(&stored_challenge.challenge_data)
            .map_err(|e| AppError::InternalError(format!("Failed to deserialize challenge: {}", e)))?;

        // Complete authentication
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(&auth_credential, &auth_state.auth_state)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Update credential sign count
        diesel::update(
            credentials::table.filter(credentials::credential_id.eq(&credential_id))
        )
        .set(credentials::sign_count.eq(auth_result.counter() as i32))
        .execute(&mut conn)
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // Delete used challenge
        diesel::delete(challenges::table.find(stored_challenge.id))
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        Ok(ServerResponse::ok())
    }

    /// Get user credentials
    async fn get_user_credentials(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        let creds = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .load::<Credential>(&mut conn)
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        Ok(creds)
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired_challenges(&self) -> Result<usize> {
        let mut conn = self.pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        let deleted = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(Utc::now()))
        )
        .execute(&mut conn)
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        Ok(deleted)
    }
}