use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use base64::Engine;

use crate::api_types::*;
use crate::database::DatabaseService;
use crate::error::{AppError, Result};
use crate::models::NewCredential;

// Session store to handle the challenge-to-user mapping
type SessionStore = Arc<RwLock<HashMap<String, (Uuid, String)>>>; // challenge -> (user_id, state_type)

#[derive(Clone)]
pub struct WebAuthnService {
    webauthn: Webauthn,
    database: DatabaseService,
    sessions: SessionStore,
}

impl WebAuthnService {
    pub fn new(webauthn: Webauthn, database: DatabaseService) -> Self {
        Self {
            webauthn,
            database,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // Registration flow
    pub async fn start_registration(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::MissingField("username".to_string()));
        }
        if request.display_name.is_empty() {
            return Err(AppError::MissingField("displayName".to_string()));
        }

        // Get or create user
        let user = match self.database.get_user_by_username(&request.username).await? {
            Some(user) => user,
            None => {
                self.database
                    .create_user(&request.username, &request.display_name)
                    .await?
            }
        };

        // Get existing credentials for exclude list
        let existing_credentials = self.database.get_credentials_for_user(user.id).await?;
        let exclude_credentials: Vec<CredentialID> = existing_credentials
            .iter()
            .filter_map(|cred| CredentialID::try_from(cred.credential_id.as_slice()).ok())
            .collect();

        // Start registration with webauthn-rs
        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                user.id,
                &request.username,
                &request.display_name,
                Some(exclude_credentials),
            )
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Extract challenge bytes safely
        let challenge_bytes = {
            // Get the challenge as bytes by serializing to JSON and extracting the challenge field
            let ccr_json = serde_json::to_value(&ccr.public_key.challenge)
                .map_err(|_| AppError::InternalServerError)?;
            
            if let Some(challenge_str) = ccr_json.as_str() {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(challenge_str)
                    .map_err(|_| AppError::InternalServerError)?
            } else {
                return Err(AppError::InternalServerError);
            }
        };

        let state_data = serde_json::to_vec(&reg_state)?;
        let expires_at = Utc::now() + Duration::minutes(5);

        self.database
            .store_registration_challenge(user.id, &challenge_bytes, &state_data, expires_at)
            .await?;

        // Store challenge-to-user mapping in session store
        let challenge_str = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        self.sessions.write().await.insert(challenge_str.clone(), (user.id, "registration".to_string()));

        // Build exclude credentials for response
        let exclude_creds: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None, // Simplified for conformance tests
            })
            .collect();

        // Create response that matches FIDO conformance requirements
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: RpEntity {
                name: ccr.public_key.rp.name.clone(),
                id: Some(ccr.public_key.rp.id.clone()),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: request.username,
                display_name: request.display_name,
                icon: None,
            },
            challenge: challenge_str,
            pub_key_cred_params: ccr.public_key.pub_key_cred_params
                .iter()
                .map(|param| PubKeyCredParam {
                    type_: param.type_.clone(),
                    alg: param.alg,
                })
                .collect(),
            timeout: ccr.public_key.timeout,
            exclude_credentials: exclude_creds,
            authenticator_selection: request.authenticator_selection,
            attestation: request.attestation,
            extensions: request.extensions,
        };

        Ok(response)
    }

    pub async fn finish_registration(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Validate credential structure first - critical for conformance tests
        credential.validate_basic_structure()?;

        let attestation_response = match credential.response {
            ServerAuthenticatorResponse::Attestation(ref resp) => resp,
            _ => {
                return Err(AppError::InvalidInput(
                    "Expected attestation response".to_string(),
                ))
            }
        };

        // Validate attestation response structure - critical for failing tests
        attestation_response.validate_structure()?;

        // Additional validation checks required by FIDO conformance tests
        if attestation_response.client_data_json.is_empty() {
            return Err(AppError::MissingField("clientDataJSON".to_string()));
        }

        if attestation_response.attestation_object.is_empty() {
            return Err(AppError::MissingField("attestationObject".to_string()));
        }

        // Decode and validate client data
        let client_data_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&attestation_response.client_data_json)
            .map_err(|_| AppError::InvalidFormat("clientDataJSON must be base64url encoded".to_string()))?;
        
        let client_data: CollectedClientData = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::InvalidFormat("Invalid clientDataJSON format".to_string()))?;

        // Validate client data type
        if client_data.type_ != "webauthn.create" {
            return Err(AppError::ValidationError(
                "clientDataJSON type must be 'webauthn.create'".to_string(),
            ));
        }

        // Validate origin
        if client_data.origin.is_empty() {
            return Err(AppError::MissingField("origin in clientDataJSON".to_string()));
        }

        // Find user by challenge using our session store
        let challenge_str = client_data.challenge.clone();
        let (user_id, session_type) = {
            let sessions = self.sessions.read().await;
            sessions.get(&challenge_str)
                .cloned()
                .ok_or(AppError::ChallengeExpired)?
        };

        if session_type != "registration" {
            return Err(AppError::ValidationError("Invalid challenge type".to_string()));
        }

        // Get user
        let user = self.database.get_user_by_id(user_id).await?
            .ok_or(AppError::UserNotFound)?;

        // Get challenge state from database
        let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&client_data.challenge)
            .map_err(|_| AppError::InvalidFormat("Invalid challenge format".to_string()))?;
        
        let challenge_record = self
            .database
            .get_registration_challenge(user.id, &challenge_bytes)
            .await?
            .ok_or(AppError::ChallengeExpired)?;

        let reg_state: PasskeyRegistration = serde_json::from_slice(&challenge_record.state_data)
            .map_err(|_| AppError::InternalServerError)?;

        // Convert credential to webauthn-rs format
        let credential_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.id)
            .map_err(|_| AppError::InvalidFormat("Invalid credential ID format".to_string()))?;

        // For now, let's create a simplified credential structure
        // This is a workaround until we get the exact types right
        let raw_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_id_bytes);
        
        // Use serde_json to construct the credential format expected by webauthn-rs
        let reg_credential_json = serde_json::json!({
            "id": credential.id,
            "rawId": raw_id_b64,
            "response": {
                "clientDataJSON": attestation_response.client_data_json,
                "attestationObject": attestation_response.attestation_object
            },
            "type": credential.type_
        });
        
        let reg_credential: RegisterPublicKeyCredential = serde_json::from_value(reg_credential_json)
            .map_err(|_| AppError::InvalidFormat("Failed to parse credential".to_string()))?;

        // Finish registration with webauthn-rs - this will perform all security validations
        let passkey = self.webauthn.finish_passkey_registration(&reg_credential, &reg_state)
            .map_err(|e| AppError::AttestationFailed(e.to_string()))?;

        // Store credential in database  
        let cred_id = passkey.cred_id().to_vec();

        let new_credential = NewCredential {
            id: Uuid::new_v4(),
            user_id: user.id,
            credential_id: cred_id,
            public_key: serde_json::to_vec(&passkey).unwrap_or_default(), // Simplified storage
            sign_count: 0, // Initial sign count
            transports: None, // Simplified for conformance tests
            backup_eligible: false,
            backup_state: false,
        };

        self.database.store_credential(new_credential).await?;

        // Clean up the challenge and session
        self.database
            .delete_registration_challenge(user.id, &challenge_bytes)
            .await?;
        
        self.sessions.write().await.remove(&challenge_str);

        Ok(ServerResponse::ok())
    }

    // Authentication flow (simplified for now)
    pub async fn start_authentication(
        &self,
        _request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Simplified implementation for initial version
        Err(AppError::InternalServerError)
    }

    pub async fn finish_authentication(
        &self,
        _credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Simplified implementation for initial version
        Err(AppError::InternalServerError)
    }
}