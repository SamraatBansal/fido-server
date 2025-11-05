use crate::error::{AppError, Result};
use crate::schema::{
    ServerPublicKeyCredential, ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse, ServerPublicKeyCredentialDescriptor,
    ServerPublicKeyCredentialGetOptionsRequest, ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredentialUserEntity, ServerResponse,
};
use crate::storage::{MemoryStore, StoredChallenge};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct SimpleWebAuthnService {
    webauthn: Arc<WebAuthn>,
    store: Arc<MemoryStore>,
    rp_name: String,
    timeout_ms: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRegistrationChallenge {
    state: PasskeyRegistration,
    user_id: Uuid,
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredAuthenticationChallenge {
    state: PasskeyAuthentication,
    username: String,
}

impl SimpleWebAuthnService {
    pub fn new(
        rp_id: &str,
        rp_origin: &url::Url,
        rp_name: &str,
        timeout_ms: u32,
        store: Arc<MemoryStore>,
    ) -> Result<Self> {
        let webauthn = WebauthnBuilder::new(rp_id, rp_origin)?
            .rp_name(rp_name)
            .build()?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
            store,
            rp_name: rp_name.to_string(),
            timeout_ms,
        })
    }

    pub async fn handle_attestation_options(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        tracing::info!("Starting registration for user: {}", request.username);

        // Validate input
        if request.username.is_empty() {
            return Err(AppError::missing_field("username"));
        }
        if request.display_name.is_empty() {
            return Err(AppError::missing_field("displayName"));
        }

        // Find or create user
        let user = if let Some(existing_user) = self.store.get_user(&request.username) {
            existing_user
        } else {
            let user_id = crate::utils::crypto::generate_random_bytes(64);
            self.store.create_user(&request.username, &request.display_name, user_id)?
        };

        // Get existing credentials for exclude list
        let existing_credentials = self.store.get_credentials(&request.username);
        let exclude_credentials: Option<Vec<CredentialID>> = if existing_credentials.is_empty() {
            None
        } else {
            Some(
                existing_credentials
                    .iter()
                    .map(|c| c.passkey.cred_id().to_vec())
                    .collect(),
            )
        };

        // Convert user_id to Uuid for WebAuthn
        let user_uuid = if user.user_id.len() >= 16 {
            Uuid::from_slice(&user.user_id[..16]).unwrap_or_else(|_| Uuid::new_v4())
        } else {
            Uuid::new_v4()
        };

        // Start WebAuthn registration
        let (creation_challenge, registration_state) = self
            .webauthn
            .start_passkey_registration(
                user_uuid,
                &user.username,
                &user.display_name,
                exclude_credentials,
            )?;

        // Store challenge state
        let challenge_id = format!("reg_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + Duration::minutes(5);

        let stored_reg_challenge = StoredRegistrationChallenge {
            state: registration_state,
            user_id: user.id,
            username: user.username.clone(),
        };

        let challenge = StoredChallenge {
            id: challenge_id,
            user_id: Some(user.id),
            challenge_type: "registration".to_string(),
            challenge_data: serde_json::to_value(stored_reg_challenge)?,
            expires_at,
            created_at: Utc::now(),
        };

        self.store.store_challenge(challenge)?;

        // Convert exclude credentials to server format
        let exclude_credentials_server: Vec<ServerPublicKeyCredentialDescriptor> = creation_challenge
            .exclude_credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: base64::encode_config(&cred.id, base64::URL_SAFE_NO_PAD),
                transports: None,
            })
            .collect();

        // Build response
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
            timeout: Some(self.timeout_ms),
            exclude_credentials: exclude_credentials_server,
            authenticator_selection: request.authenticator_selection,
            attestation: request.attestation,
            extensions: None,
        };

        tracing::info!("Generated registration challenge for user: {}", request.username);
        Ok(response)
    }

    pub async fn handle_attestation_result(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        tracing::info!("Processing registration result for credential: {}", credential.id);

        // Extract challenge from clientDataJSON
        let client_data = self.extract_client_data_json(&credential)?;
        
        // Find stored challenge by looking through all challenges
        // In a real implementation, you'd have a better lookup mechanism
        let stored_challenge = self.find_registration_challenge_by_value(&client_data.challenge)?;

        // Parse the stored challenge data
        let stored_reg_challenge: StoredRegistrationChallenge =
            serde_json::from_value(stored_challenge.challenge_data)?;

        // Convert to RegisterPublicKeyCredential
        let reg_credential = self.convert_to_register_credential(&credential)?;

        // Complete WebAuthn registration
        let passkey = self
            .webauthn
            .finish_passkey_registration(&reg_credential, &stored_reg_challenge.state)?;

        // Store the new credential
        self.store.store_credential(
            stored_reg_challenge.user_id,
            &stored_reg_challenge.username,
            passkey,
        )?;

        tracing::info!(
            "Successfully registered credential: {} for user: {}",
            credential.id,
            stored_reg_challenge.username
        );

        Ok(ServerResponse::ok())
    }

    pub async fn handle_assertion_options(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        tracing::info!("Starting authentication for user: {}", request.username);

        // Validate input
        if request.username.is_empty() {
            return Err(AppError::missing_field("username"));
        }

        // Get user credentials
        let credentials = self.store.get_credentials(&request.username);

        if credentials.is_empty() {
            return Err(AppError::UserNotFound {
                username: request.username.clone(),
            });
        }

        // Convert credentials to CredentialID format
        let allow_credentials: Vec<CredentialID> = credentials
            .iter()
            .map(|c| c.passkey.cred_id().to_vec())
            .collect();

        // Start WebAuthn authentication
        let (request_challenge, auth_state) = self
            .webauthn
            .start_passkey_authentication(&allow_credentials)?;

        // Store challenge state
        let challenge_id = format!("auth_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + Duration::minutes(5);

        let stored_auth_challenge = StoredAuthenticationChallenge {
            state: auth_state,
            username: request.username.clone(),
        };

        let challenge = StoredChallenge {
            id: challenge_id,
            user_id: None,
            challenge_type: "authentication".to_string(),
            challenge_data: serde_json::to_value(stored_auth_challenge)?,
            expires_at,
            created_at: Utc::now(),
        };

        self.store.store_challenge(challenge)?;

        // Convert credentials to server format
        let allow_credentials_server: Vec<ServerPublicKeyCredentialDescriptor> = credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: base64::encode_config(&cred.passkey.cred_id(), base64::URL_SAFE_NO_PAD),
                transports: None,
            })
            .collect();

        // Build response
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge: request_challenge.challenge,
            timeout: Some(self.timeout_ms),
            rp_id: Some(self.webauthn.get_allowed_origins()[0].domain().unwrap_or("localhost").to_string()),
            allow_credentials: allow_credentials_server,
            user_verification: request.user_verification,
            extensions: None,
        };

        tracing::info!(
            "Generated authentication challenge for user: {}, credentials: {}",
            request.username,
            credentials.len()
        );

        Ok(response)
    }

    pub async fn handle_assertion_result(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        tracing::info!("Processing authentication result for credential: {}", credential.id);

        // Extract challenge from clientDataJSON
        let client_data = self.extract_client_data_json_assertion(&credential)?;

        // Find stored challenge
        let stored_challenge = self.find_authentication_challenge_by_value(&client_data.challenge)?;

        // Parse the stored challenge data
        let stored_auth_challenge: StoredAuthenticationChallenge =
            serde_json::from_value(stored_challenge.challenge_data)?;

        // Get the credential from storage
        let credential_id_bytes = base64::decode_config(&credential.id, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::validation("Invalid credential ID encoding"))?;

        let db_credential = self
            .store
            .get_credential_by_id(&credential_id_bytes)
            .ok_or(AppError::InvalidCredential)?;

        // Convert to PublicKeyCredential
        let auth_credential = self.convert_to_auth_credential(&credential)?;

        // Complete WebAuthn authentication
        let auth_result = self.webauthn.finish_passkey_authentication(
            &auth_credential,
            &stored_auth_challenge.state,
        )?;

        // Update credential counter
        self.store.update_credential_counter(&credential_id_bytes, auth_result.counter())?;

        tracing::info!(
            "Successfully authenticated credential: {} for user: {}",
            credential.id,
            stored_auth_challenge.username
        );

        Ok(ServerResponse::ok())
    }

    // Helper methods
    fn extract_client_data_json(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ClientData> {
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

    fn extract_client_data_json_assertion(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ClientData> {
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

    fn find_registration_challenge_by_value(
        &self,
        challenge_value: &str,
    ) -> Result<StoredChallenge> {
        // This is inefficient but works for testing - in production use proper indexing
        let challenges = &self.store.challenges.read().unwrap();
        for challenge in challenges.values() {
            if challenge.challenge_type == "registration" && challenge.expires_at > Utc::now() {
                if let Ok(stored_reg): Result<StoredRegistrationChallenge, _> =
                    serde_json::from_value(challenge.challenge_data.clone())
                {
                    if stored_reg.state.challenge == challenge_value {
                        return Ok(challenge.clone());
                    }
                }
            }
        }
        Err(AppError::ChallengeNotFound)
    }

    fn find_authentication_challenge_by_value(
        &self,
        challenge_value: &str,
    ) -> Result<StoredChallenge> {
        // This is inefficient but works for testing - in production use proper indexing
        let challenges = &self.store.challenges.read().unwrap();
        for challenge in challenges.values() {
            if challenge.challenge_type == "authentication" && challenge.expires_at > Utc::now() {
                if let Ok(stored_auth): Result<StoredAuthenticationChallenge, _> =
                    serde_json::from_value(challenge.challenge_data.clone())
                {
                    if stored_auth.state.challenge == challenge_value {
                        return Ok(challenge.clone());
                    }
                }
            }
        }
        Err(AppError::ChallengeNotFound)
    }

    fn convert_to_register_credential(
        &self,
        server_cred: &ServerPublicKeyCredential,
    ) -> Result<RegisterPublicKeyCredential> {
        if let crate::schema::ServerAuthenticatorResponse::Attestation(attestation_response) = &server_cred.response {
            let client_data_json = base64::decode_config(&attestation_response.client_data_json, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid clientDataJSON encoding"))?;
            
            let attestation_object = base64::decode_config(&attestation_response.attestation_object, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid attestationObject encoding"))?;

            let credential_id = base64::decode_config(&server_cred.id, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid credential ID encoding"))?;

            Ok(RegisterPublicKeyCredential {
                id: server_cred.id.clone(),
                raw_id: credential_id,
                response: AuthenticatorAttestationResponseRaw {
                    client_data_json,
                    attestation_object,
                },
                type_: "public-key".to_string(),
                extensions: serde_json::Map::new(),
            })
        } else {
            Err(AppError::validation("Expected attestation response for registration"))
        }
    }

    fn convert_to_auth_credential(
        &self,
        server_cred: &ServerPublicKeyCredential,
    ) -> Result<PublicKeyCredential> {
        if let crate::schema::ServerAuthenticatorResponse::Assertion(assertion_response) = &server_cred.response {
            let client_data_json = base64::decode_config(&assertion_response.client_data_json, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid clientDataJSON encoding"))?;
            
            let authenticator_data = base64::decode_config(&assertion_response.authenticator_data, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid authenticatorData encoding"))?;

            let signature = base64::decode_config(&assertion_response.signature, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid signature encoding"))?;

            let user_handle = if let Some(uh) = &assertion_response.user_handle {
                if !uh.is_empty() {
                    Some(base64::decode_config(uh, base64::URL_SAFE_NO_PAD)
                        .map_err(|_| AppError::validation("Invalid userHandle encoding"))?)
                } else {
                    None
                }
            } else {
                None
            };

            let credential_id = base64::decode_config(&server_cred.id, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid credential ID encoding"))?;

            Ok(PublicKeyCredential {
                id: server_cred.id.clone(),
                raw_id: credential_id,
                response: AuthenticatorAssertionResponseRaw {
                    client_data_json,
                    authenticator_data,
                    signature,
                    user_handle,
                },
                type_: "public-key".to_string(),
                extensions: AuthenticationExtensionsClientOutputs::default(),
            })
        } else {
            Err(AppError::validation("Expected assertion response for authentication"))
        }
    }
}

#[derive(serde::Deserialize)]
struct ClientData {
    challenge: String,
    origin: String,
    #[serde(rename = "type")]
    client_type: String,
}