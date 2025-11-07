use std::sync::Arc;
use std::collections::HashMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::RngCore;
use uuid::Uuid;
use url::Url;
use webauthn_rs::{prelude::*, Webauthn, WebauthnBuilder};
use webauthn_rs_proto::{
    AttestationConveyancePreference, 
    CollectedClientData, RegisterPublicKeyCredential, PublicKeyCredential,
    AuthenticatorAttestationResponseRaw, AuthenticatorAssertionResponseRaw,
};

use crate::{
    config::settings::WebAuthnSettings,
    error::{AppError, Result},
    schemas::{request::*, response::*},
    storage::{MemoryStorage, MemoryUser},
};

#[derive(Clone)]
pub struct SimpleWebAuthnService {
    webauthn: Arc<Webauthn>,
    storage: MemoryStorage,
    registration_states: Arc<std::sync::RwLock<HashMap<String, PasskeyRegistration>>>,
    authentication_states: Arc<std::sync::RwLock<HashMap<String, PasskeyAuthentication>>>,
}

impl SimpleWebAuthnService {
    pub fn new(config: &WebAuthnSettings) -> Result<Self> {
        let origin = Url::parse(&config.origin)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid origin URL: {e}")))?;

        let webauthn = WebauthnBuilder::new(&config.rp_id, &origin)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to create WebAuthn builder: {e}")))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| AppError::WebAuthnError(format!("Failed to build WebAuthn: {e}")))?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
            storage: MemoryStorage::new(),
            registration_states: Arc::new(std::sync::RwLock::new(HashMap::new())),
            authentication_states: Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    pub async fn begin_registration(&self, req: RegistrationBeginRequest) -> Result<RegistrationBeginResponse> {
        // Check if user already exists
        let user = if let Some(existing_user) = self.storage.find_user_by_username(&req.username) {
            existing_user
        } else {
            // Create new user
            let user_id = self.generate_user_id();
            self.storage.create_user(req.username.clone(), req.display_name.clone(), user_id)
        };

        // Get existing credentials to exclude
        let exclude_credentials = self.storage.get_user_credentials(user.id);
        let exclude_list: Vec<CredentialID> = exclude_credentials
            .into_iter()
            .map(|cred| CredentialID::from(cred.credential_id))
            .collect();

        // Convert user.user_id bytes to Uuid
        let user_uuid = if user.user_id.len() == 16 {
            Uuid::from_slice(&user.user_id)
                .map_err(|e| AppError::ValidationError(format!("Invalid user ID: {e}")))?
        } else {
            Uuid::new_v4()
        };

        // Generate registration challenge
        let (ccr, reg_state) = self.webauthn
            .start_passkey_registration(
                user_uuid,
                &user.username,
                &user.display_name,
                Some(exclude_list),
            )
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start registration: {e}")))?;

        // Store challenge
        let challenge_bytes = ccr.public_key.challenge.as_ref().to_vec();
        let expires_at = Utc::now() + Duration::minutes(5);
        self.storage.store_challenge(
            challenge_bytes.clone(),
            Some(user.id),
            "registration".to_string(),
            expires_at,
        );

        // Store registration state with challenge as key
        let challenge_key = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        {
            let mut states = self.registration_states.write().unwrap();
            states.insert(challenge_key.clone(), reg_state);
        }

        // Convert to API response format
        Ok(RegistrationBeginResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            rp: crate::schemas::response::RelyingParty {
                name: ccr.public_key.rp.name.clone(),
                id: Some(ccr.public_key.rp.id.clone()),
            },
            user: PublicKeyCredentialUserEntity {
                id: URL_SAFE_NO_PAD.encode(&ccr.public_key.user.id),
                name: ccr.public_key.user.name.clone(),
                display_name: ccr.public_key.user.display_name.clone(),
            },
            challenge: URL_SAFE_NO_PAD.encode(&challenge_bytes),
            pub_key_cred_params: ccr.public_key.pub_key_cred_params.clone(),
            timeout: ccr.public_key.timeout.map(|t| t as u64),
            exclude_credentials: ccr.public_key.exclude_credentials
                .unwrap_or_default()
                .into_iter()
                .map(|desc| crate::schemas::response::PublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: URL_SAFE_NO_PAD.encode(desc.id.as_ref()),
                    transports: desc.transports.map(|t| {
                        t.into_iter().map(|transport| transport.to_string()).collect()
                    }),
                })
                .collect(),
            authenticator_selection: ccr.public_key.authenticator_selection.clone(),
            attestation: ccr.public_key.attestation.unwrap_or(AttestationConveyancePreference::None),
            extensions: None,
        })
    }

    pub async fn complete_registration(&self, req: RegistrationCompleteRequest) -> Result<ServerResponse> {
        // Decode the credential ID
        let credential_id = URL_SAFE_NO_PAD.decode(&req.id)
            .map_err(|e| AppError::ValidationError(format!("Invalid credential ID: {e}")))?;

        // Decode client data JSON
        let client_data_json = URL_SAFE_NO_PAD.decode(&req.response.client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON: {e}")))?;

        // Parse client data to get challenge
        let client_data: CollectedClientData = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON format: {e}")))?;

        // Decode challenge
        let challenge_bytes = URL_SAFE_NO_PAD.decode(&client_data.challenge)
            .map_err(|e| AppError::ValidationError(format!("Invalid challenge: {e}")))?;

        // Find and consume challenge
        let challenge = self.storage.find_and_consume_challenge(&challenge_bytes, "registration")
            .ok_or_else(|| AppError::ValidationError("Invalid or expired challenge".to_string()))?;

        // Get user
        let user = if let Some(user_id) = challenge.user_id {
            self.storage.find_user_by_id(user_id)
                .ok_or_else(|| AppError::NotFound("User not found".to_string()))?
        } else {
            return Err(AppError::ValidationError("Invalid challenge state".to_string()));
        };

        // Build RegisterPublicKeyCredential for webauthn-rs
        let reg_credential = RegisterPublicKeyCredential {
            id: req.id.clone(),
            raw_id: Base64UrlSafeData::from(credential_id.clone()),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData::from(
                    URL_SAFE_NO_PAD.decode(&req.response.attestation_object)
                        .map_err(|e| AppError::ValidationError(format!("Invalid attestation object: {e}")))?
                ),
                client_data_json: Base64UrlSafeData::from(client_data_json),
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        };

        // Retrieve the stored registration state using challenge as key
        let challenge_key = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let reg_state = {
            let mut states = self.registration_states.write().unwrap();
            states.remove(&challenge_key)
                .ok_or_else(|| AppError::ValidationError("Registration state not found".to_string()))?
        };

        // Complete registration
        let passkey = self.webauthn
            .finish_passkey_registration(&reg_credential, &reg_state)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to complete registration: {e}")))?;

        // Store credential
        let passkey_data = serde_json::to_vec(&passkey)
            .map_err(|e| AppError::ValidationError(format!("Failed to serialize passkey: {e}")))?;

        self.storage.store_credential(user.id, credential_id, passkey_data);

        Ok(ServerResponse::ok())
    }

    pub async fn begin_authentication(&self, req: AuthenticationBeginRequest) -> Result<AuthenticationBeginResponse> {
        // Find user
        let user = self.storage.find_user_by_username(&req.username)
            .ok_or_else(|| AppError::NotFound("User does not exist!".to_string()))?;

        // Get user's credentials
        let credentials = self.storage.get_user_credentials(user.id);

        if credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Convert credentials to passkeys
        let passkeys: Vec<Passkey> = credentials
            .into_iter()
            .map(|cred| self.credential_to_passkey(cred))
            .collect::<Result<Vec<_>>>()?;

        // Generate authentication challenge
        let (request_challenge_response, auth_state) = self.webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start authentication: {e}")))?;

        // Store challenge
        let challenge_bytes = request_challenge_response.public_key.challenge.as_ref().to_vec();
        let expires_at = Utc::now() + Duration::minutes(5);
        self.storage.store_challenge(
            challenge_bytes.clone(),
            Some(user.id),
            "authentication".to_string(),
            expires_at,
        );

        // Store authentication state with challenge as key
        let challenge_key = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        {
            let mut states = self.authentication_states.write().unwrap();
            states.insert(challenge_key.clone(), auth_state);
        }

        // Convert to API response format
        Ok(AuthenticationBeginResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge: URL_SAFE_NO_PAD.encode(&challenge_bytes),
            timeout: request_challenge_response.public_key.timeout.map(|t| t as u64),
            rp_id: request_challenge_response.public_key.rp_id.clone(),
            allow_credentials: request_challenge_response.public_key.allow_credentials
                .into_iter()
                .map(|desc| crate::schemas::response::PublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: URL_SAFE_NO_PAD.encode(desc.id.as_ref()),
                    transports: desc.transports.map(|t| {
                        t.into_iter().map(|transport| transport.to_string()).collect()
                    }),
                })
                .collect(),
            user_verification: req.user_verification,
            extensions: None,
        })
    }

    pub async fn complete_authentication(&self, req: AuthenticationCompleteRequest) -> Result<ServerResponse> {
        // Decode client data JSON to get challenge
        let client_data_json = URL_SAFE_NO_PAD.decode(&req.response.client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON: {e}")))?;

        let client_data: CollectedClientData = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON format: {e}")))?;

        let challenge_bytes = URL_SAFE_NO_PAD.decode(&client_data.challenge)
            .map_err(|e| AppError::ValidationError(format!("Invalid challenge: {e}")))?;

        // Find and consume challenge
        let challenge = self.storage.find_and_consume_challenge(&challenge_bytes, "authentication")
            .ok_or_else(|| AppError::ValidationError("Invalid or expired challenge".to_string()))?;

        let user = if let Some(user_id) = challenge.user_id {
            self.storage.find_user_by_id(user_id)
                .ok_or_else(|| AppError::NotFound("User not found".to_string()))?
        } else {
            return Err(AppError::ValidationError("Invalid challenge state".to_string()));
        };

        // Get user's credentials and convert to passkeys
        let credentials = self.storage.get_user_credentials(user.id);
        let _passkeys: Vec<Passkey> = credentials
            .into_iter()
            .map(|cred| self.credential_to_passkey(cred))
            .collect::<Result<Vec<_>>>()?;

        // Build PublicKeyCredential for authentication
        let auth_credential = PublicKeyCredential {
            id: req.id.clone(),
            raw_id: Base64UrlSafeData::from(URL_SAFE_NO_PAD.decode(&req.id)
                .map_err(|e| AppError::ValidationError(format!("Invalid credential ID: {e}")))?),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: Base64UrlSafeData::from(
                    URL_SAFE_NO_PAD.decode(&req.response.authenticator_data)
                        .map_err(|e| AppError::ValidationError(format!("Invalid authenticator data: {e}")))?
                ),
                client_data_json: Base64UrlSafeData::from(client_data_json),
                signature: Base64UrlSafeData::from(
                    URL_SAFE_NO_PAD.decode(&req.response.signature)
                        .map_err(|e| AppError::ValidationError(format!("Invalid signature: {e}")))?
                ),
                user_handle: if req.response.user_handle.is_empty() {
                    None
                } else {
                    Some(Base64UrlSafeData::from(
                        URL_SAFE_NO_PAD.decode(&req.response.user_handle)
                            .map_err(|e| AppError::ValidationError(format!("Invalid user handle: {e}")))?
                    ))
                },
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        };

        // Retrieve the stored authentication state using challenge as key
        let challenge_key = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let auth_state = {
            let mut states = self.authentication_states.write().unwrap();
            states.remove(&challenge_key)
                .ok_or_else(|| AppError::ValidationError("Authentication state not found".to_string()))?
        };

        // Complete authentication
        let auth_result = self.webauthn
            .finish_passkey_authentication(&auth_credential, &auth_state)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to complete authentication: {e}")))?;

        // Update credential counter
        let credential_id = URL_SAFE_NO_PAD.decode(&req.id)
            .map_err(|e| AppError::ValidationError(format!("Invalid credential ID: {e}")))?;

        self.storage.update_credential_counter(&credential_id, auth_result.counter() as i64);

        Ok(ServerResponse::ok())
    }

    // Helper methods
    fn generate_user_id(&self) -> Vec<u8> {
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        id.to_vec()
    }

    fn credential_to_passkey(&self, credential: crate::storage::MemoryCredential) -> Result<Passkey> {
        // Deserialize the stored passkey data
        serde_json::from_slice(&credential.public_key)
            .map_err(|e| AppError::ValidationError(format!("Failed to deserialize passkey: {e}")))
    }
}