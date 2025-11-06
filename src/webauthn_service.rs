use base64urlsafedata::Base64UrlSafeData;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Webauthn, CredentialID, PasskeyRegistration, PasskeyAuthentication,
    RegisterPublicKeyCredential, PublicKeyCredential, CollectedClientData,
    AuthenticatorTransport, RequestRegistrationExtensions
};

use crate::api_types::*;
use crate::database::DatabaseService;
use crate::error::{AppError, Result};
use crate::models::{NewCredential, User};

// Session store to handle the challenge-to-user mapping
// This is needed because the FIDO conformance test API doesn't provide user context in finish operations
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
            .map(|cred| CredentialID::try_from(cred.credential_id.as_slice()).unwrap())
            .collect();

        // Convert user ID to bytes for webauthn-rs
        let user_uuid = user.id;

        // Start registration with webauthn-rs
        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                user_uuid,
                &request.username,
                &request.display_name,
                Some(exclude_credentials),
            )?;

        // Store challenge state in database
        let challenge_bytes = ccr.public_key.challenge.as_ref();
        let state_data = serde_json::to_vec(&reg_state)?;
        let expires_at = Utc::now() + Duration::minutes(5);

        self.database
            .store_registration_challenge(user.id, challenge_bytes, &state_data, expires_at)
            .await?;

        // Store challenge-to-user mapping in session store
        let challenge_str = ccr.public_key.challenge.to_string();
        self.sessions.write().await.insert(challenge_str.clone(), (user.id, "registration".to_string()));

        // Build exclude credentials for response
        let exclude_creds: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: Base64UrlSafeData::from(cred.credential_id.clone()).to_string(),
                transports: cred.transports.as_ref().and_then(|t| {
                    t.iter()
                        .map(|s| s.parse::<AuthenticatorTransport>().ok())
                        .collect::<Option<Vec<_>>>()
                }),
            })
            .collect();

        // Create response that matches FIDO conformance requirements
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: ccr.public_key.rp.clone(),
            user: ServerPublicKeyCredentialUserEntity {
                id: Base64UrlSafeData::from(user_uuid.as_bytes().to_vec()).to_string(),
                name: request.username,
                display_name: request.display_name,
                icon: None,
            },
            challenge: ccr.public_key.challenge.to_string(),
            pub_key_cred_params: ccr.public_key.pub_key_cred_params,
            timeout: ccr.public_key.timeout,
            exclude_credentials: exclude_creds,
            authenticator_selection: request.authenticator_selection,
            attestation: request.attestation,
            extensions: request.extensions.or_else(|| {
                // Add default extension for conformance tests
                let mut ext = RequestRegistrationExtensions::default();
                ext.uvm = Some(true);
                Some(ext)
            }),
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
        let client_data_bytes = base64::decode_config(&attestation_response.client_data_json, base64::URL_SAFE_NO_PAD)
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
        let challenge_str = client_data.challenge.to_string();
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
        let challenge_bytes = client_data.challenge.as_ref();
        let challenge_record = self
            .database
            .get_registration_challenge(user.id, challenge_bytes)
            .await?
            .ok_or(AppError::ChallengeExpired)?;

        let reg_state: PasskeyRegistration = serde_json::from_slice(&challenge_record.state_data)
            .map_err(|_| AppError::InternalServerError)?;

        // Convert credential to webauthn-rs format
        let credential_id_bytes = base64::decode_config(&credential.id, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::InvalidFormat("Invalid credential ID format".to_string()))?;
        let client_data_json_bytes = base64::decode_config(&attestation_response.client_data_json, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::InvalidFormat("Invalid clientDataJSON format".to_string()))?;
        let attestation_object_bytes = base64::decode_config(&attestation_response.attestation_object, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::InvalidFormat("Invalid attestationObject format".to_string()))?;

        let reg_credential = RegisterPublicKeyCredential {
            id: credential.id.clone(),
            raw_id: Base64UrlSafeData::from(credential_id_bytes),
            response: webauthn_rs::AuthenticatorAttestationResponseRaw {
                client_data_json: Base64UrlSafeData::from(client_data_json_bytes),
                attestation_object: Base64UrlSafeData::from(attestation_object_bytes),
            },
            type_: credential.type_.clone(),
        };

        // Finish registration with webauthn-rs - this will perform all security validations
        let passkey = self.webauthn.finish_passkey_registration(&reg_credential, &reg_state)
            .map_err(|e| AppError::AttestationFailed(e.to_string()))?;

        // Store credential in database
        let new_credential = NewCredential {
            id: Uuid::new_v4(),
            user_id: user.id,
            credential_id: passkey.cred_id().to_vec(),
            public_key: passkey.cred().cose_key.to_vec().unwrap_or_default(),
            sign_count: passkey.counter(),
            transports: attestation_response.transports.as_ref().map(|t| {
                t.iter().map(|transport| transport.to_string()).collect()
            }),
            backup_eligible: false,
            backup_state: false,
        };

        self.database.store_credential(new_credential).await?;

        // Clean up the challenge and session
        self.database
            .delete_registration_challenge(user.id, challenge_bytes)
            .await?;
        
        self.sessions.write().await.remove(&challenge_str);

        Ok(ServerResponse::ok())
    }

    // Authentication flow
    pub async fn start_authentication(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::MissingField("username".to_string()));
        }

        // Get user
        let user = self
            .database
            .get_user_by_username(&request.username)
            .await?
            .ok_or(AppError::UserNotFound)?;

        // Get user's credentials
        let credentials = self.database.get_credentials_for_user(user.id).await?;
        
        if credentials.is_empty() {
            return Err(AppError::CredentialNotFound);
        }

        // Convert to webauthn-rs format
        let allow_credentials: Vec<CredentialID> = credentials
            .iter()
            .map(|cred| CredentialID::try_from(cred.credential_id.as_slice()).unwrap())
            .collect();

        // Start authentication
        let (rcr, auth_state) = self.webauthn.start_passkey_authentication(&allow_credentials)?;

        // Store challenge state in database
        let challenge_bytes = rcr.public_key.challenge.as_ref();
        let state_data = serde_json::to_vec(&auth_state)?;
        let expires_at = Utc::now() + Duration::minutes(5);

        self.database
            .store_authentication_challenge(user.id, challenge_bytes, &state_data, expires_at)
            .await?;

        // Store challenge-to-user mapping in session store
        let challenge_str = rcr.public_key.challenge.to_string();
        self.sessions.write().await.insert(challenge_str.clone(), (user.id, "authentication".to_string()));

        // Build allow credentials for response
        let allow_creds: Vec<ServerPublicKeyCredentialDescriptor> = credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: Base64UrlSafeData::from(cred.credential_id.clone()).to_string(),
                transports: cred.transports.as_ref().and_then(|t| {
                    t.iter()
                        .map(|s| s.parse::<AuthenticatorTransport>().ok())
                        .collect::<Option<Vec<_>>>()
                }),
            })
            .collect();

        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge: rcr.public_key.challenge.to_string(),
            timeout: rcr.public_key.timeout,
            rp_id: Some(rcr.public_key.rp_id),
            allow_credentials: allow_creds,
            user_verification: request.user_verification,
            extensions: request.extensions,
        };

        Ok(response)
    }

    pub async fn finish_authentication(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Validate credential structure
        credential.validate_basic_structure()?;

        let assertion_response = match credential.response {
            ServerAuthenticatorResponse::Assertion(ref resp) => resp,
            _ => {
                return Err(AppError::InvalidInput(
                    "Expected assertion response".to_string(),
                ))
            }
        };

        // Validate assertion response structure
        assertion_response.validate_structure()?;

        // Decode and validate client data  
        let client_data_bytes = base64::decode_config(&assertion_response.client_data_json, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::InvalidFormat("clientDataJSON must be base64url encoded".to_string()))?;
        
        let client_data: CollectedClientData = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::InvalidFormat("Invalid clientDataJSON format".to_string()))?;

        // Validate client data type
        if client_data.type_ != "webauthn.get" {
            return Err(AppError::ValidationError(
                "clientDataJSON type must be 'webauthn.get'".to_string(),
            ));
        }

        // Find user by challenge using our session store
        let challenge_str = client_data.challenge.to_string();
        let (user_id, session_type) = {
            let sessions = self.sessions.read().await;
            sessions.get(&challenge_str)
                .cloned()
                .ok_or(AppError::ChallengeExpired)?
        };

        if session_type != "authentication" {
            return Err(AppError::ValidationError("Invalid challenge type".to_string()));
        }

        // Find credential
        let credential_id_bytes = base64::decode_config(&credential.id, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::InvalidFormat("Invalid credential ID format".to_string()))?;
        
        let stored_credential = self
            .database
            .get_credential_by_id(&credential_id_bytes)
            .await?
            .ok_or(AppError::CredentialNotFound)?;

        // Verify user matches
        if stored_credential.user_id != user_id {
            return Err(AppError::AuthenticationFailed);
        }

        // Find authentication challenge and state
        let challenge_bytes = client_data.challenge.as_ref();
        let challenge_record = self
            .database
            .get_authentication_challenge(stored_credential.user_id, challenge_bytes)
            .await?
            .ok_or(AppError::ChallengeExpired)?;

        let auth_state: PasskeyAuthentication = serde_json::from_slice(&challenge_record.state_data)
            .map_err(|_| AppError::InternalServerError)?;

        // Convert to webauthn-rs format
        let auth_credential = PublicKeyCredential {
            id: credential.id.clone(),
            raw_id: Base64UrlSafeData::try_from(credential.id.as_str())
                .map_err(|_| AppError::InvalidFormat("Invalid credential ID format".to_string()))?,
            response: webauthn_rs::prelude::AuthenticatorAssertionResponseRaw {
                client_data_json: Base64UrlSafeData::try_from(assertion_response.client_data_json.as_str())
                    .map_err(|_| AppError::InvalidFormat("Invalid clientDataJSON format".to_string()))?,
                authenticator_data: Base64UrlSafeData::try_from(assertion_response.authenticator_data.as_str())
                    .map_err(|_| AppError::InvalidFormat("Invalid authenticatorData format".to_string()))?,
                signature: Base64UrlSafeData::try_from(assertion_response.signature.as_str())
                    .map_err(|_| AppError::InvalidFormat("Invalid signature format".to_string()))?,
                user_handle: assertion_response.user_handle.as_ref().map(|uh| {
                    Base64UrlSafeData::try_from(uh.as_str()).unwrap_or_default()
                }),
            },
            type_: credential.type_.clone(),
        };

        // Finish authentication with webauthn-rs - this performs all security validations
        let auth_result = self.webauthn.finish_passkey_authentication(&auth_credential, &auth_state)
            .map_err(|e| AppError::AuthenticationFailed)?;

        // Update credential sign count
        self.database
            .update_credential_sign_count(&credential_id_bytes, auth_result.counter())
            .await?;

        // Clean up challenge and session
        self.database
            .delete_authentication_challenge(stored_credential.user_id, challenge_bytes)
            .await?;
        
        self.sessions.write().await.remove(&challenge_str);

        Ok(ServerResponse::ok())
    }
}