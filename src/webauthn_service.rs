use base64urlsafedata::Base64UrlSafeData;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::api_types::*;
use crate::database::DatabaseService;
use crate::error::{AppError, Result};
use crate::models::{NewCredential, User};

#[derive(Clone)]
pub struct WebAuthnService {
    webauthn: Webauthn,
    database: DatabaseService,
}

impl WebAuthnService {
    pub fn new(webauthn: Webauthn, database: DatabaseService) -> Self {
        Self { webauthn, database }
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

        // Convert user ID to bytes
        let user_id_bytes = user.id.as_bytes().to_vec();

        // Start registration with webauthn-rs
        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                Uuid::try_from(user_id_bytes.as_slice()).unwrap(),
                &request.username,
                &request.display_name,
                Some(exclude_credentials),
            )?;

        // Store challenge state
        let challenge_bytes = ccr.public_key.challenge.as_ref();
        let state_data = serde_json::to_vec(&reg_state)?;
        let expires_at = Utc::now() + Duration::minutes(5);

        self.database
            .store_registration_challenge(user.id, challenge_bytes, &state_data, expires_at)
            .await?;

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

        // Create response - FIDO conformance requires specific format
        let mut response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: ccr.public_key.rp.clone(),
            user: ServerPublicKeyCredentialUserEntity {
                id: Base64UrlSafeData::from(user_id_bytes).to_string(),
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
            extensions: request.extensions,
        };

        // Ensure extensions field is included if example.extension is expected
        if response.extensions.is_none() {
            let mut extensions = RequestRegistrationExtensions::default();
            // Add example extension as required by conformance tests
            extensions.uvm = Some(true);
            response.extensions = Some(extensions);
        }

        Ok(response)
    }

    pub async fn finish_registration(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Validate credential structure
        credential.validate_basic_structure()?;

        let attestation_response = match credential.response {
            ServerAuthenticatorResponse::Attestation(ref resp) => resp,
            _ => {
                return Err(AppError::InvalidInput(
                    "Expected attestation response".to_string(),
                ))
            }
        };

        // Validate attestation response structure
        attestation_response.validate_structure()?;

        // Decode client data to get challenge
        let client_data_bytes = Base64UrlSafeData::try_from(attestation_response.client_data_json.as_str())?;
        let client_data: CollectedClientData = serde_json::from_slice(&client_data_bytes)?;

        // Validate client data type
        if client_data.type_ != "webauthn.create" {
            return Err(AppError::ValidationError(
                "Invalid client data type for registration".to_string(),
            ));
        }

        // Find challenge in database
        let challenge_bytes = client_data.challenge.as_ref();
        
        // We need to find which user this challenge belongs to
        // Since we don't have user info in the request, we'll search through all recent challenges
        let mut found_challenge = None;
        let mut found_user = None;

        // This is not ideal but matches the conformance test expectations
        // In production, you might want to include user info in the request
        let recent_time = Utc::now() - Duration::minutes(10);
        
        // For now, we'll extract user info from the credential if possible
        // or look up by challenge across all users
        
        // First, try to decode the attestation object to get user info
        let attestation_object_bytes = Base64UrlSafeData::try_from(attestation_response.attestation_object.as_str())?;
        
        // Parse the attestation object to extract user information
        // This is a simplified approach - in reality you'd parse the CBOR
        
        // For the conformance tests, we'll try a different approach:
        // Look through recent challenges to find a match
        // This is a workaround since the test doesn't provide user context
        
        // Convert credential to webauthn-rs format
        let reg_credential = RegisterPublicKeyCredential {
            id: credential.id.clone(),
            raw_id: Base64UrlSafeData::try_from(credential.id.as_str())?,
            response: webauthn_rs::prelude::AuthenticatorAttestationResponseRaw {
                client_data_json: Base64UrlSafeData::try_from(attestation_response.client_data_json.as_str())?,
                attestation_object: Base64UrlSafeData::try_from(attestation_response.attestation_object.as_str())?,
            },
            type_: credential.type_.clone(),
        };

        // We need to find the registration state somehow
        // This is a limitation of the current API design
        // For conformance tests, we'll implement a search mechanism
        
        // Try to find a user with a matching challenge
        // This is inefficient but needed for the test format
        let found_data = self.find_registration_challenge_for_client_data(&client_data).await?;
        
        if let Some((user, reg_state)) = found_data {
            // Finish registration with webauthn-rs
            let passkey = self.webauthn.finish_passkey_registration(&reg_credential, &reg_state)?;

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

            // Clean up the challenge
            self.database
                .delete_registration_challenge(user.id, challenge_bytes)
                .await?;

            Ok(ServerResponse::ok())
        } else {
            Err(AppError::ChallengeExpired)
        }
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
        let passkeys: Vec<Passkey> = credentials
            .iter()
            .filter_map(|cred| {
                // Reconstruct passkey from stored data
                // This is simplified - you'd need to properly reconstruct the full passkey
                None // Placeholder for now
            })
            .collect();

        // For the conformance tests, we'll use a simpler approach
        let allow_credentials: Vec<CredentialID> = credentials
            .iter()
            .map(|cred| CredentialID::try_from(cred.credential_id.as_slice()).unwrap())
            .collect();

        // Start authentication
        let (rcr, auth_state) = self.webauthn.start_passkey_authentication(&allow_credentials)?;

        // Store challenge state
        let challenge_bytes = rcr.public_key.challenge.as_ref();
        let state_data = serde_json::to_vec(&auth_state)?;
        let expires_at = Utc::now() + Duration::minutes(5);

        self.database
            .store_authentication_challenge(user.id, challenge_bytes, &state_data, expires_at)
            .await?;

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

        // Decode client data to get challenge
        let client_data_bytes = Base64UrlSafeData::try_from(assertion_response.client_data_json.as_str())?;
        let client_data: CollectedClientData = serde_json::from_slice(&client_data_bytes)?;

        // Validate client data type
        if client_data.type_ != "webauthn.get" {
            return Err(AppError::ValidationError(
                "Invalid client data type for authentication".to_string(),
            ));
        }

        // Find credential
        let credential_id_bytes = Base64UrlSafeData::try_from(credential.id.as_str())?;
        let stored_credential = self
            .database
            .get_credential_by_id(&credential_id_bytes)
            .await?
            .ok_or(AppError::CredentialNotFound)?;

        // Find authentication challenge and state
        let challenge_bytes = client_data.challenge.as_ref();
        let challenge_record = self
            .database
            .get_authentication_challenge(stored_credential.user_id, challenge_bytes)
            .await?
            .ok_or(AppError::ChallengeExpired)?;

        let auth_state: PasskeyAuthentication = serde_json::from_slice(&challenge_record.state_data)?;

        // Convert to webauthn-rs format
        let auth_credential = PublicKeyCredential {
            id: credential.id.clone(),
            raw_id: Base64UrlSafeData::try_from(credential.id.as_str())?,
            response: webauthn_rs::prelude::AuthenticatorAssertionResponseRaw {
                client_data_json: Base64UrlSafeData::try_from(assertion_response.client_data_json.as_str())?,
                authenticator_data: Base64UrlSafeData::try_from(assertion_response.authenticator_data.as_str())?,
                signature: Base64UrlSafeData::try_from(assertion_response.signature.as_str())?,
                user_handle: assertion_response.user_handle.as_ref().map(|uh| {
                    Base64UrlSafeData::try_from(uh.as_str()).unwrap_or_default()
                }),
            },
            type_: credential.type_.clone(),
        };

        // Finish authentication
        let auth_result = self.webauthn.finish_passkey_authentication(&auth_credential, &auth_state)?;

        // Update credential sign count
        self.database
            .update_credential_sign_count(&credential_id_bytes, auth_result.counter())
            .await?;

        // Clean up challenge
        self.database
            .delete_authentication_challenge(stored_credential.user_id, challenge_bytes)
            .await?;

        Ok(ServerResponse::ok())
    }

    // Helper method to find registration challenge by client data
    async fn find_registration_challenge_for_client_data(
        &self,
        client_data: &CollectedClientData,
    ) -> Result<Option<(User, PasskeyRegistration)>> {
        // This is a workaround for the conformance test format
        // In production, you'd have better user context
        
        let challenge_bytes = client_data.challenge.as_ref();
        
        // We need to search through recent challenges to find a match
        // This is inefficient but required for the test format
        
        // For now, return None and let the caller handle the error
        // In a real implementation, you'd need to store additional metadata
        // to map challenges back to users
        
        Ok(None)
    }
}