use crate::config::WebAuthnSettings;
use crate::db::{ChallengeRepository, CredentialRepository, UserRepository};
use crate::schema::{NewAuthenticationChallenge, NewCredential, NewRegistrationChallenge, User};
use crate::{AppError, Result};
use base64::prelude::*;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u32>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialAssertion {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<BTreeMap<String, serde_json::Value>>,
}

pub struct WebAuthnService {
    webauthn: Webauthn,
    user_repo: UserRepository,
    credential_repo: CredentialRepository,
    challenge_repo: ChallengeRepository,
}

impl WebAuthnService {
    pub fn new(
        config: &WebAuthnSettings,
        user_repo: UserRepository,
        credential_repo: CredentialRepository,
        challenge_repo: ChallengeRepository,
    ) -> Result<Self> {
        let rp_id = &config.rp_id;
        let origin = Url::parse(&config.origin)
            .map_err(|_| AppError::Validation {
                message: "Invalid origin URL".to_string(),
            })?;

        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .map_err(AppError::WebAuthn)?
            .rp_name(&config.rp_name)
            .build()
            .map_err(AppError::WebAuthn)?;

        Ok(Self {
            webauthn,
            user_repo,
            credential_repo,
            challenge_repo,
        })
    }

    pub fn start_registration(
        &self,
        request: &ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        let user = self.user_repo.find_or_create(&request.username, &request.display_name)?;

        let existing_creds = self.credential_repo.find_by_user_id(user.id)?;
        let exclude_credentials: Vec<CredentialID> = existing_creds
            .iter()
            .map(|c| CredentialID::from(c.credential_id.clone()))
            .collect();

        let user_id = Uuid::from_slice(&user.user_handle)
            .map_err(|_| AppError::Validation {
                message: "Invalid user handle".to_string(),
            })?;

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                user_id,
                &user.username,
                &user.display_name,
                Some(exclude_credentials),
            )
            .map_err(AppError::WebAuthn)?;

        let expires_at = Utc::now() + Duration::seconds(30);
        let state_data = serde_json::to_vec(&reg_state)
            .map_err(|_| AppError::Validation {
                message: "Failed to serialize registration state".to_string(),
            })?;

        let challenge_record = NewRegistrationChallenge {
            user_id: user.id,
            challenge: ccr.public_key.challenge.as_ref().to_vec(),
            state_data,
            expires_at: expires_at.naive_utc(),
        };

        self.challenge_repo.store_registration_challenge(&challenge_record)?;

        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: ccr.public_key.rp,
            user: ServerPublicKeyCredentialUserEntity {
                id: BASE64_URL_SAFE_NO_PAD.encode(&user.user_handle),
                name: user.username.clone(),
                display_name: user.display_name.clone(),
            },
            challenge: BASE64_URL_SAFE_NO_PAD.encode(ccr.public_key.challenge.as_ref()),
            pub_key_cred_params: ccr.public_key.pub_key_cred_params,
            timeout: ccr.public_key.timeout.map(|t| t as u32),
            exclude_credentials: ccr
                .public_key
                .exclude_credentials
                .unwrap_or_default()
                .into_iter()
                .map(|c| ServerPublicKeyCredentialDescriptor {
                    type_: "public-key".to_string(),
                    id: BASE64_URL_SAFE_NO_PAD.encode(c.id.as_ref()),
                    transports: c.transports,
                })
                .collect(),
            authenticator_selection: ccr.public_key.authenticator_selection,
            attestation: ccr.public_key.attestation,
        };

        Ok(response)
    }

    pub fn complete_registration(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<crate::error::ServerResponse> {
        let credential_id = BASE64_URL_SAFE_NO_PAD
            .decode(&credential.id)
            .map_err(|_| AppError::Validation {
                message: "Invalid credential ID".to_string(),
            })?;

        let client_data_json = BASE64_URL_SAFE_NO_PAD
            .decode(&credential.response.client_data_json)
            .map_err(|_| AppError::Validation {
                message: "Invalid clientDataJSON".to_string(),
            })?;

        let attestation_object = BASE64_URL_SAFE_NO_PAD
            .decode(&credential.response.attestation_object)
            .map_err(|_| AppError::Validation {
                message: "Invalid attestationObject".to_string(),
            })?;

        let client_data: CollectedClientData = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::Validation {
                message: "Invalid client data JSON".to_string(),
            })?;

        let challenge_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&client_data.challenge)
            .map_err(|_| AppError::Validation {
                message: "Invalid challenge in client data".to_string(),
            })?;

        // Find the matching registration challenge across all users
        let mut matching_challenge = None;
        let mut matching_user_id = None;

        // Search through all recent registration challenges to find the matching one
        // This is a simplified approach - in production you might want to store challenge->user mapping
        for user_result in [/* we need a different approach */].iter() {
            // Skip this complex lookup for now
        }

        // Simplified: find any registration challenge with matching challenge bytes
        // In practice, we'd need to iterate through users or have a better indexing strategy
        
        // For now, let's extract user info from the client data if possible
        // and use a different strategy

        let register_pk_cred = RegisterPublicKeyCredential {
            id: credential.id.clone(),
            raw_id: credential_id.clone(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: attestation_object.clone(),
                client_data_json: client_data_json.clone(),
            },
            type_: "public-key".to_string(),
        };

        // We need to find the user and challenge state
        // For now, let's implement a basic approach that stores challenge with user info
        let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(&challenge_bytes);
        
        // Try to find registration challenge by iterating (not efficient, but works for demo)
        let challenge_and_user = self.find_registration_challenge_by_bytes(&challenge_bytes)?;
        let (reg_challenge, user_id) = challenge_and_user;

        let reg_state: PasskeyRegistration = serde_json::from_slice(&reg_challenge.state_data)
            .map_err(|_| AppError::ChallengeExpired)?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(&register_pk_cred, &reg_state)
            .map_err(AppError::WebAuthn)?;

        let new_credential = NewCredential {
            user_id,
            credential_id: passkey.cred_id().clone(),
            public_key: serde_json::to_vec(passkey.cred())
                .map_err(|_| AppError::Validation {
                    message: "Failed to serialize public key".to_string(),
                })?,
            sign_count: passkey.counter() as i64,
            backup_eligible: passkey.backup_eligible(),
            backup_state: passkey.backup_state(),
            attestation_format: Some("none".to_string()),
        };

        self.credential_repo.create(&new_credential)?;

        // Clean up challenge
        self.challenge_repo.delete_registration_challenge(user_id)?;

        Ok(crate::error::ServerResponse::ok())
    }

    fn find_registration_challenge_by_bytes(&self, challenge_bytes: &[u8]) -> Result<(crate::schema::RegistrationChallenge, Uuid)> {
        // This is a helper method to find registration challenges
        // In a production system, you'd want better indexing
        
        // For now, we'll have to implement a database query that finds by challenge bytes
        // This requires adding a method to ChallengeRepository
        self.challenge_repo.find_registration_challenge_by_bytes(challenge_bytes)
    }

    pub fn start_authentication(
        &self,
        request: &ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        let user = self
            .user_repo
            .find_by_username(&request.username)?
            .ok_or(AppError::UserNotFound)?;

        let credentials = self.credential_repo.find_by_user_id(user.id)?;

        let passkeys: Vec<Passkey> = credentials
            .iter()
            .filter_map(|c| {
                serde_json::from_slice(&c.public_key).ok()
            })
            .collect();

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(AppError::WebAuthn)?;

        let expires_at = Utc::now() + Duration::seconds(60);
        let state_data = serde_json::to_vec(&auth_state)
            .map_err(|_| AppError::Validation {
                message: "Failed to serialize authentication state".to_string(),
            })?;

        let challenge_record = NewAuthenticationChallenge {
            user_id: Some(user.id),
            challenge: rcr.public_key.challenge.as_ref().to_vec(),
            state_data,
            expires_at: expires_at.naive_utc(),
        };

        self.challenge_repo.store_authentication_challenge(&challenge_record)?;

        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge: BASE64_URL_SAFE_NO_PAD.encode(rcr.public_key.challenge.as_ref()),
            timeout: rcr.public_key.timeout.map(|t| t as u32),
            rp_id: rcr.public_key.rp_id.to_string(),
            allow_credentials: rcr
                .public_key
                .allow_credentials
                .into_iter()
                .map(|c| ServerPublicKeyCredentialDescriptor {
                    type_: "public-key".to_string(),
                    id: BASE64_URL_SAFE_NO_PAD.encode(c.id.as_ref()),
                    transports: c.transports,
                })
                .collect(),
            user_verification: rcr.public_key.user_verification,
        };

        Ok(response)
    }

    pub fn complete_authentication(
        &self,
        assertion: &ServerPublicKeyCredentialAssertion,
    ) -> Result<crate::error::ServerResponse> {
        let credential_id = BASE64_URL_SAFE_NO_PAD
            .decode(&assertion.id)
            .map_err(|_| AppError::Validation {
                message: "Invalid credential ID".to_string(),
            })?;

        let client_data_json = BASE64_URL_SAFE_NO_PAD
            .decode(&assertion.response.client_data_json)
            .map_err(|_| AppError::Validation {
                message: "Invalid clientDataJSON".to_string(),
            })?;

        let authenticator_data = BASE64_URL_SAFE_NO_PAD
            .decode(&assertion.response.authenticator_data)
            .map_err(|_| AppError::Validation {
                message: "Invalid authenticatorData".to_string(),
            })?;

        let signature = BASE64_URL_SAFE_NO_PAD
            .decode(&assertion.response.signature)
            .map_err(|_| AppError::Validation {
                message: "Invalid signature".to_string(),
            })?;

        let client_data: CollectedClientData = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::Validation {
                message: "Invalid client data JSON".to_string(),
            })?;

        let challenge_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&client_data.challenge)
            .map_err(|_| AppError::Validation {
                message: "Invalid challenge in client data".to_string(),
            })?;

        let challenge_record = self
            .challenge_repo
            .get_authentication_challenge(&challenge_bytes)?
            .ok_or(AppError::ChallengeExpired)?;

        let auth_state: PasskeyAuthentication = serde_json::from_slice(&challenge_record.state_data)
            .map_err(|_| AppError::ChallengeExpired)?;

        let credential = self
            .credential_repo
            .find_by_credential_id(&credential_id)?
            .ok_or(AppError::CredentialNotFound)?;

        // Check counter regression
        let parsed_auth_data = AuthenticatorData::try_from(authenticator_data.as_slice())
            .map_err(|_| AppError::Validation {
                message: "Invalid authenticator data".to_string(),
            })?;

        if parsed_auth_data.counter <= credential.sign_count as u32 {
            return Err(AppError::CounterRegression);
        }

        let auth_pk_cred = PublicKeyCredential {
            id: assertion.id.clone(),
            raw_id: credential_id.clone(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: authenticator_data.clone(),
                client_data_json: client_data_json.clone(),
                signature: signature.clone(),
                user_handle: assertion.response.user_handle.as_ref().and_then(|h| {
                    BASE64_URL_SAFE_NO_PAD.decode(h).ok()
                }),
            },
            type_: "public-key".to_string(),
        };

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(&auth_pk_cred, &auth_state)
            .map_err(AppError::WebAuthn)?;

        // Update counter
        self.credential_repo
            .update_sign_count(&credential_id, parsed_auth_data.counter as i64)?;

        // Clean up challenge
        self.challenge_repo.delete_authentication_challenge(&challenge_bytes)?;

        Ok(crate::error::ServerResponse::ok())
    }
}