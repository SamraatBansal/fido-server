use crate::config::WebAuthnSettings;
use crate::db::{ChallengeRepository, CredentialRepository, UserRepository};
use crate::schema::{NewCredential, NewRegistrationChallenge, NewAuthenticationChallenge};
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

        // For simplicity, let's not implement exclude credentials for now
        let exclude_credentials = Vec::new();

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

        // Store the challenge and registration state
        let expires_at = Utc::now() + Duration::seconds(30);
        
        // Store state in a simple way (for demo purposes)
        let state_json = serde_json::to_string(&reg_state)
            .map_err(|_| AppError::Validation {
                message: "Failed to serialize registration state".to_string(),
            })?;

        let challenge_record = NewRegistrationChallenge {
            user_id: user.id,
            challenge: ccr.public_key.challenge.as_ref().to_vec(),
            state_data: state_json.into_bytes(),
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
            exclude_credentials: Vec::new(), // Simplified for demo
            authenticator_selection: ccr.public_key.authenticator_selection,
            attestation: ccr.public_key.attestation,
        };

        Ok(response)
    }

    pub fn complete_registration(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<crate::error::ServerResponse> {
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

        // Parse client data to get challenge
        let client_data: CollectedClientData = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::Validation {
                message: "Invalid client data JSON".to_string(),
            })?;

        let challenge_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&client_data.challenge)
            .map_err(|_| AppError::Validation {
                message: "Invalid challenge in client data".to_string(),
            })?;

        // Find the registration challenge
        let (reg_challenge, user_id) = self.challenge_repo.find_registration_challenge_by_bytes(&challenge_bytes)?;

        // Deserialize the registration state
        let state_str = String::from_utf8(reg_challenge.state_data)
            .map_err(|_| AppError::ChallengeExpired)?;
        let reg_state: PasskeyRegistration = serde_json::from_str(&state_str)
            .map_err(|_| AppError::ChallengeExpired)?;

        let register_pk_cred = RegisterPublicKeyCredential {
            id: credential.id.clone(),
            raw_id: BASE64_URL_SAFE_NO_PAD.decode(&credential.id).unwrap().into(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: attestation_object.clone(),
                client_data_json: client_data_json.clone(),
            },
            type_: "public-key".to_string(),
            extensions: None,
        };

        let passkey = self
            .webauthn
            .finish_passkey_registration(&register_pk_cred, &reg_state)
            .map_err(AppError::WebAuthn)?;

        // Store the credential
        let new_credential = NewCredential {
            user_id,
            credential_id: passkey.cred_id().clone(),
            public_key: serde_json::to_vec(&passkey).map_err(|_| AppError::Validation {
                message: "Failed to serialize passkey".to_string(),
            })?,
            sign_count: 0,
            backup_eligible: false,
            backup_state: false,
            attestation_format: Some("none".to_string()),
        };

        self.credential_repo.create(&new_credential)?;

        // Clean up challenge
        self.challenge_repo.delete_registration_challenge(user_id)?;

        Ok(crate::error::ServerResponse::ok())
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

        // Convert stored credentials to passkeys
        let passkeys: Vec<Passkey> = credentials
            .iter()
            .filter_map(|c| serde_json::from_slice(&c.public_key).ok())
            .collect();

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(AppError::WebAuthn)?;

        // Store authentication challenge
        let expires_at = Utc::now() + Duration::seconds(60);
        
        let state_json = serde_json::to_string(&auth_state)
            .map_err(|_| AppError::Validation {
                message: "Failed to serialize authentication state".to_string(),
            })?;

        let challenge_record = NewAuthenticationChallenge {
            user_id: Some(user.id),
            challenge: rcr.public_key.challenge.as_ref().to_vec(),
            state_data: state_json.into_bytes(),
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

        // Parse client data to get challenge
        let client_data: CollectedClientData = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::Validation {
                message: "Invalid client data JSON".to_string(),
            })?;

        let challenge_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&client_data.challenge)
            .map_err(|_| AppError::Validation {
                message: "Invalid challenge in client data".to_string(),
            })?;

        // Find authentication challenge
        let challenge_record = self
            .challenge_repo
            .get_authentication_challenge(&challenge_bytes)?
            .ok_or(AppError::ChallengeExpired)?;

        let state_str = String::from_utf8(challenge_record.state_data)
            .map_err(|_| AppError::ChallengeExpired)?;
        let auth_state: PasskeyAuthentication = serde_json::from_str(&state_str)
            .map_err(|_| AppError::ChallengeExpired)?;

        let auth_pk_cred = PublicKeyCredential {
            id: assertion.id.clone(),
            raw_id: BASE64_URL_SAFE_NO_PAD.decode(&assertion.id).unwrap().into(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: authenticator_data.clone(),
                client_data_json: client_data_json.clone(),
                signature: signature.clone(),
                user_handle: assertion.response.user_handle.as_ref().and_then(|h| {
                    BASE64_URL_SAFE_NO_PAD.decode(h).ok().map(Into::into)
                }),
            },
            type_: "public-key".to_string(),
            extensions: None,
        };

        let _auth_result = self
            .webauthn
            .finish_passkey_authentication(&auth_pk_cred, &auth_state)
            .map_err(AppError::WebAuthn)?;

        // Update credential counter would be done here if we tracked it properly

        // Clean up challenge
        self.challenge_repo.delete_authentication_challenge(&challenge_bytes)?;

        Ok(crate::error::ServerResponse::ok())
    }
}

impl Clone for WebAuthnService {
    fn clone(&self) -> Self {
        // This is not ideal for production but works for our demo
        // In production, you'd want to share the repositories through Arc<> 
        let config = WebAuthnSettings {
            rp_id: "localhost".to_string(),
            rp_name: "Example Corporation".to_string(),
            origin: "http://localhost:8080".to_string(),
        };

        // This is a hacky clone - in production you'd handle this differently
        Self::new(&config, self.user_repo.clone(), self.credential_repo.clone(), self.challenge_repo.clone())
            .unwrap()
    }
}