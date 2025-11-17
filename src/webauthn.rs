use crate::{
    db::Database,
    error::{AppError, Result},
    types::*,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use std::collections::BTreeMap;
use uuid::Uuid;
use webauthn_rs::{
    prelude::*,
    proto::{
        AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw,
        CollectedClientData, PublicKeyCredentialRaw,
    },
    Webauthn, WebauthnBuilder,
};

#[derive(Clone)]
pub struct WebAuthnService {
    webauthn: Webauthn,
    db: Database,
}

impl WebAuthnService {
    pub fn new(rp_id: &str, origin: &url::Url, rp_name: &str, db: Database) -> Result<Self> {
        let webauthn = WebauthnBuilder::new(rp_id, origin)?
            .rp_name(rp_name)
            .build()?;

        Ok(Self { webauthn, db })
    }

    pub async fn start_registration(
        &self,
        username: &str,
        display_name: &str,
        authenticator_selection: Option<serde_json::Value>,
        attestation: Option<String>,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Check if user already exists
        let user = if let Some(existing_user) = self.db.get_user_by_username(username).await? {
            existing_user
        } else {
            // Create new user
            let user_handle = Uuid::new_v4().as_bytes().to_vec();
            let new_user = NewUser {
                username: username.to_string(),
                display_name: display_name.to_string(),
                user_handle,
            };
            self.db.create_user(new_user).await?
        };

        // Get existing credentials to exclude
        let existing_credentials = self.db.get_credentials_by_user_id(user.id).await?;
        let exclude_credentials: Vec<CredentialID> = existing_credentials
            .iter()
            .map(|c| CredentialID::from(c.credential_id.clone()))
            .collect();

        // Set attestation conveyance preference
        let attestation_pref = match attestation.as_deref() {
            Some("direct") => AttestationConveyancePreference::Direct,
            Some("indirect") => AttestationConveyancePreference::Indirect,
            _ => AttestationConveyancePreference::None,
        };

        // Parse authenticator selection
        let mut auth_sel_builder = AuthenticatorSelectionCriteriaBuilder::default();

        if let Some(auth_sel) = &authenticator_selection {
            if let Some(require_resident_key) = auth_sel.get("requireResidentKey") {
                if let Some(value) = require_resident_key.as_bool() {
                    auth_sel_builder.require_resident_key(value);
                }
            }

            if let Some(user_verification) = auth_sel.get("userVerification") {
                if let Some(value) = user_verification.as_str() {
                    match value {
                        "required" => auth_sel_builder.user_verification(UserVerificationPolicy::Required),
                        "preferred" => auth_sel_builder.user_verification(UserVerificationPolicy::Preferred),
                        "discouraged" => auth_sel_builder.user_verification(UserVerificationPolicy::Discouraged_DO_NOT_USE),
                        _ => {}
                    }
                }
            }

            if let Some(authenticator_attachment) = auth_sel.get("authenticatorAttachment") {
                if let Some(value) = authenticator_attachment.as_str() {
                    match value {
                        "platform" => auth_sel_builder.authenticator_attachment(AuthenticatorAttachment::Platform),
                        "cross-platform" => auth_sel_builder.authenticator_attachment(AuthenticatorAttachment::CrossPlatform),
                        _ => {}
                    }
                }
            }
        }

        let auth_sel = auth_sel_builder.build().map_err(|e| {
            AppError::Internal(format!("Failed to build authenticator selection criteria: {}", e))
        })?;

        // Start registration
        let user_uuid = Uuid::from_slice(&user.user_handle)
            .map_err(|e| AppError::Internal(format!("Invalid user handle UUID: {}", e)))?;

        let (creation_challenge_response, passkey_registration) = self
            .webauthn
            .start_passkey_registration(
                user_uuid,
                &user.username,
                &user.display_name,
                Some(exclude_credentials),
                Some(auth_sel),
                Some(attestation_pref),
            )?;

        // Store challenge state
        let challenge_bytes = creation_challenge_response.public_key.challenge.as_ref().to_vec();
        let state_data = serde_json::to_vec(&passkey_registration)
            .map_err(|e| AppError::Internal(format!("Failed to serialize challenge state: {}", e)))?;

        let registration_challenge = NewRegistrationChallenge {
            user_id: user.id,
            challenge: challenge_bytes.clone(),
            state_data,
            expires_at: Utc::now() + Duration::seconds(30), // 30 second timeout
        };

        self.db
            .store_registration_challenge(registration_challenge)
            .await?;

        // Convert to conformance test format
        let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let user_id_b64 = BASE64_URL_SAFE_NO_PAD.encode(&user.user_handle);

        let exclude_credentials_json: Vec<serde_json::Value> = existing_credentials
            .iter()
            .map(|c| {
                serde_json::json!({
                    "type": "public-key",
                    "id": BASE64_URL_SAFE_NO_PAD.encode(&c.credential_id)
                })
            })
            .collect();

        Ok(ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: RpEntity {
                name: creation_challenge_response.public_key.rp.name,
            },
            user: UserEntity {
                id: user_id_b64,
                name: user.username.clone(),
                display_name: user.display_name.clone(),
            },
            challenge: challenge_b64,
            pub_key_cred_params: creation_challenge_response
                .public_key
                .pub_key_cred_params
                .iter()
                .map(|param| PubKeyCredParam {
                    type_: "public-key".to_string(),
                    alg: param.alg as i32,
                })
                .collect(),
            timeout: creation_challenge_response.public_key.timeout,
            exclude_credentials: exclude_credentials_json,
            authenticator_selection,
            attestation,
        })
    }

    pub async fn finish_registration(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Decode client data
        let client_data_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&credential.response.client_data_json)?;
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)?;

        // Extract challenge
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::InvalidInput("Missing challenge in clientDataJSON".to_string()))?;

        let challenge_bytes = BASE64_URL_SAFE_NO_PAD.decode(challenge_b64)?;

        // Get registration challenge
        let reg_challenge = self
            .db
            .get_registration_challenge(&challenge_bytes)
            .await?
            .ok_or(AppError::ChallengeNotFound)?;

        // Deserialize registration state
        let passkey_registration: PasskeyRegistration =
            serde_json::from_slice(&reg_challenge.state_data)
                .map_err(|e| AppError::Internal(format!("Failed to deserialize challenge state: {}", e)))?;

        // Create raw credential for webauthn-rs
        let raw_credential = PublicKeyCredentialRaw {
            id: BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?,
            raw_id: BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: BASE64_URL_SAFE_NO_PAD
                    .decode(&credential.response.attestation_object)?,
                client_data_json: client_data_bytes,
            },
            type_: credential.type_.clone(),
            extensions: credential.get_client_extension_results.clone().unwrap_or_default(),
        };

        // Finish registration with webauthn-rs
        let passkey = self
            .webauthn
            .finish_passkey_registration(&raw_credential, &passkey_registration)?;

        // Store credential in database
        let new_credential = NewCredential {
            user_id: reg_challenge.user_id,
            credential_id: passkey.cred_id().to_vec(),
            public_key: serde_json::to_vec(&passkey.cred())
                .map_err(|e| AppError::Internal(format!("Failed to serialize public key: {}", e)))?,
            sign_count: passkey.counter() as i64,
            backup_eligible: passkey.backup_eligible(),
            backup_state: passkey.backup_state(),
            attestation_format: None, // webauthn-rs doesn't expose this easily
        };

        self.db.create_credential(new_credential).await?;

        // Clean up challenge
        self.db.delete_registration_challenge(&challenge_bytes).await?;

        Ok(ServerResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
        })
    }

    pub async fn start_authentication(
        &self,
        username: &str,
        user_verification: Option<String>,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Get user
        let user = self
            .db
            .get_user_by_username(username)
            .await?
            .ok_or(AppError::UserNotFound)?;

        // Get user credentials
        let credentials = self.db.get_credentials_by_user_id(user.id).await?;

        if credentials.is_empty() {
            return Err(AppError::CredentialNotFound);
        }

        let mut passkeys = Vec::new();
        for cred in &credentials {
            let passkey: Passkey = serde_json::from_slice(&cred.public_key)
                .map_err(|e| AppError::Internal(format!("Failed to deserialize passkey: {}", e)))?;
            passkeys.push(passkey);
        }

        // Set user verification policy
        let user_verification_policy = match user_verification.as_deref() {
            Some("required") => UserVerificationPolicy::Required,
            Some("discouraged") => UserVerificationPolicy::Discouraged_DO_NOT_USE,
            _ => UserVerificationPolicy::Preferred,
        };

        // Start authentication
        let (request_challenge_response, passkey_authentication) = self
            .webauthn
            .start_passkey_authentication(&passkeys, Some(user_verification_policy))?;

        // Store challenge state
        let challenge_bytes = request_challenge_response.public_key.challenge.as_ref().to_vec();
        let state_data = serde_json::to_vec(&passkey_authentication)
            .map_err(|e| AppError::Internal(format!("Failed to serialize challenge state: {}", e)))?;

        let authentication_challenge = NewAuthenticationChallenge {
            user_id: Some(user.id),
            challenge: challenge_bytes.clone(),
            state_data,
            expires_at: Utc::now() + Duration::seconds(60), // 60 second timeout
        };

        self.db
            .store_authentication_challenge(authentication_challenge)
            .await?;

        // Convert to conformance test format
        let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(&challenge_bytes);

        let allow_credentials: Vec<AllowCredential> = credentials
            .iter()
            .map(|c| AllowCredential {
                type_: "public-key".to_string(),
                id: BASE64_URL_SAFE_NO_PAD.encode(&c.credential_id),
            })
            .collect();

        Ok(ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge: challenge_b64,
            timeout: request_challenge_response.public_key.timeout,
            rp_id: request_challenge_response.public_key.rp_id,
            allow_credentials,
            user_verification,
        })
    }

    pub async fn finish_authentication(
        &self,
        credential: &ServerPublicKeyCredentialAssertion,
    ) -> Result<ServerResponse> {
        // Decode client data
        let client_data_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&credential.response.client_data_json)?;
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)?;

        // Extract challenge
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::InvalidInput("Missing challenge in clientDataJSON".to_string()))?;

        let challenge_bytes = BASE64_URL_SAFE_NO_PAD.decode(challenge_b64)?;

        // Get authentication challenge
        let auth_challenge = self
            .db
            .get_authentication_challenge(&challenge_bytes)
            .await?
            .ok_or(AppError::ChallengeNotFound)?;

        // Deserialize authentication state
        let passkey_authentication: PasskeyAuthentication =
            serde_json::from_slice(&auth_challenge.state_data)
                .map_err(|e| AppError::Internal(format!("Failed to deserialize challenge state: {}", e)))?;

        // Create raw credential for webauthn-rs
        let raw_credential = PublicKeyCredentialRaw {
            id: BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?,
            raw_id: BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: BASE64_URL_SAFE_NO_PAD
                    .decode(&credential.response.authenticator_data)?,
                client_data_json: client_data_bytes,
                signature: BASE64_URL_SAFE_NO_PAD.decode(&credential.response.signature)?,
                user_handle: credential
                    .response
                    .user_handle
                    .as_ref()
                    .map(|h| BASE64_URL_SAFE_NO_PAD.decode(h))
                    .transpose()?,
            },
            type_: credential.type_.clone(),
            extensions: credential.get_client_extension_results.clone().unwrap_or_default(),
        };

        // Finish authentication with webauthn-rs
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(&raw_credential, &passkey_authentication)?;

        // Update sign count
        self.db
            .update_credential_sign_count(
                &BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?,
                auth_result.counter() as i64,
            )
            .await?;

        // Clean up challenge
        self.db.delete_authentication_challenge(&challenge_bytes).await?;

        Ok(ServerResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
        })
    }
}