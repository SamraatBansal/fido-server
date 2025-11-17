use crate::{
    db::Database,
    error::{AppError, Result},
    types::*,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::{prelude::*, Webauthn, WebauthnBuilder};
use tracing::{info, debug, error, warn};

#[derive(Clone)]
pub struct WebAuthnService {
    webauthn: Webauthn,
    db: Database,
    rp_id: String,
    // Store challenge states in memory with proper typed data
    registration_challenges: std::sync::Arc<std::sync::RwLock<HashMap<String, PasskeyRegistration>>>,
    authentication_challenges: std::sync::Arc<std::sync::RwLock<HashMap<String, PasskeyAuthentication>>>,
}

impl WebAuthnService {
    pub fn new(rp_id: &str, origin: &url::Url, rp_name: &str, db: Database) -> Result<Self> {
        let webauthn = WebauthnBuilder::new(rp_id, origin)?
            .rp_name(rp_name)
            .build()?;

        Ok(Self { 
            webauthn, 
            db,
            rp_id: rp_id.to_string(),
            registration_challenges: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            authentication_challenges: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
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

        // Create user ID from the stored user handle
        let user_uuid = Uuid::from_slice(&user.user_handle)
            .map_err(|e| AppError::Internal(format!("Invalid user handle UUID: {}", e)))?;

        // Start registration with proper webauthn-rs integration
        let (creation_challenge_response, passkey_registration) = self
            .webauthn
            .start_passkey_registration(
                user_uuid,
                &user.username,
                &user.display_name,
                Some(exclude_credentials),
            )?;

        // Store challenge state with actual webauthn state
        let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(creation_challenge_response.public_key.challenge.as_ref());
        
        debug!("Storing registration challenge for user: {} with challenge: {}", user.username, &challenge_b64[..8]);

        {
            let mut store = self.registration_challenges.write().unwrap();
            store.insert(challenge_b64.clone(), passkey_registration);
        }

        // Set expiry in 30 seconds and schedule cleanup
        let rp_challenges = self.registration_challenges.clone();
        let challenge_key = challenge_b64.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let mut store = rp_challenges.write().unwrap();
            store.remove(&challenge_key);
        });

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
                name: user.username,
                display_name: user.display_name,
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
            timeout: creation_challenge_response.public_key.timeout.unwrap_or(10000),
            exclude_credentials: exclude_credentials_json,
            authenticator_selection,
            attestation,
        })
    }

    pub async fn finish_registration(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Convert ServerPublicKeyCredential to RegisterPublicKeyCredential
        let client_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.response.client_data_json)
            .map_err(|_| AppError::AttestationVerificationFailed)?;
        let attestation_object_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.response.attestation_object)
            .map_err(|_| AppError::AttestationVerificationFailed)?;
        
        // Parse client data to get challenge
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::AttestationVerificationFailed)?;

        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::InvalidInput("Missing challenge in clientDataJSON".to_string()))?;

        debug!("Finishing registration with challenge: {}", &challenge_b64[..8]);

        // Get and remove challenge state (single use)
        let passkey_registration = {
            let mut store = self.registration_challenges.write().unwrap();
            store.remove(challenge_b64)
        }.ok_or(AppError::ChallengeNotFound)?;

        // Create RegisterPublicKeyCredential for webauthn-rs
        let reg_credential = RegisterPublicKeyCredential {
            id: credential.id.clone(),
            raw_id: BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?
                .into(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: attestation_object_bytes.into(),
                client_data_json: client_data_bytes.into(),
            },
            type_: "public-key".to_string(),
        };

        // Complete registration with webauthn-rs verification
        let passkey = self.webauthn
            .finish_passkey_registration(&reg_credential, &passkey_registration)
            .map_err(|e| {
                error!("WebAuthn registration verification failed: {}", e);
                AppError::AttestationVerificationFailed
            })?;

        info!("Successfully verified registration for credential: {}", credential.id);

        // Store credential in database
        let new_credential = NewCredential {
            user_id: passkey.user_uuid(),
            credential_id: passkey.cred_id().to_vec(),
            public_key: serde_json::to_vec(&passkey.cred())
                .map_err(|e| AppError::Internal(format!("Failed to serialize credential: {}", e)))?,
            sign_count: passkey.counter() as i64,
            backup_eligible: passkey.backup_eligible(),
            backup_state: passkey.backup_state(),
            attestation_format: Some("none".to_string()),
        };

        self.db.create_credential(new_credential).await
            .map_err(|e| {
                error!("Failed to store credential in database: {}", e);
                e
            })?;

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
        let stored_credentials = self.db.get_credentials_by_user_id(user.id).await?;

        if stored_credentials.is_empty() {
            return Err(AppError::CredentialNotFound);
        }

        // Convert stored credentials to webauthn-rs Passkey format
        let mut passkeys = Vec::new();
        for stored_cred in &stored_credentials {
            match serde_json::from_slice::<Credential>(&stored_cred.public_key) {
                Ok(cred) => {
                    // Create passkey from stored credential
                    let passkey = Passkey::new(
                        stored_cred.credential_id.clone().into(),
                        cred,
                        stored_cred.user_id,
                        stored_cred.sign_count as u32,
                    );
                    passkeys.push(passkey);
                },
                Err(e) => {
                    warn!("Failed to deserialize stored credential {}: {}", 
                          BASE64_URL_SAFE_NO_PAD.encode(&stored_cred.credential_id), e);
                    continue;
                }
            }
        }

        if passkeys.is_empty() {
            return Err(AppError::CredentialNotFound);
        }

        // Convert UserVerification
        let user_verification_policy = match user_verification.as_deref() {
            Some("required") => UserVerificationPolicy::Required,
            Some("preferred") => UserVerificationPolicy::Preferred, 
            Some("discouraged") => UserVerificationPolicy::Discouraged,
            _ => UserVerificationPolicy::Preferred,
        };

        // Start authentication with webauthn-rs
        let (request_challenge_response, passkey_authentication) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| {
                error!("Failed to start passkey authentication: {}", e);
                AppError::WebAuthn(e.to_string())
            })?;

        let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(request_challenge_response.public_key.challenge.as_ref());
        
        debug!("Storing authentication challenge for user: {} with challenge: {}", username, &challenge_b64[..8]);

        {
            let mut store = self.authentication_challenges.write().unwrap();
            store.insert(challenge_b64.clone(), passkey_authentication);
        }

        // Set expiry and schedule cleanup
        let auth_challenges = self.authentication_challenges.clone();
        let challenge_key = challenge_b64.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            let mut store = auth_challenges.write().unwrap();
            store.remove(&challenge_key);
        });

        let allow_credentials: Vec<AllowCredential> = request_challenge_response
            .public_key
            .allow_credentials
            .unwrap_or_default()
            .iter()
            .map(|c| AllowCredential {
                type_: "public-key".to_string(),
                id: BASE64_URL_SAFE_NO_PAD.encode(c.id.as_ref()),
            })
            .collect();

        Ok(ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge: challenge_b64,
            timeout: request_challenge_response.public_key.timeout.unwrap_or(20000),
            rp_id: self.rp_id.clone(),
            allow_credentials,
            user_verification,
        })
    }

    pub async fn finish_authentication(
        &self,
        credential: &ServerPublicKeyCredentialAssertion,
    ) -> Result<ServerResponse> {
        // Convert ServerPublicKeyCredentialAssertion to PublicKeyCredential
        let client_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.response.client_data_json)
            .map_err(|_| AppError::AssertionVerificationFailed)?;
        let authenticator_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.response.authenticator_data)
            .map_err(|_| AppError::AssertionVerificationFailed)?;
        let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.response.signature)
            .map_err(|_| AppError::AssertionVerificationFailed)?;

        // Parse client data to get challenge
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::AssertionVerificationFailed)?;

        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::InvalidInput("Missing challenge in clientDataJSON".to_string()))?;

        debug!("Finishing authentication with challenge: {}", &challenge_b64[..8]);

        // Get and remove challenge state (single use)
        let passkey_authentication = {
            let mut store = self.authentication_challenges.write().unwrap();
            store.remove(challenge_b64)
        }.ok_or(AppError::ChallengeNotFound)?;

        // Create PublicKeyCredential for webauthn-rs
        let user_handle = credential.response.user_handle
            .as_ref()
            .and_then(|uh| if uh.is_empty() { None } else { Some(BASE64_URL_SAFE_NO_PAD.decode(uh).ok()?) })
            .unwrap_or_default();

        let auth_credential = PublicKeyCredential {
            id: credential.id.clone(),
            raw_id: BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?
                .into(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: authenticator_data_bytes.into(),
                client_data_json: client_data_bytes.into(),
                signature: signature_bytes.into(),
                user_handle: if user_handle.is_empty() { None } else { Some(user_handle.into()) },
            },
            type_: "public-key".to_string(),
        };

        // Complete authentication with webauthn-rs verification
        let auth_result = self.webauthn
            .finish_passkey_authentication(&auth_credential, &passkey_authentication)
            .map_err(|e| {
                error!("WebAuthn authentication verification failed: {}", e);
                AppError::AssertionVerificationFailed
            })?;

        info!("Successfully verified authentication for credential: {}", credential.id);

        // Update credential counter in database
        let credential_id_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?;
        self.db
            .update_credential_sign_count(&credential_id_bytes, auth_result.counter() as i64)
            .await
            .map_err(|e| {
                error!("Failed to update credential counter: {}", e);
                e
            })?;

        Ok(ServerResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
        })
    }
}