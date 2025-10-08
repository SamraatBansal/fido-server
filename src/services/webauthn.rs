//! WebAuthn service for FIDO2 operations

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::db::{models::*, DbPool};
use crate::error::{AppError, Result};
use crate::schema::*;

/// WebAuthn service handling FIDO2 operations
pub struct WebAuthnService {
    webauthn: Webauthn,
    db_pool: DbPool,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new(rp_id: &str, rp_name: &str, origin: &str, db_pool: DbPool) -> Result<Self> {
        let rp = RelyingParty {
            id: rp_id.to_string(),
            name: rp_name.to_string(),
            origin: Url::parse(origin)
                .map_err(|e| AppError::WebAuthnError(format!("Invalid origin URL: {}", e)))?,
        };

        let webauthn = Webauthn::new(rp);

        Ok(Self { webauthn, db_pool })
    }

    /// Start registration process
    pub async fn start_registration(&self, request: RegistrationOptionsRequest) -> Result<RegistrationOptionsResponse> {
        let mut conn = self.db_pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get DB connection: {}", e)))?;

        // Check if user exists, create if not
        let user = self.get_or_create_user(&mut conn, &request.username, &request.display_name)?;

        // Generate challenge
        let (ccr, reg_state) = self.webauthn
            .start_registration(&User {
                id: user.id.as_bytes().to_vec(),
                name: user.username.clone(),
                display_name: user.display_name.clone(),
            })
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start registration: {}", e)))?;

        // Store challenge
        let challenge = BASE64.encode(&reg_state.challenge());
        let expires_at = Utc::now() + Duration::minutes(5);

        let new_challenge = NewChallenge {
            challenge_base64: challenge.clone(),
            user_id: Some(user.id),
            challenge_type: "registration".to_string(),
            expires_at,
        };

        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to store challenge: {}", e)))?;

        // Get existing credentials for exclusion
        let existing_creds: Vec<Credential> = credentials::table
            .filter(credentials::user_id.eq(user.id))
            .filter(credentials::is_active.eq(true))
            .load(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to load credentials: {}", e)))?;

        let exclude_credentials: Vec<PublicKeyCredentialDescriptor> = existing_creds
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                id: cred.credential_id,
                transports: self.deserialize_transports(&cred.transports),
            })
            .collect();

        Ok(RegistrationOptionsResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            rp: PublicKeyCredentialRpEntity {
                id: ccr.rp.id,
                name: ccr.rp.name,
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: BASE64.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            challenge,
            pub_key_cred_params: ccr.pub_key_cred_params,
            timeout: ccr.timeout,
            exclude_credentials,
            authenticator_selection: request.authenticator_selection,
            attestation: request.attestation,
            extensions: request.extensions,
        })
    }

    /// Finish registration process
    pub async fn finish_registration(&self, response: RegisterPublicKeyCredential) -> Result<ServerResponse> {
        let mut conn = self.db_pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get DB connection: {}", e)))?;

        // Get and validate challenge
        let challenge = self.get_and_validate_challenge(&mut conn, &response.response, "registration")?;

        // Find user
        let user = users::table
            .filter(users::id.eq(challenge.user_id.ok_or_else(|| AppError::InvalidChallenge("No user ID in challenge".to_string()))?))
            .first::<User>(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to find user: {}", e)))?;

        // Convert response for webauthn-rs
        let reg_credential = self.convert_registration_response(response)?;

        // Complete registration
        let auth_result = self.webauthn
            .finish_registration(&reg_credential)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to finish registration: {}", e)))?;

        // Store credential
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id: auth_result.cred_id.clone(),
            public_key: auth_result.public_key,
            attestation_format: Some(auth_result.attestation_format.to_string()),
            aaguid: Some(Uuid::from_slice(&auth_result.aaguid)
                .map_err(|e| AppError::InternalError(format!("Invalid AAGUID: {}", e)))?),
            sign_count: auth_result.counter as i64,
            backup_eligible: auth_result.backup_eligible,
            backup_state: auth_result.backup_state,
            transports: Some(self.serialize_transports(&auth_result.transports)),
            is_active: true,
        };

        diesel::insert_into(credentials::table)
            .values(&new_credential)
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to store credential: {}", e)))?;

        // Mark challenge as used
        self.mark_challenge_used(&mut conn, challenge.id)?;

        Ok(ServerResponse {
            status: "ok".to_string(),
            error_message: String::new(),
        })
    }

    /// Start authentication process
    pub async fn start_authentication(&self, request: AuthenticationOptionsRequest) -> Result<AuthenticationOptionsResponse> {
        let mut conn = self.db_pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get DB connection: {}", e)))?;

        // Find user
        let user = users::table
            .filter(users::username.eq(&request.username))
            .filter(users::is_active.eq(true))
            .first::<User>(&mut conn)
            .map_err(|_| AppError::NotFound(format!("User '{}' not found", request.username)))?;

        // Get user credentials
        let user_credentials: Vec<Credential> = credentials::table
            .filter(credentials::user_id.eq(user.id))
            .filter(credentials::is_active.eq(true))
            .load(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to load credentials: {}", e)))?;

        if user_credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Generate challenge
        let (acr, auth_state) = self.webauthn
            .start_authentication()
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start authentication: {}", e)))?;

        // Store challenge
        let challenge = BASE64.encode(&auth_state.challenge());
        let expires_at = Utc::now() + Duration::minutes(5);

        let new_challenge = NewChallenge {
            challenge_base64: challenge.clone(),
            user_id: Some(user.id),
            challenge_type: "authentication".to_string(),
            expires_at,
        };

        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to store challenge: {}", e)))?;

        // Convert credentials for response
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = user_credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: BASE64.encode(&cred.credential_id),
                transports: self.deserialize_transports(&cred.transports),
            })
            .collect();

        Ok(AuthenticationOptionsResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge,
            timeout: acr.timeout,
            rp_id: acr.rp_id,
            allow_credentials,
            user_verification: request.user_verification.unwrap_or(UserVerificationRequirement::Preferred),
            extensions: request.extensions,
        })
    }

    /// Finish authentication process
    pub async fn finish_authentication(&self, response: PublicKeyCredential) -> Result<ServerResponse> {
        let mut conn = self.db_pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get DB connection: {}", e)))?;

        // Get and validate challenge
        let challenge = self.get_and_validate_challenge(&mut conn, &response.response, "authentication")?;

        // Find credential by ID
        let credential_id = BASE64.decode(&response.id)
            .map_err(|e| AppError::BadRequest(format!("Invalid credential ID: {}", e)))?;

        let credential = credentials::table
            .filter(credentials::credential_id.eq(&credential_id))
            .filter(credentials::is_active.eq(true))
            .first::<Credential>(&mut conn)
            .map_err(|_| AppError::NotFound("Credential not found".to_string()))?;

        // Convert response for webauthn-rs
        let auth_credential = self.convert_authentication_response(response, &credential)?;

        // Complete authentication
        let auth_result = self.webauthn
            .finish_authentication(&auth_credential)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to finish authentication: {}", e)))?;

        // Update credential usage
        diesel::update(credentials::table.filter(credentials::id.eq(credential.id)))
            .set((
                credentials::sign_count.eq(auth_result.counter as i64),
                credentials::last_used_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to update credential: {}", e)))?;

        // Mark challenge as used
        self.mark_challenge_used(&mut conn, challenge.id)?;

        Ok(ServerResponse {
            status: "ok".to_string(),
            error_message: String::new(),
        })
    }

    /// Helper methods
    fn get_or_create_user(&self, conn: &mut PgConnection, username: &str, display_name: &str) -> Result<User> {
        users::table
            .filter(users::username.eq(username))
            .first::<User>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to query user: {}", e)))?
            .ok_or_else(|| {
                let new_user = NewUser {
                    username: username.to_string(),
                    display_name: display_name.to_string(),
                    is_active: true,
                };

                diesel::insert_into(users::table)
                    .values(&new_user)
                    .get_result::<User>(conn)
                    .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {}", e)))
            })?
            .map_err(Into::into)
    }

    fn get_and_validate_challenge(&self, conn: &mut PgConnection, response: &AuthenticatorResponse, challenge_type: &str) -> Result<Challenge> {
        let client_data_json = match response {
            AuthenticatorResponse::Attestation(att) => &att.client_data_json,
            AuthenticatorResponse::Assertion(assert) => &assert.client_data_json,
        };

        let client_data: Value = serde_json::from_str(client_data_json)
            .map_err(|e| AppError::BadRequest(format!("Invalid client data JSON: {}", e)))?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing challenge in client data".to_string()))?;

        let db_challenge = challenges::table
            .filter(challenges::challenge_base64.eq(challenge))
            .filter(challenges::challenge_type.eq(challenge_type))
            .filter(challenges::used_at.is_null())
            .first::<Challenge>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to query challenge: {}", e)))?
            .ok_or_else(|| AppError::InvalidChallenge("Challenge not found or already used".to_string()))?;

        if db_challenge.expires_at < Utc::now() {
            return Err(AppError::ChallengeExpired("Challenge has expired".to_string()));
        }

        Ok(db_challenge)
    }

    fn mark_challenge_used(&self, conn: &mut PgConnection, challenge_id: Uuid) -> Result<()> {
        diesel::update(challenges::table.filter(challenges::id.eq(challenge_id)))
            .set(challenges::used_at.eq(Utc::now()))
            .execute(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to mark challenge as used: {}", e)))?;
        Ok(())
    }

    fn convert_registration_response(&self, response: RegisterPublicKeyCredential) -> Result<RegisterPublicKeyCredential> {
        Ok(response)
    }

    fn convert_authentication_response(&self, response: PublicKeyCredential, _credential: &Credential) -> Result<PublicKeyCredential> {
        Ok(response)
    }

    fn serialize_transports(&self, transports: &[AuthenticatorTransport]) -> Option<Value> {
        if transports.is_empty() {
            return None;
        }

        let transport_strings: Vec<String> = transports
            .iter()
            .map(|t| match t {
                AuthenticatorTransport::Ble => "ble".to_string(),
                AuthenticatorTransport::Internal => "internal".to_string(),
                AuthenticatorTransport::Nfc => "nfc".to_string(),
                AuthenticatorTransport::SmartCard => "smart-card".to_string(),
                AuthenticatorTransport::Usb => "usb".to_string(),
            })
            .collect();

        Some(serde_json::to_value(transport_strings).ok()?)
    }

    fn deserialize_transports(&self, transports: &Option<Value>) -> Vec<AuthenticatorTransport> {
        transports
            .as_ref()
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| match s {
                        "ble" => Some(AuthenticatorTransport::Ble),
                        "internal" => Some(AuthenticatorTransport::Internal),
                        "nfc" => Some(AuthenticatorTransport::Nfc),
                        "smart-card" => Some(AuthenticatorTransport::SmartCard),
                        "usb" => Some(AuthenticatorTransport::Usb),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}