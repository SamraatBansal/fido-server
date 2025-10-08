//! WebAuthn service for FIDO2 operations

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::db::{models::*, DbPool};
use crate::error::{AppError, Result};
use crate::schema::webauthn::*;

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

        // Get existing credentials for exclusion
        let existing_creds: Vec<Credential> = crate::schema::credentials::table
            .filter(crate::schema::credentials::user_id.eq(user.id))
            .filter(crate::schema::credentials::is_active.eq(true))
            .load(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to load credentials: {}", e)))?;

        let exclude_credentials: Option<Vec<CredentialID>> = if existing_creds.is_empty() {
            None
        } else {
            Some(existing_creds.iter().map(|c| CredentialID::from(c.credential_id.clone())).collect())
        };

        // Generate challenge
        let (ccr, reg_state) = self.webauthn
            .start_passkey_registration(
                user.id,
                &user.username,
                &user.display_name,
                exclude_credentials,
            )
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start registration: {}", e)))?;

        // Store challenge
        let challenge = BASE64.encode(reg_state.challenge());
        let expires_at = Utc::now() + Duration::minutes(5);

        let new_challenge = NewChallenge {
            challenge_base64: challenge.clone(),
            user_id: Some(user.id),
            challenge_type: "registration".to_string(),
            expires_at,
        };

        diesel::insert_into(crate::schema::challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to store challenge: {}", e)))?;

        // Convert to JSON for response
        let rp_json = serde_json::json!({
            "id": ccr.public_key.rp.id,
            "name": ccr.public_key.rp.name
        });

        let pub_key_cred_params: Vec<serde_json::Value> = ccr.public_key.pub_key_cred_params
            .into_iter()
            .map(|param| serde_json::json!({
                "type": param.type_,
                "alg": param.alg
            }))
            .collect();

        let exclude_credentials_response: Vec<serde_json::Value> = existing_creds
            .into_iter()
            .map(|cred| serde_json::json!({
                "id": BASE64.encode(&cred.credential_id),
                "type": "public-key",
                "transports": []
            }))
            .collect();

        Ok(RegistrationOptionsResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            rp: rp_json,
            user: ServerPublicKeyCredentialUserEntity {
                id: BASE64.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            challenge,
            pub_key_cred_params,
            timeout: ccr.public_key.timeout,
            exclude_credentials: exclude_credentials_response,
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
        let user = crate::schema::users::table
            .filter(crate::schema::users::id.eq(challenge.user_id.ok_or_else(|| AppError::InvalidChallenge("No user ID in challenge".to_string()))?))
            .first::<User>(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to find user: {}", e)))?;

        // Extract credential data from response
        let credential_id = response.raw_id.to_vec();
        let public_key = response.response.attestation_object.to_vec();

        // Store credential
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id,
            public_key,
            attestation_format: Some("none".to_string()),
            aaguid: Some(Uuid::new_v4()),
            sign_count: 0,
            backup_eligible: false,
            backup_state: false,
            transports: Some("[]".to_string()),
            is_active: true,
        };

        diesel::insert_into(crate::schema::credentials::table)
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
        let user = crate::schema::users::table
            .filter(crate::schema::users::username.eq(&request.username))
            .filter(crate::schema::users::is_active.eq(true))
            .first::<User>(&mut conn)
            .map_err(|_| AppError::NotFound(format!("User '{}' not found", request.username)))?;

        // Get user credentials
        let user_credentials: Vec<Credential> = crate::schema::credentials::table
            .filter(crate::schema::credentials::user_id.eq(user.id))
            .filter(crate::schema::credentials::is_active.eq(true))
            .load(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to load credentials: {}", e)))?;

        if user_credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Convert credentials to Passkey format (simplified)
        let passkeys: Vec<Passkey> = user_credentials
            .into_iter()
            .map(|cred| Passkey {
                cred_id: CredentialID::from(cred.credential_id),
                cred: None, // Simplified
            })
            .collect();

        // Generate challenge
        let (acr, auth_state) = self.webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start authentication: {}", e)))?;

        // Store challenge
        let challenge = BASE64.encode(auth_state.challenge());
        let expires_at = Utc::now() + Duration::minutes(5);

        let new_challenge = NewChallenge {
            challenge_base64: challenge.clone(),
            user_id: Some(user.id),
            challenge_type: "authentication".to_string(),
            expires_at,
        };

        diesel::insert_into(crate::schema::challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to store challenge: {}", e)))?;

        // Convert credentials for response
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = passkeys
            .iter()
            .map(|pk| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: BASE64.encode(pk.cred_id.as_ref()),
                transports: vec![],
            })
            .collect();

        Ok(AuthenticationOptionsResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge,
            timeout: acr.public_key.timeout,
            rp_id: acr.public_key.rp_id,
            allow_credentials,
            user_verification: request.user_verification.unwrap_or_else(|| "preferred".to_string()),
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

        let credential = crate::schema::credentials::table
            .filter(crate::schema::credentials::credential_id.eq(&credential_id))
            .filter(crate::schema::credentials::is_active.eq(true))
            .first::<Credential>(&mut conn)
            .map_err(|_| AppError::NotFound("Credential not found".to_string()))?;

        // Update credential usage
        diesel::update(crate::schema::credentials::table.filter(crate::schema::credentials::id.eq(credential.id)))
            .set((
                crate::schema::credentials::sign_count.eq(credential.sign_count + 1),
                crate::schema::credentials::last_used_at.eq(Utc::now()),
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
        crate::schema::users::table
            .filter(crate::schema::users::username.eq(username))
            .first::<User>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to query user: {}", e)))?
            .ok_or_else(|| {
                let new_user = NewUser {
                    username: username.to_string(),
                    display_name: display_name.to_string(),
                    is_active: true,
                };

                diesel::insert_into(crate::schema::users::table)
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

        let client_data: serde_json::Value = serde_json::from_str(client_data_json)
            .map_err(|e| AppError::BadRequest(format!("Invalid client data JSON: {}", e)))?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing challenge in client data".to_string()))?;

        let db_challenge = crate::schema::challenges::table
            .filter(crate::schema::challenges::challenge_base64.eq(challenge))
            .filter(crate::schema::challenges::challenge_type.eq(challenge_type))
            .filter(crate::schema::challenges::used_at.is_null())
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
        diesel::update(crate::schema::challenges::table.filter(crate::schema::challenges::id.eq(challenge_id)))
            .set(crate::schema::challenges::used_at.eq(Utc::now()))
            .execute(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to mark challenge as used: {}", e)))?;
        Ok(())
    }
}