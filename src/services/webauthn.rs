//! WebAuthn service for FIDO2 operations (simplified version)

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use uuid::Uuid;

use crate::db::{models::*, DbPool};
use crate::error::{AppError, Result};
use crate::schema::webauthn::*;


/// WebAuthn service handling FIDO2 operations
pub struct WebAuthnService {
    db_pool: DbPool,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new(_rp_id: &str, _rp_name: &str, _origin: &str, db_pool: DbPool) -> Result<Self> {
        Ok(Self { db_pool })
    }

    /// Start registration process
    pub async fn start_registration(&self, request: RegistrationOptionsRequest) -> Result<RegistrationOptionsResponse> {
        let mut conn = self.db_pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get DB connection: {}", e)))?;

        // Check if user exists, create if not
        let user = self.get_or_create_user(&mut conn, &request.username, &request.display_name)?;

        // Generate a simple challenge
        let challenge = BASE64.encode(Uuid::new_v4().as_bytes());
        let expires_at = Utc::now() + Duration::minutes(5);

        // Store challenge
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

        // Create response
        let rp_json = serde_json::json!({
            "id": "localhost",
            "name": "FIDO Server"
        });

        let pub_key_cred_params = vec![
            serde_json::json!({"type": "public-key", "alg": -7}),
            serde_json::json!({"type": "public-key", "alg": -257}),
        ];

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
            timeout: 60000,
            exclude_credentials: vec![],
            authenticator_selection: request.authenticator_selection,
            attestation: request.attestation,
            extensions: request.extensions,
        })
    }

    /// Finish registration process
    pub async fn finish_registration(&self, _response: RegisterPublicKeyCredential) -> Result<ServerResponse> {
        // Simplified implementation
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

        // Generate a simple challenge
        let challenge = BASE64.encode(Uuid::new_v4().as_bytes());
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

        Ok(AuthenticationOptionsResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge,
            timeout: 60000,
            rp_id: "localhost".to_string(),
            allow_credentials: vec![],
            user_verification: request.user_verification.unwrap_or_else(|| "preferred".to_string()),
            extensions: request.extensions,
        })
    }

    /// Finish authentication process
    pub async fn finish_authentication(&self, _response: PublicKeyCredential) -> Result<ServerResponse> {
        // Simplified implementation
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
}