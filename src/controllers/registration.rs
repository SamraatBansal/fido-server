//! Registration controller

use crate::error::{AppError, Result};
use crate::services::{Storage, StoredCredential, StoredUser, WebAuthnService};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Registration request payload
#[derive(Debug, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
}

/// Registration start response
#[derive(Debug, Serialize)]
pub struct RegistrationStartResponse {
    pub challenge: CreationChallengeResponse,
    pub user_id: String,
    pub registration_state: String, // Serialized state
}

/// Registration finish request
#[derive(Debug, Deserialize)]
pub struct RegistrationFinishRequest {
    pub user_id: String,
    pub registration_state: String, // Serialized state
    pub credential: RegisterPublicKeyCredential,
}

/// Registration finish response
#[derive(Debug, Serialize)]
pub struct RegistrationFinishResponse {
    pub success: bool,
    pub credential_id: String,
}

/// Registration controller
pub struct RegistrationController {
    webauthn: Arc<WebAuthnService>,
    storage: Arc<dyn Storage>,
}

impl RegistrationController {
    /// Create a new registration controller
    pub fn new(webauthn: Arc<WebAuthnService>, storage: Arc<dyn Storage>) -> Self {
        Self { webauthn, storage }
    }

    /// Start registration ceremony
    pub async fn start_registration(
        &self,
        req: web::Json<RegistrationStartRequest>,
        _http_req: HttpRequest,
    ) -> Result<HttpResponse> {
        // Validate input
        if req.username.trim().is_empty() {
            return Err(AppError::ValidationError(
                "Username cannot be empty".to_string(),
            ));
        }

        if req.display_name.trim().is_empty() {
            return Err(AppError::ValidationError(
                "Display name cannot be empty".to_string(),
            ));
        }

        // Check if user already exists
        if let Some(_existing_user) = self.storage.get_user_by_username(&req.username).await? {
            return Err(AppError::BadRequest("User already exists".to_string()));
        }

        // Create user ID
        let user_id = Uuid::new_v4().to_string();

        // Get existing credentials for exclusion (none for new user)
        let exclude_credentials = None;

        // Begin registration
        let (challenge, reg_state) = self.webauthn.begin_registration(
            &user_id,
            &req.username,
            &req.display_name,
            exclude_credentials,
        )?;

        // Serialize registration state
        let registration_state = serde_json::to_string(&reg_state).map_err(|e| {
            AppError::InternalError(format!("Failed to serialize registration state: {}", e))
        })?;

        // Create and store the user with empty credentials initially
        let stored_user = StoredUser {
            id: user_id.clone(),
            username: req.username.clone(),
            display_name: req.display_name.clone(),
            credentials: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        self.storage.store_user(&stored_user).await?;

        Ok(HttpResponse::Ok().json(RegistrationStartResponse {
            challenge,
            user_id,
            registration_state,
        }))
    }

    /// Finish registration ceremony
    pub async fn finish_registration(
        &self,
        req: web::Json<RegistrationFinishRequest>,
        _http_req: HttpRequest,
    ) -> Result<HttpResponse> {
        // Deserialize registration state
        let reg_state: PasskeyRegistration = serde_json::from_str(&req.registration_state)
            .map_err(|e| AppError::BadRequest(format!("Invalid registration state: {}", e)))?;

        // Get user from storage
        let mut stored_user = self
            .storage
            .get_user(&req.user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Finish registration
        let passkey = self
            .webauthn
            .finish_registration(&reg_state, &req.credential)?;

        // Store the new credential
        let credential_id = serde_json::to_string(&passkey.cred_id())
            .map_err(|e| {
                AppError::InternalError(format!("Failed to serialize credential ID: {}", e))
            })?
            .trim_matches('"')
            .to_string();
        let credential_data = serde_json::to_string(&passkey).map_err(|e| {
            AppError::InternalError(format!("Failed to serialize credential: {}", e))
        })?;

        let stored_credential = StoredCredential {
            id: Uuid::new_v4().to_string(),
            user_id: stored_user.id.clone(),
            credential_data,
            created_at: chrono::Utc::now(),
        };

        stored_user.credentials.push(stored_credential);
        stored_user.updated_at = chrono::Utc::now();

        // Update user in storage
        self.storage.update_user(&stored_user).await?;

        Ok(HttpResponse::Ok().json(RegistrationFinishResponse {
            success: true,
            credential_id,
        }))
    }
}
