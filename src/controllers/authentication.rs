//! Authentication controller

use crate::error::{AppError, Result};
use crate::services::{Storage, WebAuthnService};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use webauthn_rs::prelude::*;

/// Authentication start request
#[derive(Debug, Deserialize)]
pub struct AuthenticationStartRequest {
    pub username: String,
}

/// Authentication start response
#[derive(Debug, Serialize)]
pub struct AuthenticationStartResponse {
    pub challenge: RequestChallengeResponse,
    pub authentication_state: String, // Serialized state
}

/// Authentication finish request
#[derive(Debug, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub username: String,
    pub authentication_state: String, // Serialized state
    pub credential: PublicKeyCredential,
}

/// Authentication finish response
#[derive(Debug, Serialize)]
pub struct AuthenticationFinishResponse {
    pub success: bool,
    pub user_id: String,
}

/// Authentication controller
pub struct AuthenticationController {
    webauthn: Arc<WebAuthnService>,
    storage: Arc<dyn Storage>,
}

impl AuthenticationController {
    /// Create a new authentication controller
    pub fn new(webauthn: Arc<WebAuthnService>, storage: Arc<dyn Storage>) -> Self {
        Self { webauthn, storage }
    }

    /// Start authentication ceremony
    pub async fn start_authentication(
        &self,
        req: web::Json<AuthenticationStartRequest>,
        _http_req: HttpRequest,
    ) -> Result<HttpResponse> {
        // Validate input
        if req.username.trim().is_empty() {
            return Err(AppError::ValidationError(
                "Username cannot be empty".to_string(),
            ));
        }

        // Get user from storage
        let stored_user = self
            .storage
            .get_user_by_username(&req.username)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        if stored_user.credentials.is_empty() {
            return Err(AppError::BadRequest(
                "User has no registered credentials".to_string(),
            ));
        }

        // Deserialize credentials
        let mut credentials = Vec::new();
        for stored_cred in &stored_user.credentials {
            let passkey: Passkey =
                serde_json::from_str(&stored_cred.credential_data).map_err(|e| {
                    AppError::InternalError(format!("Failed to deserialize credential: {}", e))
                })?;
            credentials.push(passkey);
        }

        // Begin authentication
        let (challenge, auth_state) = self.webauthn.begin_authentication(&credentials)?;

        // Serialize authentication state
        let authentication_state = serde_json::to_string(&auth_state).map_err(|e| {
            AppError::InternalError(format!("Failed to serialize authentication state: {}", e))
        })?;

        Ok(HttpResponse::Ok().json(AuthenticationStartResponse {
            challenge,
            authentication_state,
        }))
    }

    /// Finish authentication ceremony
    pub async fn finish_authentication(
        &self,
        req: web::Json<AuthenticationFinishRequest>,
        _http_req: HttpRequest,
    ) -> Result<HttpResponse> {
        // Deserialize authentication state
        let auth_state: PasskeyAuthentication = serde_json::from_str(&req.authentication_state)
            .map_err(|e| AppError::BadRequest(format!("Invalid authentication state: {}", e)))?;

        // Get user from storage
        let stored_user = self
            .storage
            .get_user_by_username(&req.username)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Finish authentication
        let _auth_result = self
            .webauthn
            .finish_authentication(&auth_state, &req.credential)?;

        Ok(HttpResponse::Ok().json(AuthenticationFinishResponse {
            success: true,
            user_id: stored_user.id,
        }))
    }
}
