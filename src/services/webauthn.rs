//! WebAuthn service implementation

use webauthn_rs::prelude::*;
use std::collections::HashMap;
use uuid::Uuid;
use crate::config::WebAuthnConfig;
use crate::services::{ChallengeService, CredentialService, UserService, SessionService, AuditService};
use crate::db::PooledDb;
use crate::schema::{
    RegistrationStartRequest, RegistrationFinishRequest, AuthenticationStartRequest, 
    AuthenticationFinishRequest, RegistrationStartResponse, RegistrationFinishResponse,
    AuthenticationStartResponse, AuthenticationFinishResponse
};
use crate::error::{AppError, Result};
use base64::{Engine as _, engine::general_purpose};

/// Main WebAuthn service
#[derive(Clone)]
pub struct WebAuthnService {
    webauthn: Webauthn,
    config: WebAuthnConfig,
    challenge_service: ChallengeService,
    credential_service: CredentialService,
    user_service: UserService,
    session_service: SessionService,
    audit_service: AuditService,
    // In-memory storage for WebAuthn state (in production, use Redis)
    registration_states: std::sync::Arc<std::sync::Mutex<HashMap<Uuid, RegistrationState>>>,
    authentication_states: std::sync::Arc<std::sync::Mutex<HashMap<Uuid, AuthenticationState>>>,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new(
        config: WebAuthnConfig,
        session_service: SessionService,
    ) -> Result<Self> {
        let webauthn = config.to_webauthn()?;
        
        Ok(Self {
            webauthn,
            config,
            challenge_service: ChallengeService::new(),
            credential_service: CredentialService::new(),
            user_service: UserService::new(),
            session_service,
            audit_service: AuditService::new(),
            registration_states: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            authentication_states: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Start the registration process
    pub async fn start_registration(
        &mut self,
        conn: &mut PooledDb,
        request: RegistrationStartRequest,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<RegistrationStartResponse> {
        // Validate origin if provided
        if let Some(origin) = &request.origin {
            self.config.validate_origin(origin)?;
        }

        // Create or get user
        let user = self.user_service
            .get_or_create_user(conn, &request.username, &request.display_name)
            .await?;

        // Generate challenge
        let challenge = self.challenge_service
            .generate_challenge(
                conn,
                Some(user.id),
                "registration",
                self.config.challenge_timeout.as_secs(),
            )
            .await?;

        // Create credential creation options
        let (ccr, state) = self.webauthn.generate_challenge_register_options(
            &user.into(),
            request.user_verification.into(),
            request.attestation.into(),
            Some(request.authenticator_selection.into()),
        ).map_err(|e| AppError::WebAuthnError(format!("Failed to generate registration options: {}", e)))?;

        // Store state for verification
        self.registration_states.lock().unwrap().insert(challenge.challenge_id, state);

        // Log audit event
        self.audit_service.log_event(
            conn,
            Some(user.id),
            "registration_started",
            true,
            None,
            ip_address,
            user_agent,
            None,
            None,
        ).await?;

        Ok(RegistrationStartResponse {
            challenge_id: challenge.challenge_id,
            public_key: ccr,
        })
    }

    /// Complete the registration process
    pub async fn finish_registration(
        &mut self,
        conn: &mut PooledDb,
        request: RegistrationFinishRequest,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<RegistrationFinishResponse> {
        // Get stored state
        let state = self.registration_states.lock().unwrap()
            .remove(&request.challenge_id)
            .ok_or(AppError::WebAuthnError("Invalid challenge ID".to_string()))?;

        // Convert request credential
        let registration_credential = self.convert_registration_credential(request.credential)?;

        // Extract client data JSON for challenge validation
        let client_data_json = general_purpose::STANDARD
            .decode(&registration_credential.response.client_data_json)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid client data JSON: {}", e)))?;

        // Validate challenge
        let challenge = self.challenge_service
            .validate_challenge(conn, request.challenge_id, &client_data_json)
            .await?;

        // Verify registration
        let auth_result = self.webauthn.register_credential(
            registration_credential,
            &state,
        ).map_err(|e| {
            // Log failed registration
            let _ = self.audit_service.log_registration_failure(
                conn,
                challenge.user_id,
                &format!("Registration verification failed: {}", e),
                ip_address,
                user_agent,
            );
            AppError::WebAuthnError(format!("Registration verification failed: {}", e))
        })?;

        // Store credential
        let credential = self.credential_service
            .store_credential(conn, auth_result.clone())
            .await?;

        // Log successful registration
        self.audit_service.log_registration_success(
            conn,
            auth_result.user_id,
            &general_purpose::URL_SAFE_NO_PAD.encode(&auth_result.credential_id),
            ip_address,
            user_agent,
        ).await?;

        Ok(RegistrationFinishResponse {
            credential_id: credential.credential_id,
            user_id: credential.user_id,
            created_at: credential.created_at,
            authenticator_info: crate::schema::registration::AuthenticatorInfo {
                aaguid: credential.aaguid,
                sign_count: auth_result.counter,
                clone_warning: auth_result.clone_warning,
                backup_eligible: auth_result.backup_eligible,
                backup_state: auth_result.backup_state,
            },
        })
    }

    /// Start the authentication process
    pub async fn start_authentication(
        &mut self,
        conn: &mut PooledDb,
        request: AuthenticationStartRequest,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuthenticationStartResponse> {
        // Validate origin if provided
        if let Some(origin) = &request.origin {
            self.config.validate_origin(origin)?;
        }

        // Get user credentials
        let user = if let Some(username) = &request.username {
            Some(self.user_service.get_user_by_username(conn, username).await?
                .ok_or(AppError::NotFound("User not found".to_string()))?)
        } else {
            None // Usernameless authentication
        };

        let allow_credentials = if let Some(user) = &user {
            self.credential_service
                .get_user_credentials(conn, user.id)
                .await?
                .into_iter()
                .map(|cred| {
                    let cred_id = general_purpose::URL_SAFE_NO_PAD.decode(&cred.credential_id)
                        .unwrap_or_default();
                    CredentialID::from_bytes(&cred_id)
                })
                .collect()
        } else {
            vec![] // Usernameless
        };

        // Generate challenge
        let challenge = self.challenge_service
            .generate_challenge(
                conn,
                user.as_ref().map(|u| u.id),
                "authentication",
                self.config.challenge_timeout.as_secs(),
            )
            .await?;

        // Create authentication options
        let (acr, state) = self.webauthn.generate_challenge_authenticate_options(
            allow_credentials,
            request.user_verification.into(),
        ).map_err(|e| AppError::WebAuthnError(format!("Failed to generate authentication options: {}", e)))?;

        // Store state for verification
        self.authentication_states.lock().unwrap().insert(challenge.challenge_id, state);

        // Log audit event
        self.audit_service.log_event(
            conn,
            user.as_ref().map(|u| u.id),
            "authentication_started",
            true,
            None,
            ip_address,
            user_agent,
            None,
            None,
        ).await?;

        Ok(AuthenticationStartResponse {
            challenge_id: challenge.challenge_id,
            public_key: acr,
        })
    }

    /// Complete the authentication process
    pub async fn finish_authentication(
        &mut self,
        conn: &mut PooledDb,
        request: AuthenticationFinishRequest,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuthenticationFinishResponse> {
        // Get stored state
        let state = self.authentication_states
            .remove(&request.challenge_id)
            .ok_or(AppError::WebAuthnError("Invalid challenge ID".to_string()))?;

        // Convert request credential
        let authentication_credential = self.convert_authentication_credential(request.credential)?;

        // Extract client data JSON for challenge validation
        let client_data_json = general_purpose::STANDARD
            .decode(&authentication_credential.response.client_data_json)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid client data JSON: {}", e)))?;

        // Validate challenge
        let challenge = self.challenge_service
            .validate_challenge(conn, request.challenge_id, &client_data_json)
            .await?;

        // Verify authentication
        let auth_result = self.webauthn.authenticate_credential(
            authentication_credential,
            &state,
        ).map_err(|e| {
            // Log failed authentication
            let _ = self.audit_service.log_authentication_failure(
                conn,
                challenge.user_id,
                None,
                &format!("Authentication verification failed: {}", e),
                ip_address,
                user_agent,
            );
            AppError::WebAuthnError(format!("Authentication verification failed: {}", e))
        })?;

        // Update credential usage
        self.credential_service
            .update_credential_usage(
                conn,
                &auth_result.credential_id,
                auth_result.counter,
            )
            .await?;

        // Create session
        let session_token = self.session_service
            .create_session(
                conn,
                auth_result.user_id,
                ip_address.map(|s| s.to_string()),
                user_agent.map(|s| s.to_string()),
            )
            .await?;

        // Log successful authentication
        self.audit_service.log_authentication_success(
            conn,
            auth_result.user_id,
            &general_purpose::URL_SAFE_NO_PAD.encode(&auth_result.credential_id),
            ip_address,
            user_agent,
        ).await?;

        Ok(AuthenticationFinishResponse {
            user_id: auth_result.user_id,
            session_token,
            authenticated_at: chrono::Utc::now(),
            authenticator_info: crate::schema::auth::AuthenticationAuthenticatorInfo {
                sign_count: auth_result.counter,
                clone_warning: false, // Would be set if clone detected
                credential_id: general_purpose::URL_SAFE_NO_PAD.encode(&auth_result.credential_id),
            },
        })
    }

    /// Convert registration credential from schema to webauthn-rs format
    fn convert_registration_credential(
        &self,
        credential: crate::schema::registration::RegistrationCredential,
    ) -> Result<PublicKeyCredential> {
        let attestation_object = general_purpose::STANDARD
            .decode(&credential.response.attestation_object)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid attestation object: {}", e)))?;

        let client_data_json = general_purpose::STANDARD
            .decode(&credential.response.client_data_json)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid client data JSON: {}", e)))?;

        Ok(PublicKeyCredential {
            id: credential.id,
            raw_id: general_purpose::STANDARD
                .decode(&credential.raw_id)
                .map_err(|e| AppError::WebAuthnError(format!("Invalid raw ID: {}", e)))?,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object,
                client_data_json,
            },
            type_: credential.type_,
            extensions: None,
        })
    }

    /// Convert authentication credential from schema to webauthn-rs format
    fn convert_authentication_credential(
        &self,
        credential: crate::schema::auth::AuthenticationCredential,
    ) -> Result<PublicKeyCredential> {
        let authenticator_data = general_purpose::STANDARD
            .decode(&credential.response.authenticator_data)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid authenticator data: {}", e)))?;

        let client_data_json = general_purpose::STANDARD
            .decode(&credential.response.client_data_json)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid client data JSON: {}", e)))?;

        let signature = general_purpose::STANDARD
            .decode(&credential.response.signature)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid signature: {}", e)))?;

        let user_handle = credential.response.user_handle
            .map(|uh| general_purpose::STANDARD.decode(&uh)
                .map_err(|e| AppError::WebAuthnError(format!("Invalid user handle: {}", e))))
            .transpose()?;

        Ok(PublicKeyCredential {
            id: credential.id,
            raw_id: general_purpose::STANDARD
                .decode(&credential.raw_id)
                .map_err(|e| AppError::WebAuthnError(format!("Invalid raw ID: {}", e)))?,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data,
                client_data_json,
                signature,
                user_handle,
            },
            type_: credential.type_,
            extensions: None,
        })
    }

    /// Clean up expired states
    pub fn cleanup_expired_states(&mut self) {
        // In a production implementation, you would check timestamps
        // For now, just clear the maps periodically
        if self.registration_states.len() > 1000 {
            self.registration_states.clear();
        }
        if self.authentication_states.len() > 1000 {
            self.authentication_states.clear();
        }
    }
}