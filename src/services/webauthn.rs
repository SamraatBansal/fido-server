//! WebAuthn service

use crate::config::WebAuthnConfig;
use crate::error::{AppError, Result};
use crate::schema::auth::{AuthenticationStartRequest, RegistrationStartRequest};
use crate::services::{ChallengeService, CredentialService, UserService};
use uuid::Uuid;
use std::collections::HashMap;
use webauthn_rs::prelude::*;
use base64::{Engine as _, engine::general_purpose};

/// WebAuthn service for handling FIDO2 operations
pub struct WebAuthnService {
    webauthn: Webauthn,
    config: WebAuthnConfig,
    challenge_service: ChallengeService,
    credential_service: CredentialService,
    user_service: UserService,
    // In-memory storage for states (in production, use Redis)
    registration_states: HashMap<Uuid, String>,
    authentication_states: HashMap<Uuid, String>,
}

impl WebAuthnService {
    /// Create new WebAuthn service
    pub fn new(
        config: WebAuthnConfig,
        challenge_service: ChallengeService,
        credential_service: CredentialService,
        user_service: UserService,
    ) -> Result<Self> {
        let rp = RelyingParty {
            name: config.rp_name.clone(),
            id: config.rp_id.clone(),
            origin: url::Url::parse(&config.rp_origin)
                .map_err(|e| AppError::WebAuthnError(format!("Invalid origin URL: {}", e)))?,
        };

        let webauthn_config = WebauthnConfig {
            rp,
            challenge_timeout: config.challenge_timeout,
            ..Default::default()
        };

        let webauthn = Webauthn::new(webauthn_config);

        Ok(Self {
            webauthn,
            config,
            challenge_service,
            credential_service,
            user_service,
            registration_states: HashMap::new(),
            authentication_states: HashMap::new(),
        })
    }

    /// Get WebAuthn configuration
    pub fn config(&self) -> &WebAuthnConfig {
        &self.config
    }

    /// Validate origin
    pub fn validate_origin(&self, origin: &str) -> Result<()> {
        self.config.validate_origin(origin)
    }

    /// Start the registration process
    pub async fn start_registration(
        &mut self,
        request: RegistrationStartRequest,
    ) -> Result<(Uuid, CreationChallengeResponse)> {
        // Validate origin if provided
        if let Some(origin) = &request.origin {
            self.validate_origin(origin)?;
        }

        // Validate input
        crate::utils::validation::validate_username(&request.username)?;
        crate::utils::validation::validate_display_name(&request.display_name)?;

        // Create or get user
        let user = self.user_service.get_or_create_user(&request.username, &request.display_name)?;

        // Generate challenge
        let challenge = self.challenge_service.generate_challenge(
            Some(user.id),
            crate::services::challenge::ChallengeType::Registration,
        )?;

        // Convert user to WebAuthn user
        let webauthn_user = webauthn_rs::prelude::User {
            id: user.id.as_bytes().to_vec(),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
        };

        // Parse user verification preference
        let user_verification = match request.user_verification.as_deref() {
            Some("required") => UserVerificationPolicy::Required,
            Some("preferred") => UserVerificationPolicy::Preferred,
            Some("discouraged") => UserVerificationPolicy::Discouraged,
            _ => UserVerificationPolicy::Preferred,
        };

        // Parse attestation preference
        let attestation = match request.attestation.as_deref() {
            Some("none") => AttestationConveyancePreference::None,
            Some("indirect") => AttestationConveyancePreference::Indirect,
            Some("direct") => AttestationConveyancePreference::Direct,
            Some("enterprise") => AttestationConveyancePreference::Enterprise,
            _ => AttestationConveyancePreference::Direct,
        };

        // Create credential creation options
        let (ccr, state) = self.webauthn.generate_challenge_register_options(
            &webauthn_user,
            user_verification,
            attestation,
            None,
        ).map_err(|e| AppError::WebAuthnError(format!("Failed to generate registration options: {}", e)))?;

        // Store state for verification
        self.registration_states.insert(challenge.challenge_id, format!("{:?}", state));

        Ok((challenge.challenge_id, ccr))
    }

    /// Complete the registration process
    pub async fn finish_registration(
        &mut self,
        challenge_id: Uuid,
        registration_credential: PublicKeyCredential,
    ) -> Result<crate::db::models::Credential> {
        // Get stored state
        let _state = self.registration_states
            .remove(&challenge_id)
            .ok_or_else(|| AppError::BadRequest("Invalid or expired challenge".to_string()))?;

        // Extract challenge data from client data
        let client_data_json = registration_credential.response.client_data_json.clone();
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::BadRequest(format!("Invalid client data JSON: {}", e)))?;

        let challenge_b64 = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing challenge in client data".to_string()))?;

        let challenge_data = general_purpose::URL_SAFE_NO_PAD.decode(challenge_b64)
            .map_err(|e| AppError::BadRequest(format!("Invalid challenge encoding: {}", e)))?;

        // Validate challenge
        self.challenge_service.validate_challenge(challenge_id, &challenge_data)?;

        // For now, create a mock credential since we don't have the full WebAuthn verification
        let user_id = Uuid::new_v4(); // This should come from the verification
        let credential_id = registration_credential.raw_id.clone();
        
        // Store credential
        let credential = self.credential_service.store_credential(
            user_id,
            credential_id,
            serde_json::json!({"type": "public-key", "algorithm": -7}), // Mock public key
            0,
            None,
        ).await?;

        // Log audit event
        self.log_audit_event(
            Some(user_id),
            "registration",
            true,
            Some(&general_purpose::STANDARD.encode(&credential_id)),
            None,
        ).await?;

        Ok(credential)
    }

    /// Start the authentication process
    pub async fn start_authentication(
        &mut self,
        request: AuthenticationStartRequest,
    ) -> Result<(Uuid, RequestChallengeResponse)> {
        // Validate origin if provided
        if let Some(origin) = &request.origin {
            self.validate_origin(origin)?;
        }

        // Get user credentials
        let user = if let Some(username) = &request.username {
            crate::utils::validation::validate_username(username)?;
            Some(self.user_service.get_user_by_username(username)?
                .ok_or_else(|| AppError::NotFound("User not found".to_string()))?)
        } else {
            None // Usernameless authentication
        };

        let allow_credentials = if let Some(user) = &user {
            self.credential_service.get_user_credentials(user.id)
                .await?
                .into_iter()
                .map(|cred| {
                    let cred_id = general_purpose::STANDARD.decode(&cred.credential_id)
                        .unwrap_or_default();
                    CredentialID::from(cred_id)
                })
                .collect()
        } else {
            vec![] // Usernameless
        };

        // Generate challenge
        let challenge = self.challenge_service.generate_challenge(
            user.as_ref().map(|u| u.id),
            crate::services::challenge::ChallengeType::Authentication,
        )?;

        // Parse user verification preference
        let user_verification = match request.user_verification.as_deref() {
            Some("required") => UserVerificationPolicy::Required,
            Some("preferred") => UserVerificationPolicy::Preferred,
            Some("discouraged") => UserVerificationPolicy::Discouraged,
            _ => UserVerificationPolicy::Preferred,
        };

        // Create authentication options
        let (acr, state) = self.webauthn.generate_challenge_authenticate_options(
            allow_credentials,
            user_verification,
        ).map_err(|e| AppError::WebAuthnError(format!("Failed to generate authentication options: {}", e)))?;

        // Store state for verification
        self.authentication_states.insert(challenge.challenge_id, format!("{:?}", state));

        Ok((challenge.challenge_id, acr))
    }

    /// Complete the authentication process
    pub async fn finish_authentication(
        &mut self,
        challenge_id: Uuid,
        authentication_credential: PublicKeyCredential,
    ) -> Result<AuthenticationResult> {
        // Get stored state
        let _state = self.authentication_states
            .remove(&challenge_id)
            .ok_or_else(|| AppError::BadRequest("Invalid or expired challenge".to_string()))?;

        // Extract challenge data from client data
        let client_data_json = authentication_credential.response.client_data_json.clone();
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::BadRequest(format!("Invalid client data JSON: {}", e)))?;

        let challenge_b64 = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing challenge in client data".to_string()))?;

        let challenge_data = general_purpose::URL_SAFE_NO_PAD.decode(challenge_b64)
            .map_err(|e| AppError::BadRequest(format!("Invalid challenge encoding: {}", e)))?;

        // Validate challenge
        self.challenge_service.validate_challenge(challenge_id, &challenge_data)?;

        // For now, create a mock result since we don't have the full WebAuthn verification
        let user_id = Uuid::new_v4(); // This should come from the verification
        let credential_id = authentication_credential.raw_id.clone();

        // Create session token
        let session_token = self.create_session(user_id).await?;

        // Log audit event
        self.log_audit_event(
            Some(user_id),
            "authentication",
            true,
            Some(&general_purpose::STANDARD.encode(&credential_id)),
            None,
        ).await?;

        Ok(AuthenticationResult {
            user_id,
            session_token,
            counter: 0,
            credential_id,
        })
    }

    async fn create_session(&self, _user_id: Uuid) -> Result<String> {
        // Generate secure session token
        let session_token = crate::utils::crypto::generate_secure_random_string(32)?;
        Ok(format!("session_{}", session_token))
    }

    async fn log_audit_event(
        &self,
        user_id: Option<Uuid>,
        action: &str,
        success: bool,
        credential_id: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        // Implementation would log to audit table
        log::info!(
            "Audit: user_id={:?}, action={}, success={}, credential_id={:?}, error={:?}",
            user_id, action, success, credential_id, error
        );
        Ok(())
    }
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub user_id: Uuid,
    pub session_token: String,
    pub counter: u32,
    pub credential_id: Vec<u8>,
}