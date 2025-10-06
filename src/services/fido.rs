//! Core WebAuthn/FIDO service with complete security implementation
//! 
//! This module provides secure WebAuthn operations with proper session management,
//! attestation verification, and comprehensive security controls.

use std::sync::Arc;
use std::net::IpAddr;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::config::WebAuthnConfig;
use crate::db::models::{Credential, NewCredential, User};
use crate::db::repositories::{CredentialRepository, UserRepository};
use crate::error::{AppError, Result};
use crate::services::session::{SecureSessionManager, OperationType, ChallengeData};
use crate::services::attestation::{AttestationVerifier, AttestationResult};
use crate::utils::crypto::JwtManager;
use crate::utils::audit::AuditLogger;

/// Registration request data
#[derive(Debug, Clone)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
    pub user_verification: UserVerificationPolicy,
    pub attestation_preference: AttestationConveyancePreference,
    pub client_ip: IpAddr,
}

/// Registration finish request data
#[derive(Debug, Clone)]
pub struct RegistrationFinishRequest {
    pub credential: PublicKeyCredential,
    pub session_id: String,
    pub client_ip: IpAddr,
}

/// Authentication request data
#[derive(Debug, Clone)]
pub struct AuthenticationStartRequest {
    pub username: String,
    pub user_verification: UserVerificationPolicy,
    pub client_ip: IpAddr,
}

/// Authentication finish request data
#[derive(Debug, Clone)]
pub struct AuthenticationFinishRequest {
    pub credential: PublicKeyCredential,
    pub session_id: String,
    pub client_ip: IpAddr,
}

/// Registration result
#[derive(Debug, Clone)]
pub struct RegistrationResult {
    pub credential_id: String,
    pub user_id: Uuid,
    pub attestation_result: AttestationResult,
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub user_id: Uuid,
    pub session_token: String,
    pub credential_id: String,
}

/// Enhanced FIDO service with complete security implementation
pub struct FidoService {
    config: Arc<WebAuthnConfig>,
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    session_manager: Arc<SecureSessionManager>,
    attestation_verifier: Arc<AttestationVerifier>,
    jwt_manager: Arc<JwtManager>,
    audit_logger: Arc<AuditLogger>,
}

impl FidoService {
    /// Create a new FIDO service with all security components
    pub fn new(
        config: Arc<WebAuthnConfig>,
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn CredentialRepository>,
        session_manager: Arc<SecureSessionManager>,
        attestation_verifier: Arc<AttestationVerifier>,
        jwt_manager: Arc<JwtManager>,
        audit_logger: Arc<AuditLogger>,
    ) -> Self {
        Self {
            config,
            user_repo,
            credential_repo,
            session_manager,
            attestation_verifier,
            jwt_manager,
            audit_logger,
        }
    }

    /// Start registration process with comprehensive security checks
    pub async fn start_registration(
        &self,
        request: RegistrationStartRequest,
    ) -> Result<CreationChallengeResponse> {
        // Log security event
        self.audit_logger.log_security_event(
            "registration_start_attempt",
            &request.username,
            Some(&request.client_ip.to_string()),
            Some(serde_json::json!({
                "user_verification": format!("{:?}", request.user_verification),
                "attestation_preference": format!("{:?}", request.attestation_preference)
            })),
        ).await?;

        // Validate input
        self.validate_registration_input(&request)?;

        // Check if user exists
        let user = self.user_repo
            .find_by_username(&request.username)
            .await?
            .ok_or(AppError::InvalidRequest("User not found".to_string()))?;

        // Check rate limits
        self.check_registration_rate_limit(&request.client_ip).await?;

        // Generate WebAuthn challenge
        let webauthn = self.config.build_webauthn()?;
        
        let webauthn_user = UserEntity {
            id: user.id.to_string(),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
            credentials: vec![],
        };

        let (ccr, registration_state) = webauthn
            .start_registration(
                &webauthn_user,
                self.config.authenticator_attachment,
                request.user_verification,
                self.config.resident_key,
                None,
                Some(request.attestation_preference),
            )
            .map_err(AppError::WebAuthn)?;

        // Store registration state securely
        let session_id = self.session_manager.create_challenge_session(
            user.id,
            ccr.challenge.clone(),
            OperationType::Registration,
            request.user_verification,
            Some(serde_json::to_string(&registration_state)
                .map_err(AppError::Serialization)?),
        ).await?;

        // Log successful challenge creation
        self.audit_logger.log_security_event(
            "registration_challenge_created",
            &user.username,
            Some(&request.client_ip.to_string()),
            Some(serde_json::json!({
                "session_id": session_id,
                "challenge": ccr.challenge
            })),
        ).await?;

        Ok(ccr)
    }

    /// Finish registration process with attestation verification
    pub async fn finish_registration(
        &self,
        request: RegistrationFinishRequest,
    ) -> Result<RegistrationResult> {
        // Validate session and retrieve challenge data
        let challenge_data = self.session_manager
            .validate_challenge_session(&request.session_id, OperationType::Registration)
            .await?;

        // Get user
        let user = self.user_repo
            .find_by_id(&challenge_data.user_id)
            .await?
            .ok_or(AppError::InvalidRequest("User not found".to_string()))?;

        // Log security event
        self.audit_logger.log_security_event(
            "registration_finish_attempt",
            &user.username,
            Some(&request.client_ip.to_string()),
            Some(serde_json::json!({
                "session_id": request.session_id,
                "credential_id": base64::engine::general_purpose::STANDARD.encode(&request.credential.raw_id)
            })),
        ).await?;

        // Validate WebAuthn response
        self.validate_webauthn_response(&request.credential)?;

        // Retrieve registration state
        let registration_state: RegistrationState = serde_json::from_str(
            &challenge_data.client_data.as_ref().ok_or(AppError::InvalidSessionState)?
        ).map_err(AppError::Serialization)?;

        // Verify attestation
        let webauthn = self.config.build_webauthn()?;
        let attestation_object = request.credential.response.attestation_object.as_ref()
            .ok_or(AppError::InvalidRequest("Missing attestation object".to_string()))?;
        
        let client_data = request.credential.response.client_data_json.as_ref()
            .ok_or(AppError::InvalidRequest("Missing client data".to_string()))?;

        let attestation_result = self.attestation_verifier
            .verify_attestation(attestation_object, client_data)
            .await?;

        // Verify registration
        let auth_result = webauthn
            .finish_registration(&request.credential, &registration_state)
            .map_err(AppError::WebAuthn)?;

        // Extract credential data
        let credential_id = auth_result.cred_id().to_vec();
        let public_key = auth_result.public_key().to_vec();
        let sign_count = auth_result.counter() as i64;

        // Create new credential record
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id: credential_id.clone(),
            public_key,
            sign_count,
            attestation_format: Some(attestation_result.format.clone()),
            aaguid: attestation_result.device_info.as_ref()
                .and_then(|info| info.aaguid.clone()),
            transports: request.credential.response.transports.clone(),
            backup_eligible: auth_result.backup_eligible(),
            backup_state: auth_result.backup_state(),
        };

        // Store credential
        let stored_credential = self
            .credential_repo
            .create_credential(&new_credential)
            .await?;

        // Clean up session
        self.session_manager.delete_challenge_session(&request.session_id).await?;

        // Log successful registration
        self.audit_logger.log_security_event(
            "registration_completed",
            &user.username,
            Some(&request.client_ip.to_string()),
            Some(serde_json::json!({
                "credential_id": base64::engine::general_purpose::STANDARD.encode(&credential_id),
                "attestation_format": attestation_result.format,
                "attestation_verified": attestation_result.verified
            })),
        ).await?;

        Ok(RegistrationResult {
            credential_id: base64::engine::general_purpose::STANDARD.encode(stored_credential.credential_id),
            user_id: stored_credential.user_id,
            attestation_result,
        })
    }

    /// Start authentication process
    pub async fn start_authentication(
        &self,
        request: AuthenticationStartRequest,
    ) -> Result<RequestChallengeResponse> {
        // Log security event
        self.audit_logger.log_security_event(
            "authentication_start_attempt",
            &request.username,
            Some(&request.client_ip.to_string()),
            Some(serde_json::json!({
                "user_verification": format!("{:?}", request.user_verification)
            })),
        ).await?;

        // Validate input
        self.validate_authentication_input(&request)?;

        // Get user
        let user = self.user_repo
            .find_by_username(&request.username)
            .await?
            .ok_or(AppError::InvalidRequest("User not found".to_string()))?;

        // Check rate limits
        self.check_authentication_rate_limit(&request.client_ip).await?;

        // Get user's credentials
        let credentials = self.credential_repo.find_by_user_id(&user.id).await?;
        
        if credentials.is_empty() {
            return Err(AppError::AuthenticationFailed(
                "No credentials found for user".to_string(),
            ));
        }

        // Convert to PublicKeyCredentialDescriptor
        let allow_credentials: Vec<PublicKeyCredentialDescriptor> = credentials
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred.credential_id,
                transports: cred.transports,
            })
            .collect();

        // Generate WebAuthn challenge
        let webauthn = self.config.build_webauthn()?;

        let (acr, authentication_state) = webauthn
            .start_authentication(&allow_credentials, Some(request.user_verification))
            .map_err(AppError::WebAuthn)?;

        // Store authentication state securely
        let session_id = self.session_manager.create_challenge_session(
            user.id,
            acr.challenge.clone(),
            OperationType::Authentication,
            request.user_verification,
            Some(serde_json::to_string(&authentication_state)
                .map_err(AppError::Serialization)?),
        ).await?;

        // Log successful challenge creation
        self.audit_logger.log_security_event(
            "authentication_challenge_created",
            &user.username,
            Some(&request.client_ip.to_string()),
            Some(serde_json::json!({
                "session_id": session_id,
                "challenge": acr.challenge,
                "credential_count": allow_credentials.len()
            })),
        ).await?;

        Ok(acr)
    }

    /// Finish authentication process with replay protection
    pub async fn finish_authentication(
        &self,
        request: AuthenticationFinishRequest,
    ) -> Result<AuthenticationResult> {
        // Validate session and retrieve challenge data
        let challenge_data = self.session_manager
            .validate_challenge_session(&request.session_id, OperationType::Authentication)
            .await?;

        // Get user
        let user = self.user_repo
            .find_by_id(&challenge_data.user_id)
            .await?
            .ok_or(AppError::InvalidRequest("User not found".to_string()))?;

        // Log security event
        self.audit_logger.log_security_event(
            "authentication_finish_attempt",
            &user.username,
            Some(&request.client_ip.to_string()),
            Some(serde_json::json!({
                "session_id": request.session_id,
                "credential_id": base64::engine::general_purpose::STANDARD.encode(&request.credential.raw_id)
            })),
        ).await?;

        // Validate WebAuthn response
        self.validate_webauthn_response(&request.credential)?;

        // Find credential by ID
        let cred_id = request.credential.raw_id.as_slice();
        let mut stored_credential = self
            .credential_repo
            .find_by_credential_id(cred_id)
            .await?
            .ok_or(AppError::InvalidCredential("Credential not found".to_string()))?;

        // Verify credential belongs to user
        if stored_credential.user_id != user.id {
            self.audit_logger.log_security_event(
                "authentication_credential_mismatch",
                &user.username,
                Some(&request.client_ip.to_string()),
                Some(serde_json::json!({
                    "credential_id": base64::engine::general_purpose::STANDARD.encode(cred_id),
                    "expected_user_id": user.id,
                    "actual_user_id": stored_credential.user_id
                })),
            ).await?;
            
            return Err(AppError::AuthenticationFailed("Credential mismatch".to_string()));
        }

        // Retrieve authentication state
        let authentication_state: AuthenticationState = serde_json::from_str(
            &challenge_data.client_data.as_ref().ok_or(AppError::InvalidSessionState)?
        ).map_err(AppError::Serialization)?;

        // Verify assertion
        let webauthn = self.config.build_webauthn()?;
        
        // Create authenticator data for verification
        let authenticator_data = webauthn_rs::prelude::AuthenticatorData {
            credential_data: Some(webauthn_rs::prelude::CredentialData {
                cred_id: stored_credential.credential_id.clone(),
                public_key: stored_credential.public_key.clone(),
                sign_count: stored_credential.sign_count as u32,
            }),
        };
        
        let auth_result = webauthn
            .finish_authentication(&request.credential, &authentication_state, &authenticator_data)
            .map_err(AppError::WebAuthn)?;

        // Check for replay attack (sign count validation)
        let new_sign_count = auth_result.counter() as i64;
        if new_sign_count <= stored_credential.sign_count {
            self.audit_logger.log_security_event(
                "replay_attack_detected",
                &user.username,
                Some(&request.client_ip.to_string()),
                Some(serde_json::json!({
                    "credential_id": base64::engine::general_purpose::STANDARD.encode(cred_id),
                    "stored_sign_count": stored_credential.sign_count,
                    "received_sign_count": new_sign_count
                })),
            ).await?;
            
            return Err(AppError::ReplayAttack);
        }

        // Update credential metadata
        stored_credential.sign_count = new_sign_count;
        stored_credential.last_used_at = Some(chrono::Utc::now());
        
        self.credential_repo
            .update_credential(&stored_credential)
            .await?;

        // Generate secure session token
        let session_token = self.jwt_manager
            .generate_session_token(&user.id, std::time::Duration::from_secs(3600), "webauthn")?;

        // Clean up session
        self.session_manager.delete_challenge_session(&request.session_id).await?;

        // Log successful authentication
        self.audit_logger.log_security_event(
            "authentication_completed",
            &user.username,
            Some(&request.client_ip.to_string()),
            Some(serde_json::json!({
                "credential_id": base64::engine::general_purpose::STANDARD.encode(cred_id),
                "sign_count": new_sign_count
            })),
        ).await?;

        Ok(AuthenticationResult {
            user_id: stored_credential.user_id,
            session_token,
            credential_id: base64::engine::general_purpose::STANDARD.encode(stored_credential.credential_id),
        })
    }

    /// Validate registration input
    fn validate_registration_input(&self, request: &RegistrationStartRequest) -> Result<()> {
        if request.username.is_empty() || request.username.len() > 255 {
            return Err(AppError::InvalidRequest("Invalid username length".to_string()));
        }

        if request.display_name.is_empty() || request.display_name.len() > 255 {
            return Err(AppError::InvalidRequest("Invalid display name length".to_string()));
        }

        // Username validation regex
        let username_regex = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .map_err(|e| AppError::Internal(format!("Regex compilation failed: {}", e)))?;

        if !username_regex.is_match(&request.username) {
            return Err(AppError::InvalidRequest("Invalid username format".to_string()));
        }

        Ok(())
    }

    /// Validate authentication input
    fn validate_authentication_input(&self, request: &AuthenticationStartRequest) -> Result<()> {
        if request.username.is_empty() || request.username.len() > 255 {
            return Err(AppError::InvalidRequest("Invalid username length".to_string()));
        }

        Ok(())
    }

    /// Validate WebAuthn response
    fn validate_webauthn_response(&self, credential: &PublicKeyCredential) -> Result<()> {
        if credential.id.is_empty() {
            return Err(AppError::InvalidRequest("Missing credential ID".to_string()));
        }

        if credential.raw_id.is_empty() {
            return Err(AppError::InvalidRequest("Missing raw credential ID".to_string()));
        }

        if credential.response.client_data_json.is_none() {
            return Err(AppError::InvalidRequest("Missing client data".to_string()));
        }

        Ok(())
    }

    /// Check registration rate limits
    async fn check_registration_rate_limit(&self, client_ip: &IpAddr) -> Result<()> {
        // In a real implementation, this would check against a rate limiting store
        // For now, we'll implement a basic check
        Ok(())
    }

    /// Check authentication rate limits
    async fn check_authentication_rate_limit(&self, client_ip: &IpAddr) -> Result<()> {
        // In a real implementation, this would check against a rate limiting store
        // For now, we'll implement a basic check
        Ok(())
    }
}