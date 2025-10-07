use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use rand::Rng;

use crate::config::WebAuthnConfig;
use crate::db::repositories::{UserRepository, CredentialRepository, AuthSessionRepository, AuditLogRepository};
use crate::db::models::{NewUser, NewCredential, NewAuthSession, NewAuditLog};
use crate::schema::{
    AttestationOptionsRequest, AttestationOptionsResponse, AttestationResultRequest, AttestationResultResponse,
    AssertionOptionsRequest, AssertionOptionsResponse, AssertionResultRequest, AssertionResultResponse,
    RequestContext, SessionData, SessionType, AuthResult, CredentialCreationData, AuditEventData,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialParameters,
    AuthenticatorSelectionCriteria, AttestationConveyancePreference, RegistrationExtensionInputs,
    RegistrationExtensionOutputs, AuthenticationExtensionInputs, AuthenticationExtensionOutputs,
    PublicKeyCredentialDescriptor, AuthenticatorTransport, AuthenticatorAttachment,
    UserVerificationPolicy, ResidentKeyRequirement, CredentialPropertiesOutput,
    LargeBlobExtensionInput, LargeBlobExtensionOutput, LargeBlobAuthenticationInput, LargeBlobAuthenticationOutput
};
use crate::error::{AppError, Result};

pub struct WebAuthnService {
    webauthn: WebAuthn<WebauthnConfig>,
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    session_repo: Arc<dyn AuthSessionRepository>,
    audit_repo: Arc<dyn AuditLogRepository>,
    config: WebAuthnConfig,
}

impl WebAuthnService {
    pub fn new(
        config: WebAuthnConfig,
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn CredentialRepository>,
        session_repo: Arc<dyn AuthSessionRepository>,
        audit_repo: Arc<dyn AuditLogRepository>,
    ) -> Result<Self> {
        let rp_id = config.rp_id.clone();
        let rp_name = config.rp_name.clone();
        let rp_origin = config.rp_origin.parse()
            .map_err(|e| AppError::Configuration(format!("Invalid origin: {}", e)))?;
        
        let webauthn_config = WebauthnConfig {
            rp: RpId::Domain(rp_id),
            rp_name,
            origin: rp_origin,
        };
        
        let webauthn = WebAuthn::new(webauthn_config);
        
        Ok(Self {
            webauthn,
            user_repo,
            credential_repo,
            session_repo,
            audit_repo,
            config,
        })
    }

    pub async fn start_attestation(
        &self,
        request: AttestationOptionsRequest,
        context: &RequestContext,
    ) -> Result<AttestationOptionsResponse> {
        // Validate request
        request.validate()
            .map_err(|e| AppError::InvalidRequest(format!("Validation error: {}", e)))?;

        // Find or create user
        let user = match self.user_repo.find_by_username(&request.username).await? {
            Some(user) => user,
            None => {
                let new_user = NewUser {
                    username: request.username.clone(),
                    display_name: request.display_name.clone(),
                    email: None,
                };
                self.user_repo.create_user(&new_user).await?
            }
        };

        // Get existing credentials for exclusion
        let existing_credentials = self.credential_repo.find_by_user_id(&user.id).await?;
        let exclude_credentials: Vec<_> = existing_credentials.iter().map(|cred| {
            PublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: cred.transports.as_ref().map(|t| {
                    t.iter().filter_map(|s| match s.as_str() {
                        "usb" => Some(AuthenticatorTransport::Usb),
                        "nfc" => Some(AuthenticatorTransport::Nfc),
                        "ble" => Some(AuthenticatorTransport::Ble),
                        "internal" => Some(AuthenticatorTransport::Internal),
                        _ => None,
                    }).collect()
                }),
            }
        }).collect();

        // Convert authenticator selection
        let authenticator_selection = request.authenticator_selection.map(|auth_sel| {
            AuthenticatorSelectionCriteria {
                authenticator_attachment: auth_sel.authenticator_attachment,
                require_resident_key: auth_sel.require_resident_key,
                resident_key: auth_sel.resident_key,
                user_verification: auth_sel.user_verification.or_else(|| {
                    match self.config.user_verification.as_str() {
                        "required" => Some(UserVerificationPolicy::Required),
                        "preferred" => Some(UserVerificationPolicy::Preferred),
                        "discouraged" => Some(UserVerificationPolicy::Discouraged),
                        _ => None,
                    }
                }),
            }
        });

        // Convert attestation preference
        let attestation = request.attestation.or_else(|| {
            match self.config.attestation_preference.as_str() {
                "none" => Some(AttestationConveyancePreference::None),
                "indirect" => Some(AttestationConveyancePreference::Indirect),
                "direct" => Some(AttestationConveyancePreference::Direct),
                "enterprise" => Some(AttestationConveyancePreference::Enterprise),
                _ => Some(AttestationConveyancePreference::None),
            }
        });

        // Create credential creation options
        let user_entity = User {
            id: user.id.as_bytes().to_vec(),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
        };

        let credential_creation_options = self.webauthn.start_credential_registration(
            &user_entity,
            authenticator_selection.as_ref().map(|auth_sel| {
                webauthn_rs::prelude::AuthenticatorSelectionCriteria {
                    authenticator_attachment: auth_sel.authenticator_attachment.as_ref().map(|a| match a {
                        AuthenticatorAttachment::Platform => webauthn_rs::prelude::AuthenticatorAttachment::Platform,
                        AuthenticatorAttachment::CrossPlatform => webauthn_rs::prelude::AuthenticatorAttachment::CrossPlatform,
                    }),
                    require_resident_key: auth_sel.require_resident_key,
                    resident_key: auth_sel.resident_key.as_ref().map(|rk| match rk {
                        ResidentKeyRequirement::Discouraged => webauthn_rs::prelude::ResidentKeyRequirement::Discouraged,
                        ResidentKeyRequirement::Preferred => webauthn_rs::prelude::ResidentKeyRequirement::Preferred,
                        ResidentKeyRequirement::Required => webauthn_rs::prelude::ResidentKeyRequirement::Required,
                    }),
                    user_verification: auth_sel.user_verification.as_ref().map(|uv| match uv {
                        UserVerificationPolicy::Required => webauthn_rs::prelude::UserVerificationPolicy::Required,
                        UserVerificationPolicy::Preferred => webauthn_rs::prelude::UserVerificationPolicy::Preferred,
                        UserVerificationPolicy::Discouraged => webauthn_rs::prelude::UserVerificationPolicy::Discouraged,
                    }).unwrap_or(webauthn_rs::prelude::UserVerificationPolicy::Preferred),
                }
            }),
            attestation.as_ref().map(|att| match att {
                AttestationConveyancePreference::None => webauthn_rs::prelude::AttestationConveyancePreference::None,
                AttestationConveyancePreference::Indirect => webauthn_rs::prelude::AttestationConveyancePreference::Indirect,
                AttestationConveyancePreference::Direct => webauthn_rs::prelude::AttestationConveyancePreference::Direct,
                AttestationConveyancePreference::Enterprise => webauthn_rs::prelude::AttestationConveyancePreference::Enterprise,
            }),
            None, // extensions
            Some(exclude_credentials.iter().map(|cred| {
                webauthn_rs::prelude::PublicKeyCredentialDescriptor {
                    type_: webauthn_rs::prelude::PublicKeyCredentialType::PublicKey,
                    id: general_purpose::URL_SAFE_NO_PAD.decode(&cred.id).unwrap_or_default(),
                    transports: cred.transports.as_ref().map(|t| {
                        t.iter().map(|transport| match transport {
                            AuthenticatorTransport::Usb => webauthn_rs::prelude::AuthenticatorTransport::Usb,
                            AuthenticatorTransport::Nfc => webauthn_rs::prelude::AuthenticatorTransport::Nfc,
                            AuthenticatorTransport::Ble => webauthn_rs::prelude::AuthenticatorTransport::Ble,
                            AuthenticatorTransport::Internal => webauthn_rs::prelude::AuthenticatorTransport::Internal,
                        }).collect()
                    }).unwrap_or_default(),
                }
            }).collect()),
        )?;

        // Generate session ID and store session data
        let session_id = self.generate_session_id();
        let challenge = credential_creation_options.challenge.clone();
        let expires_at = Utc::now() + Duration::seconds(self.config.timeout as i64 / 1000);

        let session_data = SessionData {
            user_id: Some(user.id),
            username: Some(user.username),
            challenge: challenge.as_bytes().to_vec(),
            session_type: SessionType::Registration,
            expires_at,
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
        };

        let new_session = NewAuthSession {
            session_id: session_id.clone(),
            challenge: session_data.challenge.clone(),
            user_id: session_data.user_id,
            session_type: "registration".to_string(),
            expires_at,
            data: Some(serde_json::to_value(session_data)?),
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
        };

        self.session_repo.create_session(&new_session).await?;

        // Log audit event
        let audit_log = NewAuditLog {
            user_id: Some(user.id),
            action: "attestation_started".to_string(),
            resource_type: Some("session".to_string()),
            resource_id: Some(session_id.clone()),
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
            success: true,
            error_message: None,
            metadata: Some(serde_json::json!({
                "username": user.username,
                "session_type": "registration"
            })),
        };

        self.audit_repo.create_log(&audit_log).await?;

        // Build response
        let response = AttestationOptionsResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            rp: PublicKeyCredentialRpEntity {
                id: self.config.rp_id.clone(),
                name: self.config.rp_name.clone(),
            },
            user: PublicKeyCredentialUserEntity {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            challenge: general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes()),
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters { type_: "public-key".to_string(), alg: -7 },  // ES256
                PublicKeyCredentialParameters { type_: "public-key".to_string(), alg: -257 }, // RS256
                PublicKeyCredentialParameters { type_: "public-key".to_string(), alg: -8 },   // EdDSA
            ],
            timeout: self.config.timeout,
            exclude_credentials: Some(exclude_credentials),
            authenticator_selection,
            attestation,
            extensions: None, // TODO: Map extensions from request
        };

        Ok(response)
    }

    pub async fn finish_attestation(
        &self,
        request: AttestationResultRequest,
        context: &RequestContext,
    ) -> Result<AttestationResultResponse> {
        // Validate request
        request.validate()
            .map_err(|e| AppError::InvalidRequest(format!("Validation error: {}", e)))?;

        // Find session
        let session = self.session_repo.find_by_session_id(&request.session_id).await?
            .ok_or(AppError::SessionNotFound)?;

        // Check session expiration
        if session.expires_at < Utc::now() {
            self.session_repo.delete_session(&request.session_id).await?;
            return Err(AppError::SessionExpired);
        }

        // Verify session type
        if session.session_type != "registration" {
            return Err(AppError::InvalidRequest("Invalid session type".to_string()));
        }

        // Parse session data
        let session_data: SessionData = serde_json::from_value(session.data.ok_or_else(|| {
            AppError::InvalidRequest("Session data missing".to_string())
        })?)?;

        let user_id = session_data.user_id.ok_or_else(|| {
            AppError::InvalidRequest("User ID missing from session".to_string())
        })?;

        // Parse credential response
        let credential_id = general_purpose::URL_SAFE_NO_PAD.decode(&request.credential_id)
            .map_err(|_| AppError::InvalidRequest("Invalid credential ID".to_string()))?;

        let client_data_json = general_purpose::URL_SAFE_NO_PAD.decode(&request.response.client_data_json)
            .map_err(|_| AppError::InvalidRequest("Invalid client data JSON".to_string()))?;

        let attestation_object = general_purpose::URL_SAFE_NO_PAD.decode(&request.response.attestation_object)
            .map_err(|_| AppError::InvalidRequest("Invalid attestation object".to_string()))?;

        // Create PublicKeyCredential
        let public_key_credential = PublicKeyCredential {
            id: credential_id.clone(),
            raw_id: credential_id.clone(),
            response: AuthenticatorAttestationResponseRaw {
                client_data_json: client_data_json.clone(),
                attestation_object: attestation_object.clone(),
            },
            type_: webauthn_rs::prelude::PublicKeyCredentialType::PublicKey,
            extensions: None,
            client_extension_results: Default::default(),
        };

        // Verify attestation
        let attestation_result = self.webauthn.finish_credential_registration(
            &public_key_credential,
            &session_data.challenge,
        )?;

        // Store credential
        let new_credential = NewCredential {
            user_id,
            credential_id: credential_id.clone(),
            credential_public_key: attestation_result.credential.public_key.clone(),
            aaguid: Some(attestation_result.credential.aaguid.clone()),
            sign_count: attestation_result.credential.sign_count as i64,
            user_verified: attestation_result.user_verified,
            backup_eligible: attestation_result.credential.backup_eligible,
            backup_state: attestation_result.credential.backup_state,
            attestation_format: Some(attestation_result.attestation_format().to_string()),
            attestation_statement: Some(serde_json::to_value(attestation_result.attestation_statement())?),
            transports: request.authenticator_attachment.as_ref().map(|_| {
                vec!["internal".to_string()] // Default to internal for platform authenticators
            }),
            is_resident: attestation_result.credential.backup_eligible,
        };

        let stored_credential = self.credential_repo.create_credential(&new_credential).await?;

        // Clean up session
        self.session_repo.delete_session(&request.session_id).await?;

        // Log audit event
        let audit_log = NewAuditLog {
            user_id: Some(user_id),
            action: "attestation_completed".to_string(),
            resource_type: Some("credential".to_string()),
            resource_id: Some(general_purpose::URL_SAFE_NO_PAD.encode(&credential_id)),
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
            success: true,
            error_message: None,
            metadata: Some(serde_json::json!({
                "credential_id": general_purpose::URL_SAFE_NO_PAD.encode(&credential_id),
                "aaguid": general_purpose::URL_SAFE_NO_PAD.encode(&attestation_result.credential.aaguid),
                "user_verified": attestation_result.user_verified
            })),
        };

        self.audit_repo.create_log(&audit_log).await?;

        // Get user for response
        let user = self.user_repo.find_by_id(&user_id).await?
            .ok_or(AppError::UserNotFound)?;

        let response = AttestationResultResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            credential_id: general_purpose::URL_SAFE_NO_PAD.encode(&credential_id),
            aaguid: Some(general_purpose::URL_SAFE_NO_PAD.encode(&attestation_result.credential.aaguid)),
            sign_count: attestation_result.credential.sign_count,
            user_verified: attestation_result.user_verified,
            new_identity: Some(PublicKeyCredentialUserEntity {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            }),
        };

        Ok(response)
    }

    pub async fn start_assertion(
        &self,
        request: AssertionOptionsRequest,
        context: &RequestContext,
    ) -> Result<AssertionOptionsResponse> {
        // Validate request
        request.validate()
            .map_err(|e| AppError::InvalidRequest(format!("Validation error: {}", e)))?;

        // Find user if username provided
        let user = if let Some(username) = &request.username {
            self.user_repo.find_by_username(username).await?
        } else {
            None
        };

        // Get user credentials
        let allow_credentials = if let Some(user) = &user {
            let credentials = self.credential_repo.find_by_user_id(&user.id).await?;
            Some(credentials.iter().map(|cred| {
                PublicKeyCredentialDescriptor {
                    type_: "public-key".to_string(),
                    id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                    transports: cred.transports.as_ref().map(|t| {
                        t.iter().filter_map(|s| match s.as_str() {
                            "usb" => Some(AuthenticatorTransport::Usb),
                            "nfc" => Some(AuthenticatorTransport::Nfc),
                            "ble" => Some(AuthenticatorTransport::Ble),
                            "internal" => Some(AuthenticatorTransport::Internal),
                            _ => None,
                        }).collect()
                    }),
                }
            }).collect())
        } else {
            None // Username-less authentication
        };

        // Convert user verification policy
        let user_verification = request.user_verification.or_else(|| {
            match self.config.user_verification.as_str() {
                "required" => Some(UserVerificationPolicy::Required),
                "preferred" => Some(UserVerificationPolicy::Preferred),
                "discouraged" => Some(UserVerificationPolicy::Discouraged),
                _ => Some(UserVerificationPolicy::Preferred),
            }
        });

        // Create assertion options
        let credential_request_options = self.webauthn.start_authentication(
            allow_credentials.as_ref().map(|creds| {
                creds.iter().map(|cred| {
                    webauthn_rs::prelude::PublicKeyCredentialDescriptor {
                        type_: webauthn_rs::prelude::PublicKeyCredentialType::PublicKey,
                        id: general_purpose::URL_SAFE_NO_PAD.decode(&cred.id).unwrap_or_default(),
                        transports: cred.transports.as_ref().map(|t| {
                            t.iter().map(|transport| match transport {
                                AuthenticatorTransport::Usb => webauthn_rs::prelude::AuthenticatorTransport::Usb,
                                AuthenticatorTransport::Nfc => webauthn_rs::prelude::AuthenticatorTransport::Nfc,
                                AuthenticatorTransport::Ble => webauthn_rs::prelude::AuthenticatorTransport::Ble,
                                AuthenticatorTransport::Internal => webauthn_rs::prelude::AuthenticatorTransport::Internal,
                            }).collect()
                        }).unwrap_or_default(),
                    }
                }).collect()
            }),
            user_verification.as_ref().map(|uv| match uv {
                UserVerificationPolicy::Required => webauthn_rs::prelude::UserVerificationPolicy::Required,
                UserVerificationPolicy::Preferred => webauthn_rs::prelude::UserVerificationPolicy::Preferred,
                UserVerificationPolicy::Discouraged => webauthn_rs::prelude::UserVerificationPolicy::Discouraged,
            }),
            None, // extensions
        )?;

        // Generate session ID and store session data
        let session_id = self.generate_session_id();
        let challenge = credential_request_options.challenge.clone();
        let expires_at = Utc::now() + Duration::seconds(self.config.timeout as i64 / 1000);

        let session_data = SessionData {
            user_id: user.as_ref().map(|u| u.id),
            username: user.as_ref().map(|u| u.username.clone()),
            challenge: challenge.as_bytes().to_vec(),
            session_type: SessionType::Authentication,
            expires_at,
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
        };

        let new_session = NewAuthSession {
            session_id: session_id.clone(),
            challenge: session_data.challenge.clone(),
            user_id: session_data.user_id,
            session_type: "authentication".to_string(),
            expires_at,
            data: Some(serde_json::to_value(session_data)?),
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
        };

        self.session_repo.create_session(&new_session).await?;

        // Log audit event
        let audit_log = NewAuditLog {
            user_id: user.as_ref().map(|u| u.id),
            action: "assertion_started".to_string(),
            resource_type: Some("session".to_string()),
            resource_id: Some(session_id.clone()),
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
            success: true,
            error_message: None,
            metadata: Some(serde_json::json!({
                "username": user.as_ref().map(|u| &u.username),
                "session_type": "authentication"
            })),
        };

        self.audit_repo.create_log(&audit_log).await?;

        let response = AssertionOptionsResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge: general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes()),
            timeout: self.config.timeout,
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification,
            extensions: None, // TODO: Map extensions from request
        };

        Ok(response)
    }

    pub async fn finish_assertion(
        &self,
        request: AssertionResultRequest,
        context: &RequestContext,
    ) -> Result<AssertionResultResponse> {
        // Validate request
        request.validate()
            .map_err(|e| AppError::InvalidRequest(format!("Validation error: {}", e)))?;

        // Find session
        let session = self.session_repo.find_by_session_id(&request.session_id).await?
            .ok_or(AppError::SessionNotFound)?;

        // Check session expiration
        if session.expires_at < Utc::now() {
            self.session_repo.delete_session(&request.session_id).await?;
            return Err(AppError::SessionExpired);
        }

        // Verify session type
        if session.session_type != "authentication" {
            return Err(AppError::InvalidRequest("Invalid session type".to_string()));
        }

        // Parse session data
        let session_data: SessionData = serde_json::from_value(session.data.ok_or_else(|| {
            AppError::InvalidRequest("Session data missing".to_string())
        })?)?;

        // Parse credential response
        let credential_id = general_purpose::URL_SAFE_NO_PAD.decode(&request.credential_id)
            .map_err(|_| AppError::InvalidRequest("Invalid credential ID".to_string()))?;

        let client_data_json = general_purpose::URL_SAFE_NO_PAD.decode(&request.response.client_data_json)
            .map_err(|_| AppError::InvalidRequest("Invalid client data JSON".to_string()))?;

        let authenticator_data = general_purpose::URL_SAFE_NO_PAD.decode(&request.response.authenticator_data)
            .map_err(|_| AppError::InvalidRequest("Invalid authenticator data".to_string()))?;

        let signature = general_purpose::URL_SAFE_NO_PAD.decode(&request.response.signature)
            .map_err(|_| AppError::InvalidRequest("Invalid signature".to_string()))?;

        let user_handle = request.response.user_handle.as_ref()
            .and_then(|uh| general_purpose::URL_SAFE_NO_PAD.decode(uh).ok());

        // Find credential
        let credential = self.credential_repo.find_by_credential_id(&credential_id).await?
            .ok_or(AppError::CredentialNotFound)?;

        // Get user
        let user = self.user_repo.find_by_id(&credential.user_id).await?
            .ok_or(AppError::UserNotFound)?;

        // Create PublicKeyCredential
        let public_key_credential = PublicKeyCredential {
            id: credential_id.clone(),
            raw_id: credential_id.clone(),
            response: AuthenticatorAssertionResponseRaw {
                client_data_json: client_data_json.clone(),
                authenticator_data: authenticator_data.clone(),
                signature: signature.clone(),
                user_handle: user_handle.clone(),
            },
            type_: webauthn_rs::prelude::PublicKeyCredentialType::PublicKey,
            extensions: None,
            client_extension_results: Default::default(),
        };

        // Verify assertion
        let auth_result = self.webauthn.finish_authentication(
            &public_key_credential,
            &session_data.challenge,
            &webauthn_rs::prelude::AuthenticationResult {
                credential_data: webauthn_rs::prelude::Credential {
                    credential_id: credential_id.clone(),
                    public_key: credential.credential_public_key.clone(),
                    sign_count: credential.sign_count as u64,
                    aaguid: credential.aaguid.clone().unwrap_or_default(),
                    backup_eligible: credential.backup_eligible,
                    backup_state: credential.backup_state,
                },
                user_verified: true, // Will be verified by the library
            },
        )?;

        // Update credential sign count and last used
        self.credential_repo.update_sign_count(&credential_id, auth_result.credential_data.sign_count as i64).await?;
        self.credential_repo.update_last_used(&credential_id).await?;

        // Update user last login
        self.user_repo.update_last_login(&user.id).await?;

        // Clean up session
        self.session_repo.delete_session(&request.session_id).await?;

        // Log audit event
        let audit_log = NewAuditLog {
            user_id: Some(user.id),
            action: "assertion_completed".to_string(),
            resource_type: Some("credential".to_string()),
            resource_id: Some(general_purpose::URL_SAFE_NO_PAD.encode(&credential_id)),
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
            success: true,
            error_message: None,
            metadata: Some(serde_json::json!({
                "credential_id": general_purpose::URL_SAFE_NO_PAD.encode(&credential_id),
                "sign_count": auth_result.credential_data.sign_count,
                "user_verified": auth_result.user_verified
            })),
        };

        self.audit_repo.create_log(&audit_log).await?;

        let response = AssertionResultResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            credential_id: general_purpose::URL_SAFE_NO_PAD.encode(&credential_id),
            sign_count: auth_result.credential_data.sign_count as u32,
            user_verified: auth_result.user_verified,
            user_handle: user_handle.map(|uh| general_purpose::URL_SAFE_NO_PAD.encode(&uh)),
        };

        Ok(response)
    }

    fn generate_session_id(&self) -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
}