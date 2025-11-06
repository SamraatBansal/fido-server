use crate::api::*;
use crate::error::{AppError, Result};
use crate::memory_storage::*;
use base64::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs::{Webauthn, WebauthnBuilder};
use serde_json::Value;

#[derive(Clone)]
pub struct WebAuthnService {
    webauthn: Webauthn,
    storage: Arc<MemoryStorage>,
}

impl WebAuthnService {
    pub fn new(rp_id: &str, rp_name: &str, rp_origin: &str) -> Result<Self> {
        // Parse origin URL
        let origin_url = url::Url::parse(rp_origin)
            .map_err(|e| AppError::ValidationError(format!("Invalid RP origin: {}", e)))?;

        // Build WebAuthn instance
        let webauthn = WebauthnBuilder::new(rp_id, &origin_url)
            .map_err(|e| AppError::WebAuthnError(format!("WebAuthn builder error: {:?}", e)))?
            .rp_name(rp_name)
            .build()
            .map_err(|e| AppError::WebAuthnError(format!("WebAuthn build error: {:?}", e)))?;

        Ok(Self {
            webauthn,
            storage: Arc::new(MemoryStorage::new()),
        })
    }

    pub async fn start_registration(
        &self,
        request: &ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate input
        crate::error::validate_string_not_empty(&request.username, "username")?;
        crate::error::validate_string_not_empty(&request.display_name, "displayName")?;

        // Clean up expired challenges
        self.storage.cleanup_expired_challenges()?;

        // Check if user exists and get existing credentials
        let existing_user = self.storage.get_user_by_username(&request.username)?;

        let user_id = match &existing_user {
            Some(user) => user.id,
            None => Uuid::new_v4(),
        };

        // Get existing credentials for excludeCredentials
        let existing_credentials = if existing_user.is_some() {
            self.storage.get_credentials_for_user(user_id)?
        } else {
            Vec::new()
        };

        let exclude_credentials: Vec<CredentialID> = existing_credentials
            .iter()
            .map(|cred| CredentialID::from(cred.credential_id.clone()))
            .collect();

        // Convert authenticator selection criteria
        let authenticator_selection = if let Some(auth_sel) = &request.authenticator_selection {
            self.parse_authenticator_selection(auth_sel)?
        } else {
            AuthenticatorSelectionCriteria::default()
        };

        // Convert attestation preference
        let attestation = if let Some(att) = &request.attestation {
            match att.as_str() {
                "none" => AttestationConveyancePreference::None,
                "indirect" => AttestationConveyancePreference::Indirect,
                "direct" => AttestationConveyancePreference::Direct,
                "enterprise" => AttestationConveyancePreference::Enterprise,
                _ => AttestationConveyancePreference::None,
            }
        } else {
            AttestationConveyancePreference::None
        };

        // Start registration with webauthn-rs
        let (ccr, reg_state) = self.webauthn
            .start_passkey_registration(
                user_id,
                &request.username,
                &request.display_name,
                Some(exclude_credentials),
                Some(authenticator_selection),
                Some(attestation),
            )
            .map_err(|e| AppError::WebAuthnError(format!("Start registration error: {:?}", e)))?;

        // Store challenge state
        let challenge_data = serde_json::to_vec(&reg_state)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize reg state: {}", e)))?;
        let challenge_context = serde_json::json!({
            "user_id": user_id,
            "username": request.username,
            "display_name": request.display_name,
            "reg_state": BASE64_URL_SAFE_NO_PAD.encode(&challenge_data)
        });
        let challenge_data = serde_json::to_vec(&challenge_context)?;
        self.storage.store_challenge(user_id, "registration", &challenge_data)?;

        // Convert to server response format
        let exclude_creds: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: BASE64_URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            })
            .collect();

        // Prepare extensions
        let mut extensions = HashMap::new();
        if let Some(req_ext) = &request.extensions {
            extensions = req_ext.clone();
        }

        let response = ServerPublicKeyCredentialCreationOptionsResponse::new(
            PublicKeyCredentialRpEntity {
                id: Some(ccr.public_key.rp.id),
                name: ccr.public_key.rp.name,
            },
            ServerPublicKeyCredentialUserEntity {
                id: BASE64_URL_SAFE_NO_PAD.encode(&ccr.public_key.user.id),
                name: ccr.public_key.user.name,
                display_name: ccr.public_key.user.display_name,
            },
            BASE64_URL_SAFE_NO_PAD.encode(&ccr.public_key.challenge),
            ccr.public_key.pub_key_cred_params
                .into_iter()
                .map(|p| PublicKeyCredentialParameters {
                    type_: "public-key".to_string(),
                    alg: p.alg as i64,
                })
                .collect(),
            exclude_creds,
            request.authenticator_selection.clone(),
            request.attestation.clone(),
            ccr.public_key.timeout.map(|t| t as u32),
            Some(extensions),
        );

        Ok(response)
    }

    pub async fn finish_registration(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Comprehensive validation
        self.validate_credential_structure(credential)?;

        let response = match &credential.response {
            ServerAuthenticatorResponse::Attestation(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected attestation response".to_string())),
        };

        // Additional validation for attestation response
        self.validate_attestation_response(response)?;

        // Decode credential ID and get challenge
        let credential_id_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?;
        let client_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json)?;
        let attestation_object_bytes = BASE64_URL_SAFE_NO_PAD.decode(&response.attestation_object)?;

        // Parse client data to get challenge
        let client_data: Value = serde_json::from_slice(&client_data_bytes)?;
        let challenge_b64 = client_data["challenge"].as_str()
            .ok_or_else(|| AppError::MissingField("challenge".to_string()))?;
        let _challenge_bytes = BASE64_URL_SAFE_NO_PAD.decode(challenge_b64)?;

        // Find stored challenge
        let stored_challenge = self.storage.get_challenge("registration")?
            .ok_or(AppError::ChallengeExpired)?;

        // Deserialize stored challenge context
        let challenge_context: Value = serde_json::from_slice(&stored_challenge.challenge_data)?;
        let user_id: Uuid = serde_json::from_value(challenge_context["user_id"].clone())?;
        let username = challenge_context["username"].as_str().unwrap_or("unknown");
        let display_name = challenge_context["display_name"].as_str().unwrap_or("Unknown User");
        let reg_state_b64 = challenge_context["reg_state"].as_str()
            .ok_or_else(|| AppError::InternalError("Missing reg_state in challenge".to_string()))?;

        // Decode registration state
        let reg_state_bytes = BASE64_URL_SAFE_NO_PAD.decode(reg_state_b64)?;
        let reg_state: PasskeyRegistration = serde_json::from_slice(&reg_state_bytes)
            .map_err(|e| AppError::InternalError(format!("Failed to deserialize reg state: {}", e)))?;

        // Convert to webauthn-rs format
        let reg_credential = RegisterPublicKeyCredential {
            id: credential.id.clone(),
            raw_id: credential_id_bytes,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: attestation_object_bytes,
                client_data_json: client_data_bytes,
            },
            type_: "public-key".to_string(),
            extensions: credential.get_client_extension_results.clone().unwrap_or_default(),
        };

        // Finish registration with webauthn-rs
        let passkey = self.webauthn
            .finish_passkey_registration(&reg_credential, &reg_state)
            .map_err(|e| AppError::WebAuthnError(format!("Finish registration error: {:?}", e)))?;

        // Store or update user
        let existing_user = self.storage.get_user_by_id(user_id)?;
        if existing_user.is_none() {
            self.storage.store_user_with_id(user_id, username, display_name)?;
        }

        // Store credential
        self.storage.store_credential(user_id, passkey.cred_id(), &passkey.cred().cose_key)?;

        // Clean up challenge
        self.storage.remove_challenge(stored_challenge.id)?;

        Ok(ServerResponse::success())
    }

    pub async fn start_authentication(
        &self,
        request: &ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate input
        crate::error::validate_string_not_empty(&request.username, "username")?;

        // Clean up expired challenges
        self.storage.cleanup_expired_challenges()?;

        // Find user
        let user = self.storage.get_user_by_username(&request.username)?
            .ok_or(AppError::UserNotFound)?;

        // Get user credentials
        let user_credentials = self.storage.get_credentials_for_user(user.id)?;

        if user_credentials.is_empty() {
            return Err(AppError::CredentialNotFound);
        }

        // Convert to webauthn-rs format
        let allow_credentials: Vec<CredentialID> = user_credentials
            .iter()
            .map(|cred| CredentialID::from(cred.credential_id.clone()))
            .collect();

        // Parse user verification requirement
        let user_verification = if let Some(uv) = &request.user_verification {
            match uv.as_str() {
                "required" => UserVerificationPolicy::Required,
                "preferred" => UserVerificationPolicy::Preferred,
                "discouraged" => UserVerificationPolicy::Discouraged,
                _ => UserVerificationPolicy::Preferred,
            }
        } else {
            UserVerificationPolicy::Preferred
        };

        // Start authentication with webauthn-rs
        let (ccr, auth_state) = self.webauthn
            .start_passkey_authentication(&allow_credentials, Some(user_verification))
            .map_err(|e| AppError::WebAuthnError(format!("Start authentication error: {:?}", e)))?;

        // Store challenge state
        let challenge_data = serde_json::to_vec(&auth_state)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize auth state: {}", e)))?;
        let challenge_context = serde_json::json!({
            "user_id": user.id,
            "auth_state": BASE64_URL_SAFE_NO_PAD.encode(&challenge_data)
        });
        let challenge_data = serde_json::to_vec(&challenge_context)?;
        self.storage.store_challenge(user.id, "authentication", &challenge_data)?;

        // Convert to server response format
        let allow_creds: Vec<ServerPublicKeyCredentialDescriptor> = user_credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: BASE64_URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            })
            .collect();

        let response = ServerPublicKeyCredentialGetOptionsResponse::new(
            BASE64_URL_SAFE_NO_PAD.encode(&ccr.public_key.challenge),
            ccr.public_key.rp_id,
            allow_creds,
            request.user_verification.clone(),
            ccr.public_key.timeout.map(|t| t as u32),
            request.extensions.clone(),
        );

        Ok(response)
    }

    pub async fn finish_authentication(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Comprehensive validation
        self.validate_credential_structure(credential)?;

        let response = match &credential.response {
            ServerAuthenticatorResponse::Assertion(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected assertion response".to_string())),
        };

        // Additional validation for assertion response
        self.validate_assertion_response(response)?;

        // Decode fields
        let credential_id_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.id)?;
        let client_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json)?;
        let authenticator_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(&response.authenticator_data)?;
        let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(&response.signature)?;
        let user_handle_bytes = if !response.user_handle.is_empty() {
            Some(BASE64_URL_SAFE_NO_PAD.decode(&response.user_handle)?)
        } else {
            None
        };

        // Find stored challenge
        let stored_challenge = self.storage.get_challenge("authentication")?
            .ok_or(AppError::ChallengeExpired)?;

        // Deserialize stored challenge context
        let challenge_context: Value = serde_json::from_slice(&stored_challenge.challenge_data)?;
        let user_id: Uuid = serde_json::from_value(challenge_context["user_id"].clone())?;
        let auth_state_b64 = challenge_context["auth_state"].as_str()
            .ok_or_else(|| AppError::InternalError("Missing auth_state in challenge".to_string()))?;

        // Decode authentication state
        let auth_state_bytes = BASE64_URL_SAFE_NO_PAD.decode(auth_state_b64)?;
        let auth_state: PasskeyAuthentication = serde_json::from_slice(&auth_state_bytes)
            .map_err(|e| AppError::InternalError(format!("Failed to deserialize auth state: {}", e)))?;

        // Convert to webauthn-rs format
        let auth_credential = PublicKeyCredential {
            id: credential.id.clone(),
            raw_id: credential_id_bytes,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: authenticator_data_bytes,
                client_data_json: client_data_bytes,
                signature: signature_bytes,
                user_handle: user_handle_bytes,
            },
            type_: "public-key".to_string(),
            extensions: credential.get_client_extension_results.clone().unwrap_or_default(),
        };

        // Finish authentication with webauthn-rs
        let _auth_result = self.webauthn
            .finish_passkey_authentication(&auth_credential, &auth_state)
            .map_err(|e| AppError::AuthenticationFailed)?;

        // Clean up challenge
        self.storage.remove_challenge(stored_challenge.id)?;

        Ok(ServerResponse::success())
    }

    // Helper methods for validation and parsing

    fn validate_credential_structure(&self, credential: &ServerPublicKeyCredential) -> Result<()> {
        // Validate credential ID field
        if credential.id.is_empty() {
            return Err(AppError::MissingField("id".to_string()));
        }
        
        // Validate base64url encoding of credential ID
        if !is_valid_base64url(&credential.id) {
            return Err(AppError::InvalidField("id is not valid base64url".to_string()));
        }
        
        // Validate type field
        if credential.type_ != "public-key" {
            return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
        }

        Ok(())
    }

    fn validate_attestation_response(&self, response: &ServerAuthenticatorAttestationResponse) -> Result<()> {
        // Validate clientDataJSON
        if response.client_data_json.is_empty() {
            return Err(AppError::InvalidField("clientDataJSON cannot be empty".to_string()));
        }
        
        // Validate base64url encoding of clientDataJSON
        let client_data_bytes = match BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json) {
            Ok(bytes) => bytes,
            Err(_) => return Err(AppError::InvalidField("clientDataJSON is not valid base64url".to_string())),
        };
        
        // Parse and validate client data JSON structure
        let client_data: Value = match serde_json::from_slice(&client_data_bytes) {
            Ok(data) => data,
            Err(_) => return Err(AppError::InvalidField("clientDataJSON is not valid JSON".to_string())),
        };
        
        // Validate type field in clientDataJSON
        match client_data.get("type") {
            Some(Value::String(type_val)) if type_val == "webauthn.create" => {},
            Some(Value::String(type_val)) => {
                return Err(AppError::InvalidField(format!("clientDataJSON.type must be 'webauthn.create', got: {}", type_val)));
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.type must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.type".to_string()));
            }
        }
        
        // Validate challenge field in clientDataJSON
        match client_data.get("challenge") {
            Some(Value::String(challenge)) if !challenge.is_empty() => {
                if !is_valid_base64url(challenge) {
                    return Err(AppError::InvalidField("clientDataJSON.challenge is not valid base64url".to_string()));
                }
            },
            Some(Value::String(_)) => {
                return Err(AppError::InvalidField("clientDataJSON.challenge cannot be empty".to_string()));
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.challenge must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.challenge".to_string()));
            }
        }
        
        // Validate origin field in clientDataJSON
        match client_data.get("origin") {
            Some(Value::String(origin)) if !origin.is_empty() => {},
            Some(Value::String(_)) => {
                return Err(AppError::InvalidField("clientDataJSON.origin cannot be empty".to_string()));
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.origin must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.origin".to_string()));
            }
        }
        
        // Validate tokenBinding if present
        if let Some(token_binding) = client_data.get("tokenBinding") {
            if !token_binding.is_object() {
                return Err(AppError::InvalidField("clientDataJSON.tokenBinding must be an object".to_string()));
            }
            
            let token_binding_obj = token_binding.as_object().unwrap();
            match token_binding_obj.get("status") {
                Some(Value::String(status)) => {
                    if !matches!(status.as_str(), "present" | "supported" | "not-supported") {
                        return Err(AppError::InvalidField("clientDataJSON.tokenBinding.status must be 'present', 'supported', or 'not-supported'".to_string()));
                    }
                },
                Some(_) => {
                    return Err(AppError::InvalidField("clientDataJSON.tokenBinding.status must be a string".to_string()));
                },
                None => {
                    return Err(AppError::MissingField("clientDataJSON.tokenBinding.status".to_string()));
                }
            }
        }
        
        // Validate attestationObject
        if response.attestation_object.is_empty() {
            return Err(AppError::InvalidField("attestationObject cannot be empty".to_string()));
        }
        
        // Validate base64url encoding of attestationObject
        match BASE64_URL_SAFE_NO_PAD.decode(&response.attestation_object) {
            Ok(_) => {},
            Err(_) => return Err(AppError::InvalidField("attestationObject is not valid base64url".to_string())),
        }

        Ok(())
    }

    fn validate_assertion_response(&self, response: &ServerAuthenticatorAssertionResponse) -> Result<()> {
        // Validate clientDataJSON
        if response.client_data_json.is_empty() {
            return Err(AppError::InvalidField("clientDataJSON cannot be empty".to_string()));
        }
        
        // Validate base64url encoding of clientDataJSON
        let client_data_bytes = match BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json) {
            Ok(bytes) => bytes,
            Err(_) => return Err(AppError::InvalidField("clientDataJSON is not valid base64url".to_string())),
        };
        
        // Parse and validate client data JSON structure
        let client_data: Value = match serde_json::from_slice(&client_data_bytes) {
            Ok(data) => data,
            Err(_) => return Err(AppError::InvalidField("clientDataJSON is not valid JSON".to_string())),
        };
        
        // Validate type field in clientDataJSON
        match client_data.get("type") {
            Some(Value::String(type_val)) if type_val == "webauthn.get" => {},
            Some(Value::String(type_val)) => {
                return Err(AppError::InvalidField(format!("clientDataJSON.type must be 'webauthn.get', got: {}", type_val)));
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.type must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.type".to_string()));
            }
        }
        
        // Validate challenge field in clientDataJSON
        match client_data.get("challenge") {
            Some(Value::String(challenge)) if !challenge.is_empty() => {
                if !is_valid_base64url(challenge) {
                    return Err(AppError::InvalidField("clientDataJSON.challenge is not valid base64url".to_string()));
                }
            },
            Some(Value::String(_)) => {
                return Err(AppError::InvalidField("clientDataJSON.challenge cannot be empty".to_string()));
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.challenge must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.challenge".to_string()));
            }
        }
        
        // Validate origin field in clientDataJSON
        match client_data.get("origin") {
            Some(Value::String(origin)) if !origin.is_empty() => {},
            Some(Value::String(_)) => {
                return Err(AppError::InvalidField("clientDataJSON.origin cannot be empty".to_string()));
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.origin must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.origin".to_string()));
            }
        }
        
        // Validate authenticatorData
        if response.authenticator_data.is_empty() {
            return Err(AppError::InvalidField("authenticatorData cannot be empty".to_string()));
        }
        
        // Validate base64url encoding of authenticatorData
        match BASE64_URL_SAFE_NO_PAD.decode(&response.authenticator_data) {
            Ok(_) => {},
            Err(_) => return Err(AppError::InvalidField("authenticatorData is not valid base64url".to_string())),
        }
        
        // Validate signature
        if response.signature.is_empty() {
            return Err(AppError::InvalidField("signature cannot be empty".to_string()));
        }
        
        // Validate base64url encoding of signature
        match BASE64_URL_SAFE_NO_PAD.decode(&response.signature) {
            Ok(_) => {},
            Err(_) => return Err(AppError::InvalidField("signature is not valid base64url".to_string())),
        }

        Ok(())
    }

    fn parse_authenticator_selection(&self, auth_sel: &Value) -> Result<AuthenticatorSelectionCriteria> {
        let mut criteria = AuthenticatorSelectionCriteria::default();

        if let Some(obj) = auth_sel.as_object() {
            if let Some(attachment) = obj.get("authenticatorAttachment") {
                if let Some(attachment_str) = attachment.as_str() {
                    criteria.authenticator_attachment = Some(match attachment_str {
                        "platform" => AuthenticatorAttachment::Platform,
                        "cross-platform" => AuthenticatorAttachment::CrossPlatform,
                        _ => AuthenticatorAttachment::CrossPlatform,
                    });
                }
            }

            if let Some(resident_key) = obj.get("requireResidentKey") {
                if let Some(rk_bool) = resident_key.as_bool() {
                    criteria.require_resident_key = rk_bool;
                }
            }

            if let Some(resident_key) = obj.get("residentKey") {
                if let Some(rk_str) = resident_key.as_str() {
                    criteria.resident_key = match rk_str {
                        "required" => ResidentKeyRequirement::Required,
                        "preferred" => ResidentKeyRequirement::Preferred,
                        "discouraged" => ResidentKeyRequirement::Discouraged,
                        _ => ResidentKeyRequirement::Discouraged,
                    };
                }
            }

            if let Some(user_verification) = obj.get("userVerification") {
                if let Some(uv_str) = user_verification.as_str() {
                    criteria.user_verification = match uv_str {
                        "required" => UserVerificationPolicy::Required,
                        "preferred" => UserVerificationPolicy::Preferred,
                        "discouraged" => UserVerificationPolicy::Discouraged,
                        _ => UserVerificationPolicy::Preferred,
                    };
                }
            }
        }

        Ok(criteria)
    }
}

// Helper function to validate base64url encoding
fn is_valid_base64url(input: &str) -> bool {
    // Check for valid base64url characters
    if input.chars().any(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_')) {
        return false;
    }
    
    // Try to decode to verify it's valid base64url
    BASE64_URL_SAFE_NO_PAD.decode(input).is_ok()
}