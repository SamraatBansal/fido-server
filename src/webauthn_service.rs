use crate::api::*;
use crate::error::{AppError, Result};
use crate::memory_storage::*;
use base64::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct WebAuthnService {
    webauthn: Arc<Webauthn>,
    storage: Arc<MemoryStorage>,
    rp_id: String,
    rp_name: String,
    rp_origin: String,
}

impl WebAuthnService {
    pub fn new(rp_id: &str, rp_name: &str, rp_origin: &str) -> Result<Self> {
        // Parse and validate origin
        let origin_url = url::Url::parse(rp_origin)
            .map_err(|e| AppError::ValidationError(format!("Invalid RP origin: {}", e)))?;

        // Build WebAuthn instance
        let webauthn = WebauthnBuilder::new(rp_id, &origin_url)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?
            .rp_name(rp_name)
            .build()
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
            storage: Arc::new(MemoryStorage::new()),
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            rp_origin: rp_origin.to_string(),
        })
    }

    pub async fn start_registration(
        &self,
        request: &ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate input
        if request.username.trim().is_empty() {
            return Err(AppError::ValidationError("username cannot be empty".to_string()));
        }
        if request.display_name.trim().is_empty() {
            return Err(AppError::ValidationError("displayName cannot be empty".to_string()));
        }

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

        // Convert to webauthn-rs types
        let exclude_credentials: Vec<CredentialID> = existing_credentials
            .iter()
            .map(|cred| CredentialID::from(cred.credential_id.clone()))
            .collect();

        // Parse authenticator selection
        let authenticator_selection = if let Some(auth_sel) = &request.authenticator_selection {
            Self::parse_authenticator_selection(auth_sel)?
        } else {
            None
        };

        // Parse attestation
        let attestation = request.attestation.as_ref()
            .map(|att| Self::parse_attestation_conveyance(att))
            .transpose()?
            .unwrap_or(AttestationConveyancePreference::None);

        // Parse extensions
        let extensions = request.extensions.as_ref()
            .map(|ext| Self::parse_extensions(ext))
            .transpose()?;

        // Start registration with webauthn-rs
        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                user_id,
                &request.username,
                &request.display_name,
                exclude_credentials,
            )
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Store registration state
        let state_data = serde_json::to_vec(&reg_state)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize state: {}", e)))?;
        
        let challenge_context = serde_json::json!({
            "user_id": user_id,
            "username": request.username,
            "display_name": request.display_name,
            "state": state_data
        });
        let challenge_data = serde_json::to_vec(&challenge_context)?;
        let _challenge_id = self.storage.store_challenge(user_id, "registration", &challenge_data)?;

        // Convert response format
        let response = Self::convert_creation_challenge_response(
            ccr,
            &request.username,
            &request.display_name,
            user_id,
            request.authenticator_selection.clone(),
            request.attestation.clone(),
            request.extensions.clone(),
            &self.rp_name,
            &self.rp_id,
        )?;

        Ok(response)
    }

    pub async fn finish_registration(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Comprehensive validation for FIDO conformance
        Self::validate_credential_structure(credential)?;

        let response = match &credential.response {
            ServerAuthenticatorResponse::Attestation(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected attestation response".to_string())),
        };

        // Validate response structure
        Self::validate_attestation_response_structure(response)?;

        // Convert to webauthn-rs format
        let reg_credential = Self::convert_registration_credential(credential)?;

        // Find stored challenge
        let stored_challenge = self.storage.get_challenge("registration")?
            .ok_or(AppError::ChallengeExpired)?;

        // Deserialize challenge context
        let challenge_context: serde_json::Value = serde_json::from_slice(&stored_challenge.challenge_data)?;
        let user_id: Uuid = serde_json::from_value(challenge_context["user_id"].clone())?;
        let username = challenge_context["username"].as_str().unwrap_or("unknown");
        let display_name = challenge_context["display_name"].as_str().unwrap_or("Unknown User");
        let state_data: Vec<u8> = serde_json::from_value(challenge_context["state"].clone())?;
        
        let reg_state: PasskeyRegistration = serde_json::from_slice(&state_data)
            .map_err(|e| AppError::InternalError(format!("Failed to deserialize state: {}", e)))?;

        // Finish registration with webauthn-rs
        let passkey = self
            .webauthn
            .finish_passkey_registration(&reg_credential, &reg_state)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Store user if doesn't exist
        let existing_user = self.storage.get_user_by_id(user_id)?;
        if existing_user.is_none() {
            self.storage.store_user_with_id(user_id, username, display_name)?;
        }

        // Store credential
        let cred_id = passkey.cred_id().0.clone();
        let public_key = passkey.cred().cose_key.clone();
        self.storage.store_credential(user_id, &cred_id, &public_key)?;

        // Clean up challenge
        self.storage.remove_challenge(stored_challenge.id)?;

        Ok(ServerResponse::success())
    }

    pub async fn start_authentication(
        &self,
        request: &ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate input
        if request.username.trim().is_empty() {
            return Err(AppError::ValidationError("username cannot be empty".to_string()));
        }

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

        // Convert to webauthn-rs types
        let allowed_credentials: Vec<CredentialID> = user_credentials
            .iter()
            .map(|cred| CredentialID::from(cred.credential_id.clone()))
            .collect();

        // Parse user verification
        let user_verification = request.user_verification.as_ref()
            .map(|uv| Self::parse_user_verification(uv))
            .transpose()?
            .unwrap_or(UserVerificationPolicy::Preferred);

        // Parse extensions
        let extensions = request.extensions.as_ref()
            .map(|ext| Self::parse_extensions(ext))
            .transpose()?;

        // Start authentication with webauthn-rs
        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&allowed_credentials)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Store authentication state
        let state_data = serde_json::to_vec(&auth_state)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize state: {}", e)))?;
        
        let challenge_context = serde_json::json!({
            "user_id": user.id,
            "state": state_data
        });
        let challenge_data = serde_json::to_vec(&challenge_context)?;
        let _challenge_id = self.storage.store_challenge(user.id, "authentication", &challenge_data)?;

        // Convert response format
        let response = Self::convert_request_challenge_response(
            rcr,
            &self.rp_id,
            request.user_verification.clone(),
            request.extensions.clone(),
        )?;

        Ok(response)
    }

    pub async fn finish_authentication(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Comprehensive validation for FIDO conformance
        Self::validate_credential_structure(credential)?;

        let response = match &credential.response {
            ServerAuthenticatorResponse::Assertion(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected assertion response".to_string())),
        };

        // Validate response structure
        Self::validate_assertion_response_structure(response)?;

        // Convert to webauthn-rs format
        let auth_credential = Self::convert_authentication_credential(credential)?;

        // Find stored challenge
        let stored_challenge = self.storage.get_challenge("authentication")?
            .ok_or(AppError::ChallengeExpired)?;

        // Deserialize challenge context
        let challenge_context: serde_json::Value = serde_json::from_slice(&stored_challenge.challenge_data)?;
        let user_id: Uuid = serde_json::from_value(challenge_context["user_id"].clone())?;
        let state_data: Vec<u8> = serde_json::from_value(challenge_context["state"].clone())?;
        
        let auth_state: PasskeyAuthentication = serde_json::from_slice(&state_data)
            .map_err(|e| AppError::InternalError(format!("Failed to deserialize state: {}", e)))?;

        // Get stored credentials for verification
        let user_credentials = self.storage.get_credentials_for_user(user_id)?;
        let passkeys: Vec<Passkey> = user_credentials
            .iter()
            .map(|cred| {
                // This is a simplified conversion - in real implementation, 
                // we'd store the full passkey data properly
                // For now, create a minimal passkey structure
                todo!("Convert stored credential to Passkey - requires proper storage of passkey data")
            })
            .collect();

        // Finish authentication with webauthn-rs
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(&auth_credential, &auth_state)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Update credential counter if needed
        // In real implementation, we'd update the sign count

        // Clean up challenge
        self.storage.remove_challenge(stored_challenge.id)?;

        Ok(ServerResponse::success())
    }

    // Helper methods for parsing and conversion
    fn parse_authenticator_selection(value: &serde_json::Value) -> Result<Option<AuthenticatorSelectionCriteria>> {
        // Implementation would parse the JSON value into AuthenticatorSelectionCriteria
        // For now, return None for simplicity
        Ok(None)
    }

    fn parse_attestation_conveyance(value: &str) -> Result<AttestationConveyancePreference> {
        match value {
            "none" => Ok(AttestationConveyancePreference::None),
            "indirect" => Ok(AttestationConveyancePreference::Indirect),
            "direct" => Ok(AttestationConveyancePreference::Direct),
            _ => Err(AppError::ValidationError(format!("Invalid attestation preference: {}", value))),
        }
    }

    fn parse_user_verification(value: &str) -> Result<UserVerificationPolicy> {
        match value {
            "required" => Ok(UserVerificationPolicy::Required),
            "preferred" => Ok(UserVerificationPolicy::Preferred),
            "discouraged" => Ok(UserVerificationPolicy::Discouraged),
            _ => Err(AppError::ValidationError(format!("Invalid user verification: {}", value))),
        }
    }

    fn parse_extensions(_value: &HashMap<String, serde_json::Value>) -> Result<Option<RequestRegistrationExtensions>> {
        // For now, return None - would implement extension parsing here
        Ok(None)
    }

    fn validate_credential_structure(credential: &ServerPublicKeyCredential) -> Result<()> {
        if credential.id.is_empty() {
            return Err(AppError::MissingField("id".to_string()));
        }
        if credential.type_ != "public-key" {
            return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
        }
        Ok(())
    }

    fn validate_attestation_response_structure(response: &ServerAuthenticatorAttestationResponse) -> Result<()> {
        if response.client_data_json.is_empty() {
            return Err(AppError::MissingField("clientDataJSON".to_string()));
        }
        if response.attestation_object.is_empty() {
            return Err(AppError::MissingField("attestationObject".to_string()));
        }
        Ok(())
    }

    fn validate_assertion_response_structure(response: &ServerAuthenticatorAssertionResponse) -> Result<()> {
        if response.client_data_json.is_empty() {
            return Err(AppError::MissingField("clientDataJSON".to_string()));
        }
        if response.authenticator_data.is_empty() {
            return Err(AppError::MissingField("authenticatorData".to_string()));
        }
        if response.signature.is_empty() {
            return Err(AppError::MissingField("signature".to_string()));
        }
        Ok(())
    }

    fn convert_registration_credential(credential: &ServerPublicKeyCredential) -> Result<RegisterPublicKeyCredential> {
        let response = match &credential.response {
            ServerAuthenticatorResponse::Attestation(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected attestation response".to_string())),
        };

        let id_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|_| AppError::InvalidField("Invalid credential id encoding".to_string()))?;
        
        let client_data_json = BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json)
            .map_err(|_| AppError::InvalidField("Invalid clientDataJSON encoding".to_string()))?;
        
        let attestation_object = BASE64_URL_SAFE_NO_PAD.decode(&response.attestation_object)
            .map_err(|_| AppError::InvalidField("Invalid attestationObject encoding".to_string()))?;

        Ok(RegisterPublicKeyCredential {
            id: credential.id.clone(),
            raw_id: id_bytes,
            response: AuthenticatorAttestationResponseRaw {
                client_data_json,
                attestation_object,
            },
            type_: "public-key".to_string(),
        })
    }

    fn convert_authentication_credential(credential: &ServerPublicKeyCredential) -> Result<PublicKeyCredential> {
        let response = match &credential.response {
            ServerAuthenticatorResponse::Assertion(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected assertion response".to_string())),
        };

        let id_bytes = BASE64_URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|_| AppError::InvalidField("Invalid credential id encoding".to_string()))?;
        
        let client_data_json = BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json)
            .map_err(|_| AppError::InvalidField("Invalid clientDataJSON encoding".to_string()))?;
        
        let authenticator_data = BASE64_URL_SAFE_NO_PAD.decode(&response.authenticator_data)
            .map_err(|_| AppError::InvalidField("Invalid authenticatorData encoding".to_string()))?;
        
        let signature = BASE64_URL_SAFE_NO_PAD.decode(&response.signature)
            .map_err(|_| AppError::InvalidField("Invalid signature encoding".to_string()))?;

        let user_handle = if response.user_handle.is_empty() {
            None
        } else {
            Some(BASE64_URL_SAFE_NO_PAD.decode(&response.user_handle)
                .map_err(|_| AppError::InvalidField("Invalid userHandle encoding".to_string()))?)
        };

        Ok(PublicKeyCredential {
            id: credential.id.clone(),
            raw_id: id_bytes,
            response: AuthenticatorAssertionResponseRaw {
                client_data_json,
                authenticator_data,
                signature,
                user_handle,
            },
            type_: "public-key".to_string(),
            extensions: AuthenticationExtensionsClientOutputs::default(),
        })
    }

    fn convert_creation_challenge_response(
        ccr: RequestChallengeResponse,
        username: &str,
        display_name: &str,
        user_id: Uuid,
        authenticator_selection: Option<serde_json::Value>,
        attestation: Option<String>,
        extensions: Option<HashMap<String, serde_json::Value>>,
        rp_name: &str,
        rp_id: &str,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Convert webauthn-rs challenge response to our API format
        let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(&ccr.public_key.challenge);
        
        let pub_key_cred_params: Vec<PublicKeyCredentialParameters> = ccr
            .public_key
            .pub_key_cred_params
            .iter()
            .map(|param| PublicKeyCredentialParameters {
                type_: param.type_.clone(),
                alg: param.alg as i64,
            })
            .collect();

        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = ccr
            .public_key
            .exclude_credentials
            .unwrap_or_default()
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: cred.type_.clone(),
                id: BASE64_URL_SAFE_NO_PAD.encode(&cred.id),
                transports: cred.transports.as_ref().map(|t| t.iter().map(|tr| tr.to_string()).collect()),
            })
            .collect();

        Ok(ServerPublicKeyCredentialCreationOptionsResponse::new(
            PublicKeyCredentialRpEntity {
                id: Some(rp_id.to_string()),
                name: rp_name.to_string(),
            },
            ServerPublicKeyCredentialUserEntity {
                id: BASE64_URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
                name: username.to_string(),
                display_name: display_name.to_string(),
            },
            challenge_b64,
            pub_key_cred_params,
            exclude_credentials,
            authenticator_selection,
            attestation,
            ccr.public_key.timeout.map(|t| t as u32),
            extensions,
        ))
    }

    fn convert_request_challenge_response(
        rcr: RequestChallengeResponse,
        rp_id: &str,
        user_verification: Option<String>,
        extensions: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(&rcr.public_key.challenge);
        
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = rcr
            .public_key
            .allow_credentials
            .unwrap_or_default()
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: cred.type_.clone(),
                id: BASE64_URL_SAFE_NO_PAD.encode(&cred.id),
                transports: cred.transports.as_ref().map(|t| t.iter().map(|tr| tr.to_string()).collect()),
            })
            .collect();

        Ok(ServerPublicKeyCredentialGetOptionsResponse::new(
            challenge_b64,
            rp_id.to_string(),
            allow_credentials,
            user_verification,
            rcr.public_key.timeout.map(|t| t as u32),
            extensions,
        ))
    }
}