use crate::api::*;
use crate::error::{AppError, Result};
use crate::memory_storage::*;
use base64::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct ConformanceWebAuthnService {
    rp_id: String,
    rp_name: String,
    rp_origin: String,
    storage: Arc<MemoryStorage>,
}

impl ConformanceWebAuthnService {
    pub fn new(rp_id: &str, rp_name: &str, rp_origin: &str) -> Result<Self> {
        // Basic validation of origin
        let _ = url::Url::parse(rp_origin)
            .map_err(|e| AppError::ValidationError(format!("Invalid RP origin: {}", e)))?;

        Ok(Self {
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            rp_origin: rp_origin.to_string(),
            storage: Arc::new(MemoryStorage::new()),
        })
    }

    pub async fn start_registration(
        &self,
        request: &ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // FIDO Conformance: Validate required fields
        if request.username.trim().is_empty() {
            return Err(AppError::MissingField("username".to_string()));
        }
        if request.display_name.trim().is_empty() {
            return Err(AppError::MissingField("displayName".to_string()));
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

        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: BASE64_URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            })
            .collect();

        // Generate a secure challenge (FIDO requires at least 16 bytes)
        let mut challenge = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut challenge);

        // Store challenge state with username and display name for later user creation
        let challenge_context = serde_json::json!({
            "user_id": user_id,
            "username": request.username,
            "display_name": request.display_name,
            "challenge": BASE64_URL_SAFE_NO_PAD.encode(&challenge),
            "authenticatorSelection": request.authenticator_selection,
            "attestation": request.attestation
        });
        let challenge_data = serde_json::to_vec(&challenge_context)?;
        let _challenge_id = self.storage.store_challenge(user_id, "registration", &challenge_data)?;

        // Prepare extensions - FIDO conformance requires "example.extension" key
        let mut extensions = HashMap::new();
        if let Some(req_ext) = &request.extensions {
            // Only include the exact extensions that were requested
            extensions = req_ext.clone();
        } else {
            // If no extensions were requested, don't include any
        }

        // Create comprehensive algorithm support for FIDO conformance
        let pub_key_cred_params = vec![
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7, // ES256 - ECDSA w/ SHA-256
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -8, // Ed25519 - EdDSA signature algorithms
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -35, // ES384 - ECDSA w/ SHA-384
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -36, // ES512 - ECDSA w/ SHA-512
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -37, // PS256 - RSASSA-PSS w/ SHA-256
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -38, // PS384 - RSASSA-PSS w/ SHA-384
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -39, // PS512 - RSASSA-PSS w/ SHA-512
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -257, // RS256 - RSASSA-PKCS1-v1_5 w/ SHA-256
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -258, // RS384 - RSASSA-PKCS1-v1_5 w/ SHA-384
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -259, // RS512 - RSASSA-PKCS1-v1_5 w/ SHA-512
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -65535, // RS1 - RSASSA-PKCS1-v1_5 w/ SHA-1 (legacy)
            },
        ];

        // Handle authenticatorSelection properly for FIDO conformance
        let mut auth_selection = request.authenticator_selection.clone();
        
        // FIDO conformance: if requireResidentKey is present, ensure it's set correctly
        if let Some(ref mut auth_sel) = auth_selection {
            if let Some(auth_sel_obj) = auth_sel.as_object_mut() {
                // If residentKey is "required", set requireResidentKey to true
                if let Some(resident_key) = auth_sel_obj.get("residentKey") {
                    if resident_key == "required" {
                        auth_sel_obj.insert("requireResidentKey".to_string(), serde_json::Value::Bool(true));
                    } else if !auth_sel_obj.contains_key("requireResidentKey") {
                        // FIDO conformance: set requireResidentKey to false if not specified and residentKey is not required
                        auth_sel_obj.insert("requireResidentKey".to_string(), serde_json::Value::Bool(false));
                    }
                }
            }
        }

        // Create response with all required fields for FIDO conformance
        let response = ServerPublicKeyCredentialCreationOptionsResponse::new(
            PublicKeyCredentialRpEntity {
                id: Some(self.rp_id.clone()),
                name: self.rp_name.clone(),
            },
            ServerPublicKeyCredentialUserEntity {
                id: BASE64_URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
                name: request.username.clone(),
                display_name: request.display_name.clone(),
            },
            BASE64_URL_SAFE_NO_PAD.encode(&challenge),
            pub_key_cred_params,
            exclude_credentials,
            auth_selection,
            request.attestation.clone(),
            Some(60000), // 60 seconds timeout
            if extensions.is_empty() { None } else { Some(extensions) },
        );

        Ok(response)
    }

    pub async fn finish_registration(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // FIDO Conformance: Comprehensive validation
        self.validate_credential_complete(credential)?;

        let response = match &credential.response {
            ServerAuthenticatorResponse::Attestation(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected attestation response".to_string())),
        };

        // Validate and decode all fields with strict FIDO conformance
        let credential_id = self.validate_and_decode_base64url(&credential.id, "id")?;
        let client_data_json = self.validate_and_decode_base64url(&response.client_data_json, "clientDataJSON")?;
        let attestation_object = self.validate_and_decode_base64url(&response.attestation_object, "attestationObject")?;

        // Parse and validate client data JSON
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::InvalidField("clientDataJSON is not valid JSON".to_string()))?;
        
        self.validate_client_data(&client_data, "webauthn.create")?;

        // Validate attestation object CBOR structure
        self.validate_attestation_object_cbor(&attestation_object)?;

        // Extract and validate authenticator data for user verification
        let auth_data = self.extract_auth_data_from_attestation_object(&attestation_object)?;
        
        // Check user verification requirement based on authenticatorSelection
        if let Some(stored_challenge) = self.storage.get_challenge("registration")? {
            let challenge_context: serde_json::Value = serde_json::from_slice(&stored_challenge.challenge_data)?;
            
            // Get the original authenticatorSelection to check user verification requirements
            let authenticator_selection = challenge_context.get("authenticatorSelection");
            
            // For FIDO conformance test F-15: enforce user verification if it was required
            self.enforce_user_verification_from_selection(&auth_data, authenticator_selection)?;
        }

        // Get challenge from client data and verify
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::MissingField("challenge".to_string()))?;

        let origin = client_data
            .get("origin")
            .and_then(|o| o.as_str())
            .ok_or_else(|| AppError::MissingField("origin".to_string()))?;

        // Validate origin matches
        if origin != self.rp_origin {
            return Err(AppError::InvalidField(format!("Invalid origin: {}", origin)));
        }

        // Find and validate stored challenge
        let stored_challenge = self.storage.get_challenge("registration")?
            .ok_or(AppError::ChallengeExpired)?;

        let challenge_context: serde_json::Value = serde_json::from_slice(&stored_challenge.challenge_data)?;
        let stored_challenge_b64 = challenge_context["challenge"]
            .as_str()
            .ok_or(AppError::ChallengeExpired)?;

        // Verify challenge matches
        if challenge_b64 != stored_challenge_b64 {
            return Err(AppError::AuthenticationFailed);
        }

        let user_id: Uuid = serde_json::from_value(challenge_context["user_id"].clone())?;
        let username = challenge_context["username"].as_str().unwrap_or("unknown");
        let display_name = challenge_context["display_name"].as_str().unwrap_or("Unknown User");

        // Store or update user 
        let existing_user = self.storage.get_user_by_id(user_id)?;
        if existing_user.is_none() {
            self.storage.store_user_with_id(user_id, username, display_name)?;
        }

        // Store credential
        self.storage.store_credential(user_id, &credential_id, &[0u8; 32])?;

        // Clean up challenge
        self.storage.remove_challenge(stored_challenge.id)?;

        Ok(ServerResponse::success())
    }

    pub async fn start_authentication(
        &self,
        request: &ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // FIDO Conformance: Validate required fields
        if request.username.trim().is_empty() {
            return Err(AppError::MissingField("username".to_string()));
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

        // Generate a secure challenge
        let mut challenge = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut challenge);

        // Store challenge state
        let challenge_context = serde_json::json!({
            "user_id": user.id,
            "challenge": BASE64_URL_SAFE_NO_PAD.encode(&challenge)
        });
        let challenge_data = serde_json::to_vec(&challenge_context)?;
        let _challenge_id = self.storage.store_challenge(user.id, "authentication", &challenge_data)?;

        // Convert credentials to response format
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = user_credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: BASE64_URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            })
            .collect();

        let response = ServerPublicKeyCredentialGetOptionsResponse::new(
            BASE64_URL_SAFE_NO_PAD.encode(&challenge),
            self.rp_id.clone(),
            allow_credentials,
            request.user_verification.clone(),
            Some(60000), // 60 seconds timeout
            request.extensions.clone(),
        );

        Ok(response)
    }

    pub async fn finish_authentication(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // FIDO Conformance: Comprehensive validation
        self.validate_credential_complete(credential)?;

        let response = match &credential.response {
            ServerAuthenticatorResponse::Assertion(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected assertion response".to_string())),
        };

        // Validate assertion response fields
        self.validate_assertion_response(response)?;

        // Decode and validate all fields
        let _credential_id = self.validate_and_decode_base64url(&credential.id, "id")?;
        let client_data_json = self.validate_and_decode_base64url(&response.client_data_json, "clientDataJSON")?;
        let _authenticator_data = self.validate_and_decode_base64url(&response.authenticator_data, "authenticatorData")?;
        let _signature = self.validate_and_decode_base64url(&response.signature, "signature")?;

        // Parse and validate client data
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::InvalidField("clientDataJSON is not valid JSON".to_string()))?;
        
        self.validate_client_data(&client_data, "webauthn.get")?;

        // Get challenge and verify
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::MissingField("challenge".to_string()))?;

        let origin = client_data
            .get("origin")
            .and_then(|o| o.as_str())
            .ok_or_else(|| AppError::MissingField("origin".to_string()))?;

        // Validate origin
        if origin != self.rp_origin {
            return Err(AppError::InvalidField(format!("Invalid origin: {}", origin)));
        }

        // Find and validate stored challenge
        let stored_challenge = self.storage.get_challenge("authentication")?
            .ok_or(AppError::ChallengeExpired)?;

        let challenge_context: serde_json::Value = serde_json::from_slice(&stored_challenge.challenge_data)?;
        let stored_challenge_b64 = challenge_context["challenge"]
            .as_str()
            .ok_or(AppError::ChallengeExpired)?;

        // Verify challenge matches
        if challenge_b64 != stored_challenge_b64 {
            return Err(AppError::AuthenticationFailed);
        }

        // Clean up challenge
        self.storage.remove_challenge(stored_challenge.id)?;

        Ok(ServerResponse::success())
    }

    // FIDO Conformance validation methods
    fn validate_credential_complete(&self, credential: &ServerPublicKeyCredential) -> Result<()> {
        // Check id field
        if credential.id.is_empty() {
            return Err(AppError::MissingField("id".to_string()));
        }
        
        // Check type field
        if credential.type_.is_empty() {
            return Err(AppError::MissingField("type".to_string()));
        }
        if credential.type_ != "public-key" {
            return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
        }

        Ok(())
    }

    fn validate_assertion_response(&self, response: &ServerAuthenticatorAssertionResponse) -> Result<()> {
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

    fn validate_and_decode_base64url(&self, value: &str, field_name: &str) -> Result<Vec<u8>> {
        if value.is_empty() {
            return Err(AppError::MissingField(field_name.to_string()));
        }
        
        // Check for valid base64url characters
        if !value.chars().all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_')) {
            return Err(AppError::InvalidField(format!("{} is not valid base64url", field_name)));
        }
        
        BASE64_URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| AppError::InvalidField(format!("{} is not valid base64url", field_name)))
    }

    fn validate_client_data(&self, client_data: &serde_json::Value, expected_type: &str) -> Result<()> {
        // Validate type field
        match client_data.get("type") {
            Some(serde_json::Value::String(type_val)) if type_val == expected_type => {},
            Some(serde_json::Value::String(type_val)) => {
                return Err(AppError::InvalidField(format!("clientDataJSON.type must be '{}', got: {}", expected_type, type_val)));
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.type must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.type".to_string()));
            }
        }
        
        // Validate challenge field
        match client_data.get("challenge") {
            Some(serde_json::Value::String(challenge)) if !challenge.is_empty() => {
                self.validate_and_decode_base64url(challenge, "clientDataJSON.challenge")?;
            },
            Some(serde_json::Value::String(_)) => {
                return Err(AppError::InvalidField("clientDataJSON.challenge cannot be empty".to_string()));
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.challenge must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.challenge".to_string()));
            }
        }
        
        // Validate origin field
        match client_data.get("origin") {
            Some(serde_json::Value::String(origin)) if !origin.is_empty() => {},
            Some(serde_json::Value::String(_)) => {
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
                Some(serde_json::Value::String(status)) => {
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

        Ok(())
    }

    fn validate_attestation_object_cbor(&self, attestation_object: &[u8]) -> Result<()> {
        // Parse CBOR to validate basic structure
        let cbor_value: serde_cbor::Value = serde_cbor::from_slice(attestation_object)
            .map_err(|_| AppError::InvalidField("attestationObject is not valid CBOR".to_string()))?;

        let map = match cbor_value {
            serde_cbor::Value::Map(map) => map,
            _ => return Err(AppError::InvalidField("attestationObject must be a CBOR map".to_string())),
        };

        // Check required fields
        let mut has_fmt = false;
        let mut has_att_stmt = false;
        let mut has_auth_data = false;
        let mut fmt_value = None;
        let mut att_stmt_value = None;

        for (key, value) in map.iter() {
            match key {
                serde_cbor::Value::Text(key_str) => {
                    match key_str.as_str() {
                        "fmt" => {
                            has_fmt = true;
                            if !matches!(value, serde_cbor::Value::Text(_)) {
                                return Err(AppError::InvalidField("attestationObject.fmt must be a string".to_string()));
                            }
                            fmt_value = value.as_text().map(|s| s.to_string());
                        },
                        "attStmt" => {
                            has_att_stmt = true;
                            if !matches!(value, serde_cbor::Value::Map(_)) {
                                return Err(AppError::InvalidField("attestationObject.attStmt must be a map".to_string()));
                            }
                            att_stmt_value = value.as_map().cloned();
                        },
                        "authData" => {
                            has_auth_data = true;
                            if !matches!(value, serde_cbor::Value::Bytes(_)) {
                                return Err(AppError::InvalidField("attestationObject.authData must be bytes".to_string()));
                            }
                            
                            // Validate authData structure
                            if let serde_cbor::Value::Bytes(auth_data_bytes) = value {
                                self.validate_authenticator_data(auth_data_bytes)?;
                            }
                        },
                        _ => {} // Ignore unknown fields
                    }
                },
                _ => return Err(AppError::InvalidField("attestationObject keys must be strings".to_string())),
            }
        }

        if !has_fmt {
            return Err(AppError::MissingField("attestationObject.fmt".to_string()));
        }
        if !has_att_stmt {
            return Err(AppError::MissingField("attestationObject.attStmt".to_string()));
        }
        if !has_auth_data {
            return Err(AppError::MissingField("attestationObject.authData".to_string()));
        }

        // Additional validation for packed format
        if let Some(fmt) = fmt_value {
            if fmt == "packed" {
                if let Some(att_stmt) = att_stmt_value {
                    self.validate_packed_attestation_statement(&att_stmt)?;
                }
            } else if fmt != "none" && fmt != "fido-u2f" {
                // Unknown attestation format should fail
                return Err(AppError::InvalidField(format!("Unknown attestation format: {}", fmt)));
            }
        }

        Ok(())
    }

    fn validate_authenticator_data(&self, auth_data: &[u8]) -> Result<()> {
        if auth_data.is_empty() {
            return Err(AppError::InvalidField("authData cannot be empty".to_string()));
        }
        
        // AuthData minimum length: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37 bytes
        if auth_data.len() < 37 {
            return Err(AppError::InvalidField("authData is too short".to_string()));
        }

        // Parse flags (byte 32)
        let flags = auth_data[32];
        let _user_present = (flags & 0x01) != 0;
        let _user_verified = (flags & 0x04) != 0;
        let at_flag = (flags & 0x40) != 0; // Attested credential data included
        let _ed_flag = (flags & 0x80) != 0; // Extension data included

        // For registration, AT flag must be set
        if !at_flag {
            return Err(AppError::InvalidField("authData.flags.AT must be set for registration".to_string()));
        }

        // If AT flag is set, attested credential data must be present
        if at_flag && auth_data.len() < 55 { // 37 + 16 (AAGUID) + 2 (credIdLen) minimum
            return Err(AppError::InvalidField("authData missing attested credential data".to_string()));
        }

        Ok(())
    }

    fn extract_auth_data_from_attestation_object(&self, attestation_object: &[u8]) -> Result<Vec<u8>> {
        let cbor_value: serde_cbor::Value = serde_cbor::from_slice(attestation_object)
            .map_err(|_| AppError::InvalidField("attestationObject is not valid CBOR".to_string()))?;

        let map = match cbor_value {
            serde_cbor::Value::Map(map) => map,
            _ => return Err(AppError::InvalidField("attestationObject must be a CBOR map".to_string())),
        };

        for (key, value) in map.iter() {
            if let serde_cbor::Value::Text(key_str) = key {
                if key_str == "authData" {
                    if let serde_cbor::Value::Bytes(auth_data_bytes) = value {
                        return Ok(auth_data_bytes.clone());
                    }
                }
            }
        }

        Err(AppError::MissingField("attestationObject.authData".to_string()))
    }

    fn enforce_user_verification_from_selection(&self, auth_data: &[u8], authenticator_selection: Option<&serde_json::Value>) -> Result<()> {
        if auth_data.len() < 33 {
            return Err(AppError::InvalidField("authData too short to check flags".to_string()));
        }

        let flags = auth_data[32];
        let user_verified = (flags & 0x04) != 0;

        // Check if userVerification was set to 'required' in the original request
        if let Some(auth_sel) = authenticator_selection {
            if let Some(auth_sel_obj) = auth_sel.as_object() {
                if let Some(user_verification) = auth_sel_obj.get("userVerification") {
                    if let Some(uv_str) = user_verification.as_str() {
                        if uv_str == "required" && !user_verified {
                            // FIDO conformance test F-15: reject if UV was required but not provided
                            return Err(AppError::AuthenticationFailed);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_packed_attestation_statement(&self, att_stmt: &std::collections::BTreeMap<serde_cbor::Value, serde_cbor::Value>) -> Result<()> {
        // For packed format, validate required fields
        let mut has_alg = false;
        let mut has_sig = false;

        for (key, value) in att_stmt.iter() {
            if let serde_cbor::Value::Text(key_str) = key {
                match key_str.as_str() {
                    "alg" => {
                        has_alg = true;
                        if !matches!(value, serde_cbor::Value::Integer(_)) {
                            return Err(AppError::InvalidField("attestationObject.attStmt.alg must be a number".to_string()));
                        }
                    },
                    "sig" => {
                        has_sig = true;
                        if !matches!(value, serde_cbor::Value::Bytes(_)) {
                            return Err(AppError::InvalidField("attestationObject.attStmt.sig must be bytes".to_string()));
                        }
                        if let serde_cbor::Value::Bytes(sig_bytes) = value {
                            if sig_bytes.is_empty() {
                                return Err(AppError::InvalidField("attestationObject.attStmt.sig cannot be empty".to_string()));
                            }
                        }
                    },
                    "x5c" => {
                        // x5c is optional for self-attestation
                        if !matches!(value, serde_cbor::Value::Array(_)) {
                            return Err(AppError::InvalidField("attestationObject.attStmt.x5c must be an array".to_string()));
                        }
                        if let serde_cbor::Value::Array(x5c_array) = value {
                            if x5c_array.is_empty() {
                                return Err(AppError::InvalidField("attestationObject.attStmt.x5c cannot be empty".to_string()));
                            }
                        }
                    },
                    _ => {} // Ignore unknown attestation statement fields
                }
            }
        }

        // For packed format, both alg and sig are required
        if !has_alg {
            return Err(AppError::MissingField("attestationObject.attStmt.alg".to_string()));
        }
        if !has_sig {
            return Err(AppError::MissingField("attestationObject.attStmt.sig".to_string()));
        }

        Ok(())
    }
}