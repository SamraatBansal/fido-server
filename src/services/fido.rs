//! FIDO/WebAuthn service implementation

use std::sync::Arc;
use base64::Engine;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use rand::RngCore;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::{
    config::WebAuthnSettings,
    db::{models::*, DbPool},
    schema_db::{challenge_states, credentials, users},
    schema::{
        ChallengeData, ChallengeOperation, ServerPublicKeyCredentialCreationOptionsRequest,
        ServerPublicKeyCredentialCreationOptionsResponse, ServerPublicKeyCredentialGetOptionsRequest,
        ServerPublicKeyCredentialGetOptionsResponse, ServerPublicKeyCredential,
        ServerPublicKeyCredentialAssertion, PublicKeyCredentialRpEntity,
        ServerPublicKeyCredentialUserEntity, PublicKeyCredentialParameters,
        ServerPublicKeyCredentialDescriptor, AuthenticatorSelectionCriteria,
    },
    AppError, Result,
};

pub struct FidoService {
    webauthn: Arc<Webauthn>,
    db_pool: Arc<DbPool>,
}

impl FidoService {
    pub fn new(config: &WebAuthnSettings, db_pool: Arc<DbPool>) -> Result<Self> {
        let rp_id = config.rp_id.clone();
        let rp_origin = Url::parse(&config.origin)
            .map_err(|e| AppError::InternalError(format!("Invalid origin URL: {e}")))?;
        
        let webauthn_builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .map_err(|e| AppError::InternalError(format!("WebAuthn builder error: {e}")))?;
            
        let webauthn = webauthn_builder
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| AppError::InternalError(format!("WebAuthn build error: {e}")))?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
            db_pool,
        })
    }

    pub async fn start_registration(
        &self,
        req: &ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        let mut conn = self.db_pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // Get or create user
        let user = self.get_or_create_user(&mut conn, &req.username, &req.display_name)?;

        // Get existing credentials to exclude
        let existing_credentials: Vec<Credential> = credentials::table
            .filter(credentials::user_id.eq(user.id))
            .load::<Credential>(&mut conn)?;

        let exclude_credentials: Vec<CredentialID> = existing_credentials
            .iter()
            .map(|cred| CredentialID::from(cred.id.clone()))
            .collect();

        // Convert authenticator selection if provided
        let authenticator_selection = req.authenticator_selection.as_ref().map(|sel| {
            AuthenticatorSelectionCriteria {
                authenticator_attachment: sel.authenticator_attachment.as_ref().map(|s| {
                    match s.as_str() {
                        "platform" => AuthenticatorAttachment::Platform,
                        "cross-platform" => AuthenticatorAttachment::CrossPlatform,
                        _ => AuthenticatorAttachment::CrossPlatform,
                    }
                }),
                require_resident_key: sel.require_resident_key.unwrap_or(false),
                user_verification: match sel.user_verification.as_deref().unwrap_or("preferred") {
                    "required" => UserVerificationPolicy::Required,
                    "discouraged" => UserVerificationPolicy::Discouraged,
                    _ => UserVerificationPolicy::Preferred,
                },
            }
        });

        // Convert user to WebAuthn user
        let webauthn_user = User::new(
            user.user_id.clone(),
            user.username.clone(),
            user.display_name.clone(),
        );

        // Start registration
        let (creation_challenge_response, registration_state) = self.webauthn
            .start_passkey_registration(
                &webauthn_user,
                &exclude_credentials,
                authenticator_selection,
                None, // No extensions for now
            )
            .map_err(AppError::WebAuthnError)?;

        // Store challenge state
        let challenge_bytes = creation_challenge_response.challenge.as_bytes();
        let state_data = serde_json::to_value(&registration_state)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize state: {e}")))?;

        let challenge_state = NewChallengeState {
            challenge: challenge_bytes.to_vec(),
            user_id: Some(user.id),
            operation: ChallengeOperation::Registration.to_string(),
            state_data,
            expires_at: Utc::now() + Duration::minutes(5),
        };

        diesel::insert_into(challenge_states::table)
            .values(&challenge_state)
            .execute(&mut conn)?;

        // Build response
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: creation_challenge_response.rp.name,
                id: creation_challenge_response.rp.id,
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(&creation_challenge_response.user.id),
                name: creation_challenge_response.user.name,
                display_name: creation_challenge_response.user.display_name,
            },
            challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(creation_challenge_response.challenge.as_bytes()),
            pub_key_cred_params: creation_challenge_response
                .pub_key_cred_params
                .iter()
                .map(|param| PublicKeyCredentialParameters {
                    type_: "public-key".to_string(),
                    alg: param.alg as i32,
                })
                .collect(),
            timeout: Some(creation_challenge_response.timeout),
            exclude_credentials: Some(
                creation_challenge_response
                    .exclude_credentials
                    .iter()
                    .map(|desc| ServerPublicKeyCredentialDescriptor {
                        type_: "public-key".to_string(),
                        id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&desc.id),
                        transports: desc.transports.as_ref().map(|t| {
                            t.iter().map(|transport| format!("{transport:?}").to_lowercase()).collect()
                        }),
                    })
                    .collect(),
            ),
            authenticator_selection: req.authenticator_selection.clone(),
            attestation: req.attestation.clone().or_else(|| Some("none".to_string())),
            extensions: None,
        };

        Ok(response)
    }

    pub async fn finish_registration(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<()> {
        let mut conn = self.db_pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // Decode challenge from clientDataJSON
        let client_data_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.response.client_data_json)
            .map_err(|_| AppError::ValidationError("Invalid clientDataJSON encoding".to_string()))?;

        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::ValidationError("Invalid clientDataJSON format".to_string()))?;

        let challenge_b64 = client_data.get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::ValidationError("Missing challenge in clientDataJSON".to_string()))?;

        let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(challenge_b64)
            .map_err(|_| AppError::ValidationError("Invalid challenge encoding".to_string()))?;

        // Retrieve and validate challenge state
        let challenge_state: ChallengeState = challenge_states::table
            .filter(challenge_states::challenge.eq(&challenge_bytes))
            .first::<ChallengeState>(&mut conn)
            .map_err(|_| AppError::ValidationError("Challenge not found or expired".to_string()))?;

        if challenge_state.expires_at < Utc::now() {
            // Clean up expired challenge
            diesel::delete(challenge_states::table.filter(challenge_states::id.eq(challenge_state.id)))
                .execute(&mut conn)?;
            return Err(AppError::ValidationError("Challenge expired".to_string()));
        }

        if challenge_state.operation != ChallengeOperation::Registration.to_string() {
            return Err(AppError::ValidationError("Invalid challenge operation".to_string()));
        }

        // Deserialize registration state
        let registration_state: PasskeyRegistration = serde_json::from_value(challenge_state.state_data)
            .map_err(|e| AppError::InternalError(format!("Failed to deserialize state: {e}")))?;

        // Convert credential to WebAuthn format
        let registration_response = RegisterPublicKeyCredential {
            id: base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
                .map_err(|_| AppError::ValidationError("Invalid credential ID encoding".to_string()))?,
            raw_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
                .map_err(|_| AppError::ValidationError("Invalid credential raw ID encoding".to_string()))?,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&credential.response.attestation_object)
                    .map_err(|_| AppError::ValidationError("Invalid attestationObject encoding".to_string()))?,
                client_data_json: client_data_bytes,
            },
            type_: "public-key".to_string(),
        };

        // Finish registration
        let passkey = self.webauthn
            .finish_passkey_registration(&registration_response, &registration_state)
            .map_err(AppError::WebAuthnError)?;

        // Store credential in database
        let new_credential = NewCredential {
            id: passkey.cred_id().to_vec(),
            user_id: challenge_state.user_id.ok_or_else(|| {
                AppError::ValidationError("Missing user ID in challenge state".to_string())
            })?,
            public_key: serde_json::to_vec(&passkey.cred())
                .map_err(|e| AppError::InternalError(format!("Failed to serialize public key: {e}")))?,
            sign_count: passkey.counter() as i64,
            credential_type: "public-key".to_string(),
            transports: None, // Will be populated from attestation if available
            backup_eligible: false, // Will be set based on authenticator data
            backup_state: false,
            attestation_type: None,
            attestation_trust_path: None,
        };

        diesel::insert_into(credentials::table)
            .values(&new_credential)
            .execute(&mut conn)?;

        // Clean up challenge state
        diesel::delete(challenge_states::table.filter(challenge_states::id.eq(challenge_state.id)))
            .execute(&mut conn)?;

        Ok(())
    }

    pub async fn start_authentication(
        &self,
        req: &ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        let mut conn = self.db_pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // Find user by username
        let user: User = users::table
            .filter(users::username.eq(&req.username))
            .first::<User>(&mut conn)
            .map_err(|_| AppError::NotFound("User not found".to_string()))?;

        // Get user's credentials
        let user_credentials: Vec<Credential> = credentials::table
            .filter(credentials::user_id.eq(user.id))
            .load::<Credential>(&mut conn)?;

        if user_credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Convert credentials to Passkey format
        let passkeys: Vec<Passkey> = user_credentials
            .iter()
            .filter_map(|cred| {
                serde_json::from_slice(&cred.public_key).ok()
            })
            .collect();

        if passkeys.is_empty() {
            return Err(AppError::InternalError("Failed to deserialize user credentials".to_string()));
        }

        // Convert user verification requirement
        let user_verification = match req.user_verification.as_deref().unwrap_or("preferred") {
            "required" => UserVerificationPolicy::Required,
            "discouraged" => UserVerificationPolicy::Discouraged,
            _ => UserVerificationPolicy::Preferred,
        };

        // Start authentication
        let (request_challenge_response, authentication_state) = self.webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(AppError::WebAuthnError)?;

        // Store challenge state
        let challenge_bytes = request_challenge_response.challenge.as_bytes();
        let state_data = serde_json::to_value(&authentication_state)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize state: {e}")))?;

        let challenge_state = NewChallengeState {
            challenge: challenge_bytes.to_vec(),
            user_id: Some(user.id),
            operation: ChallengeOperation::Authentication.to_string(),
            state_data,
            expires_at: Utc::now() + Duration::minutes(5),
        };

        diesel::insert_into(challenge_states::table)
            .values(&challenge_state)
            .execute(&mut conn)?;

        // Build response
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(request_challenge_response.challenge.as_bytes()),
            timeout: Some(request_challenge_response.timeout),
            rp_id: request_challenge_response.rp_id,
            allow_credentials: request_challenge_response
                .allow_credentials
                .iter()
                .map(|desc| ServerPublicKeyCredentialDescriptor {
                    type_: "public-key".to_string(),
                    id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&desc.id),
                    transports: desc.transports.as_ref().map(|t| {
                        t.iter().map(|transport| format!("{transport:?}").to_lowercase()).collect()
                    }),
                })
                .collect(),
            user_verification: req.user_verification.clone(),
        };

        Ok(response)
    }

    pub async fn finish_authentication(
        &self,
        credential: &ServerPublicKeyCredentialAssertion,
    ) -> Result<()> {
        let mut conn = self.db_pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // Decode challenge from clientDataJSON
        let client_data_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.response.client_data_json)
            .map_err(|_| AppError::ValidationError("Invalid clientDataJSON encoding".to_string()))?;

        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::ValidationError("Invalid clientDataJSON format".to_string()))?;

        let challenge_b64 = client_data.get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::ValidationError("Missing challenge in clientDataJSON".to_string()))?;

        let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(challenge_b64)
            .map_err(|_| AppError::ValidationError("Invalid challenge encoding".to_string()))?;

        // Retrieve and validate challenge state
        let challenge_state: ChallengeState = challenge_states::table
            .filter(challenge_states::challenge.eq(&challenge_bytes))
            .first::<ChallengeState>(&mut conn)
            .map_err(|_| AppError::ValidationError("Challenge not found or expired".to_string()))?;

        if challenge_state.expires_at < Utc::now() {
            // Clean up expired challenge
            diesel::delete(challenge_states::table.filter(challenge_states::id.eq(challenge_state.id)))
                .execute(&mut conn)?;
            return Err(AppError::ValidationError("Challenge expired".to_string()));
        }

        if challenge_state.operation != ChallengeOperation::Authentication.to_string() {
            return Err(AppError::ValidationError("Invalid challenge operation".to_string()));
        }

        // Deserialize authentication state
        let authentication_state: PasskeyAuthentication = serde_json::from_value(challenge_state.state_data)
            .map_err(|e| AppError::InternalError(format!("Failed to deserialize state: {e}")))?;

        // Convert credential to WebAuthn format
        let auth_response = AuthenticatorAssertionResponseRaw {
            authenticator_data: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&credential.response.authenticator_data)
                .map_err(|_| AppError::ValidationError("Invalid authenticatorData encoding".to_string()))?,
            client_data_json: client_data_bytes,
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&credential.response.signature)
                .map_err(|_| AppError::ValidationError("Invalid signature encoding".to_string()))?,
        };

        let auth_credential = PublicKeyCredential {
            id: base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
                .map_err(|_| AppError::ValidationError("Invalid credential ID encoding".to_string()))?,
            raw_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
                .map_err(|_| AppError::ValidationError("Invalid credential raw ID encoding".to_string()))?,
            response: auth_response,
            type_: "public-key".to_string(),
            extensions: AuthenticationExtensionsClientOutputs::default(),
        };

        // Finish authentication
        let authentication_result = self.webauthn
            .finish_passkey_authentication(&auth_credential, &authentication_state)
            .map_err(AppError::WebAuthnError)?;

        // Update credential counter
        let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|_| AppError::ValidationError("Invalid credential ID encoding".to_string()))?;

        diesel::update(credentials::table.filter(credentials::id.eq(&credential_id)))
            .set((
                credentials::sign_count.eq(authentication_result.counter() as i64),
                credentials::last_used_at.eq(diesel::dsl::now),
            ))
            .execute(&mut conn)?;

        // Clean up challenge state
        diesel::delete(challenge_states::table.filter(challenge_states::id.eq(challenge_state.id)))
            .execute(&mut conn)?;

        Ok(())
    }

    fn get_or_create_user(
        &self,
        conn: &mut PgConnection,
        username: &str,
        display_name: &str,
    ) -> Result<User> {
        // Try to find existing user
        if let Ok(user) = users::table
            .filter(users::username.eq(username))
            .first::<User>(conn)
        {
            return Ok(user);
        }

        // Create new user
        let user_id = {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes.to_vec()
        };

        let new_user = NewUser {
            username: username.to_string(),
            display_name: display_name.to_string(),
            user_id,
        };

        let user = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result::<User>(conn)?;

        Ok(user)
    }
}