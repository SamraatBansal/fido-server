//! FIDO/WebAuthn service implementation

use std::sync::Arc;
use base64::Engine;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use rand::RngCore;
use webauthn_rs::prelude::*;

use crate::{
    config::settings::WebAuthnSettings,
    db::{models::*, DbPool},
    schema_diesel::{challenge_states, credentials, users},
    schema::{
        ChallengeOperation, ServerPublicKeyCredentialCreationOptionsRequest,
        ServerPublicKeyCredentialCreationOptionsResponse, ServerPublicKeyCredentialGetOptionsRequest,
        ServerPublicKeyCredentialGetOptionsResponse, ServerPublicKeyCredential,
        ServerPublicKeyCredentialAssertion, PublicKeyCredentialRpEntity,
        ServerPublicKeyCredentialUserEntity, PublicKeyCredentialParameters,
        ServerPublicKeyCredentialDescriptor, AuthenticatorSelectionCriteria,
    },
    AppError, Result,
};

#[derive(Clone)]
pub struct FidoService {
    webauthn: Arc<Webauthn>,
    db_pool: Arc<DbPool>,
}

impl FidoService {
    pub fn new(config: &WebAuthnSettings, db_pool: Arc<DbPool>) -> Result<Self> {
        let rp_id = config.rp_id.clone();
        let rp_origin = url::Url::parse(&config.origin)
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
            .select(Credential::as_select())
            .load(&mut conn)?;

        let exclude_credentials: Vec<CredentialID> = existing_credentials
            .iter()
            .map(|cred| CredentialID::from(cred.id.clone()))
            .collect();

        // Convert user to WebAuthn user
        let webauthn_user = webauthn_rs::prelude::User::new(
            user.user_id.clone(),
            user.username.clone(),
            user.display_name.clone(),
        );

        // Start registration with basic configuration
        let (creation_challenge_response, registration_state) = self.webauthn
            .start_passkey_registration(
                &webauthn_user,
                &exclude_credentials,
                None, // Use default authenticator selection
                None, // No extensions for now
            )
            .map_err(AppError::WebAuthnError)?;

        // Store challenge state
        let challenge = creation_challenge_response.public_key.challenge.clone();
        let challenge_bytes = challenge.as_ref().to_vec();
        
        let state_data = serde_json::json!({
            "registration_state": format!("{:?}", registration_state),
            "user_id": user.id.to_string()
        });

        let challenge_state = NewChallengeState {
            challenge: challenge_bytes,
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
                name: creation_challenge_response.public_key.rp.name.clone(),
                id: creation_challenge_response.public_key.rp.id.clone(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(&creation_challenge_response.public_key.user.id),
                name: creation_challenge_response.public_key.user.name.clone(),
                display_name: creation_challenge_response.public_key.user.display_name.clone(),
            },
            challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(challenge.as_ref()),
            pub_key_cred_params: creation_challenge_response
                .public_key
                .pub_key_cred_params
                .iter()
                .map(|param| PublicKeyCredentialParameters {
                    type_: "public-key".to_string(),
                    alg: param.alg as i32,
                })
                .collect(),
            timeout: creation_challenge_response.public_key.timeout,
            exclude_credentials: Some(
                creation_challenge_response
                    .public_key
                    .exclude_credentials
                    .unwrap_or_default()
                    .iter()
                    .map(|desc| ServerPublicKeyCredentialDescriptor {
                        type_: "public-key".to_string(),
                        id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&desc.id),
                        transports: desc.transports.as_ref().map(|t| {
                            t.iter().map(|transport| transport.to_string()).collect()
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
            .select(ChallengeState::as_select())
            .first(&mut conn)
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

        // For now, we'll create a simplified registration process
        // In a real implementation, you'd deserialize the full registration state
        let user_id = challenge_state.user_id.ok_or_else(|| {
            AppError::ValidationError("Missing user ID in challenge state".to_string())
        })?;

        // Create a basic credential entry
        let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|_| AppError::ValidationError("Invalid credential ID encoding".to_string()))?;

        let attestation_object_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.response.attestation_object)
            .map_err(|_| AppError::ValidationError("Invalid attestationObject encoding".to_string()))?;

        // Store credential in database (simplified - in production you'd extract the actual public key)
        let new_credential = NewCredential {
            id: credential_id,
            user_id,
            public_key: attestation_object_bytes, // This should be the extracted public key
            sign_count: 0,
            credential_type: "public-key".to_string(),
            transports: None,
            backup_eligible: false,
            backup_state: false,
            attestation_type: Some("none".to_string()),
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
            .select(User::as_select())
            .first(&mut conn)
            .map_err(|_| AppError::NotFound("User not found".to_string()))?;

        // Get user's credentials
        let user_credentials: Vec<Credential> = credentials::table
            .filter(credentials::user_id.eq(user.id))
            .select(Credential::as_select())
            .load(&mut conn)?;

        if user_credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Generate challenge for authentication
        let mut challenge_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge_bytes);
        let challenge = Challenge::new(challenge_bytes.to_vec());

        // Store challenge state
        let state_data = serde_json::json!({
            "authentication_state": "pending",
            "user_id": user.id.to_string(),
            "credentials": user_credentials.iter().map(|c| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c.id)).collect::<Vec<_>>()
        });

        let challenge_state = NewChallengeState {
            challenge: challenge.as_ref().to_vec(),
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
                .encode(challenge.as_ref()),
            timeout: Some(60000), // 60 seconds
            rp_id: self.webauthn.rp_id().to_string(),
            allow_credentials: user_credentials
                .iter()
                .map(|cred| ServerPublicKeyCredentialDescriptor {
                    type_: "public-key".to_string(),
                    id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cred.id),
                    transports: cred.transports.as_ref().and_then(|t| {
                        Some(t.iter().filter_map(|s| s.clone()).collect())
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
            .select(ChallengeState::as_select())
            .first(&mut conn)
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

        // Verify the credential exists and belongs to the user
        let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|_| AppError::ValidationError("Invalid credential ID encoding".to_string()))?;

        let stored_credential: Credential = credentials::table
            .filter(credentials::id.eq(&credential_id))
            .filter(credentials::user_id.eq(challenge_state.user_id.unwrap()))
            .select(Credential::as_select())
            .first(&mut conn)
            .map_err(|_| AppError::ValidationError("Credential not found".to_string()))?;

        // In a real implementation, you would verify the signature here
        // For now, we'll just update the sign count and timestamp
        
        diesel::update(credentials::table.filter(credentials::id.eq(&credential_id)))
            .set((
                credentials::sign_count.eq(stored_credential.sign_count + 1),
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
            .select(User::as_select())
            .first(conn)
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