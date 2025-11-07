use std::sync::Arc;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::RngCore;
use uuid::Uuid;
use url::Url;
use webauthn_rs::{prelude::*, Webauthn, WebauthnBuilder};
use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticatorSelectionCriteria, 
    CollectedClientData, RegisterPublicKeyCredential, PublicKeyCredential,
    AuthenticatorAttestationResponseRaw, AuthenticatorAssertionResponseRaw,
};

use crate::{
    config::settings::WebAuthnSettings,
    db::DbPool,
    error::{AppError, Result},
    models::{Challenge, Credential, NewChallenge, NewCredential, NewUser, User},
    schemas::{request::*, response::*},
};
use diesel::prelude::*;

#[derive(Clone)]
pub struct WebAuthnService {
    webauthn: Arc<Webauthn>,
    db_pool: Arc<DbPool>,
}

impl WebAuthnService {
    pub fn new(config: &WebAuthnSettings, db_pool: Arc<DbPool>) -> Result<Self> {
        let origin = Url::parse(&config.origin)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid origin URL: {e}")))?;

        let webauthn = WebauthnBuilder::new(&config.rp_id, &origin)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to create WebAuthn builder: {e}")))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| AppError::WebAuthnError(format!("Failed to build WebAuthn: {e}")))?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
            db_pool,
        })
    }

    pub async fn begin_registration(&self, req: RegistrationBeginRequest) -> Result<RegistrationBeginResponse> {
        let mut conn = self.db_pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {e}")))?;

        // Check if user already exists
        let existing_user = self.find_user_by_username(&mut conn, &req.username)?;
        
        // Generate or get user
        let user = if let Some(user) = existing_user {
            user
        } else {
            // Create new user
            let user_id = self.generate_user_id();
            let new_user = NewUser {
                username: req.username.clone(),
                display_name: req.display_name.clone(),
                user_id: user_id.clone(),
            };

            diesel::insert_into(crate::schema::users::table)
                .values(&new_user)
                .get_result::<User>(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {e}")))?
        };

        // Get existing credentials to exclude
        let exclude_credentials = self.get_user_credentials(&mut conn, user.id)?;

        // Convert existing credentials to exclude list
        let exclude_list: Vec<CredentialID> = exclude_credentials
            .into_iter()
            .map(|cred| CredentialID::from(cred.credential_id))
            .collect();

        // Convert user.user_id bytes to Uuid
        let user_uuid = if user.user_id.len() == 16 {
            Uuid::from_slice(&user.user_id)
                .map_err(|e| AppError::ValidationError(format!("Invalid user ID: {e}")))?
        } else {
            // If not UUID format, create a new UUID
            Uuid::new_v4()
        };

        // Generate registration challenge
        let (ccr, reg_state) = self.webauthn
            .start_passkey_registration(
                user_uuid,
                &user.username,
                &user.display_name,
                Some(exclude_list),
            )
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start registration: {e}")))?;

        // Store challenge in database
        self.store_challenge(
            &mut conn,
            ccr.public_key.challenge.as_ref(),
            Some(user.id),
            "registration".to_string(),
        )?;

        // Convert to API response format
        Ok(RegistrationBeginResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            rp: crate::schemas::response::RelyingParty {
                name: ccr.public_key.rp.name.clone(),
                id: Some(ccr.public_key.rp.id.clone()),
            },
            user: PublicKeyCredentialUserEntity {
                id: URL_SAFE_NO_PAD.encode(&ccr.public_key.user.id),
                name: ccr.public_key.user.name.clone(),
                display_name: ccr.public_key.user.display_name.clone(),
            },
            challenge: URL_SAFE_NO_PAD.encode(ccr.public_key.challenge.as_ref()),
            pub_key_cred_params: ccr.public_key.pub_key_cred_params.clone(),
            timeout: ccr.public_key.timeout.map(|t| t as u64),
            exclude_credentials: ccr.public_key.exclude_credentials
                .unwrap_or_default()
                .into_iter()
                .map(|desc| crate::schemas::response::PublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: URL_SAFE_NO_PAD.encode(desc.id.as_ref()),
                    transports: desc.transports.map(|t| {
                        t.into_iter().map(|transport| transport.to_string()).collect()
                    }),
                })
                .collect(),
            authenticator_selection: ccr.public_key.authenticator_selection.clone(),
            attestation: ccr.public_key.attestation.unwrap_or(AttestationConveyancePreference::None),
            extensions: None, // Simplified for now
        })
    }

    pub async fn complete_registration(&self, req: RegistrationCompleteRequest) -> Result<ServerResponse> {
        let mut conn = self.db_pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {e}")))?;

        // Decode the credential ID
        let credential_id = URL_SAFE_NO_PAD.decode(&req.id)
            .map_err(|e| AppError::ValidationError(format!("Invalid credential ID: {e}")))?;

        // Decode client data JSON
        let client_data_json = URL_SAFE_NO_PAD.decode(&req.response.client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON: {e}")))?;

        // Parse client data to get challenge
        let client_data: CollectedClientData = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON format: {e}")))?;

        // Decode challenge
        let challenge_bytes = URL_SAFE_NO_PAD.decode(&client_data.challenge)
            .map_err(|e| AppError::ValidationError(format!("Invalid challenge: {e}")))?;

        // Find and consume challenge
        let challenge = self.find_and_consume_challenge(&mut conn, &challenge_bytes, "registration")?;

        // Get user
        let user = if let Some(user_id) = challenge.user_id {
            self.find_user_by_id(&mut conn, user_id)?
                .ok_or_else(|| AppError::NotFound("User not found".to_string()))?
        } else {
            return Err(AppError::ValidationError("Invalid challenge state".to_string()));
        };

        // Build RegisterPublicKeyCredential for webauthn-rs
        let reg_credential = RegisterPublicKeyCredential {
            id: req.id.clone(),
            raw_id: Base64UrlSafeData::from(credential_id.clone()),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData::from(
                    URL_SAFE_NO_PAD.decode(&req.response.attestation_object)
                        .map_err(|e| AppError::ValidationError(format!("Invalid attestation object: {e}")))?
                ),
                client_data_json: Base64UrlSafeData::from(client_data_json),
                transports: None, // Will be extracted from attestation
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        };

        // Convert user.user_id bytes to Uuid for registration state recreation
        let user_uuid = if user.user_id.len() == 16 {
            Uuid::from_slice(&user.user_id)
                .map_err(|e| AppError::ValidationError(format!("Invalid user ID: {e}")))?
        } else {
            Uuid::new_v4()
        };

        // We need to simulate the registration state that was stored during begin_registration
        // For simplicity, we'll create a new registration flow - in production you'd store this properly
        let (_, reg_state) = self.webauthn
            .start_passkey_registration(
                user_uuid,
                &user.username,
                &user.display_name,
                None, // No exclusions for recreated state
            )
            .map_err(|e| AppError::WebAuthnError(format!("Failed to recreate registration state: {e}")))?;

        // Complete registration
        let passkey = self.webauthn
            .finish_passkey_registration(&reg_credential, &reg_state)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to complete registration: {e}")))?;

        // Store credential in database
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id: credential_id.clone(),
            public_key: passkey.cred_id().as_ref().to_vec(),
            counter: passkey.counter() as i64,
            aaguid: Some(passkey.aaguid()),
            credential_type: "public-key".to_string(),
            transports: None, // TODO: Extract from attestation
            backup_eligible: Some(passkey.backup_eligible()),
            backup_state: Some(passkey.backup_state()),
            attestation_type: None, // TODO: Extract from attestation
        };

        diesel::insert_into(crate::schema::credentials::table)
            .values(&new_credential)
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to store credential: {e}")))?;

        Ok(ServerResponse::ok())
    }

    pub async fn begin_authentication(&self, req: AuthenticationBeginRequest) -> Result<AuthenticationBeginResponse> {
        let mut conn = self.db_pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {e}")))?;

        // Find user
        let user = self.find_user_by_username(&mut conn, &req.username)?
            .ok_or_else(|| AppError::NotFound("User does not exist!".to_string()))?;

        // Get user's credentials
        let credentials = self.get_user_credentials(&mut conn, user.id)?;

        if credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Convert credentials to passkeys
        let passkeys: Vec<Passkey> = credentials
            .into_iter()
            .map(|cred| self.credential_to_passkey(cred))
            .collect::<Result<Vec<_>>>()?;

        // Generate authentication challenge
        let (request_challenge_response, auth_state) = self.webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start authentication: {e}")))?;

        // Store challenge
        self.store_challenge(
            &mut conn,
            request_challenge_response.public_key.challenge.as_ref(),
            Some(user.id),
            "authentication".to_string(),
        )?;

        // Convert to API response format
        Ok(AuthenticationBeginResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge: URL_SAFE_NO_PAD.encode(request_challenge_response.public_key.challenge.as_ref()),
            timeout: request_challenge_response.public_key.timeout.map(|t| t as u64),
            rp_id: request_challenge_response.public_key.rp_id.clone(),
            allow_credentials: request_challenge_response.public_key.allow_credentials
                .map(|creds| creds.into_iter()
                    .map(|desc| crate::schemas::response::PublicKeyCredentialDescriptor {
                        credential_type: "public-key".to_string(),
                        id: URL_SAFE_NO_PAD.encode(desc.id.as_ref()),
                        transports: desc.transports.map(|t| {
                            t.into_iter().map(|transport| transport.to_string()).collect()
                        }),
                    })
                    .collect())
                .unwrap_or_default(),
            user_verification: req.user_verification,
            extensions: None, // Simplified for now
        })
    }

    pub async fn complete_authentication(&self, req: AuthenticationCompleteRequest) -> Result<ServerResponse> {
        let mut conn = self.db_pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {e}")))?;

        // Decode client data JSON to get challenge
        let client_data_json = URL_SAFE_NO_PAD.decode(&req.response.client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON: {e}")))?;

        let client_data: CollectedClientData = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid client data JSON format: {e}")))?;

        let challenge_bytes = URL_SAFE_NO_PAD.decode(&client_data.challenge)
            .map_err(|e| AppError::ValidationError(format!("Invalid challenge: {e}")))?;

        // Find and consume challenge
        let challenge = self.find_and_consume_challenge(&mut conn, &challenge_bytes, "authentication")?;

        let user = if let Some(user_id) = challenge.user_id {
            self.find_user_by_id(&mut conn, user_id)?
                .ok_or_else(|| AppError::NotFound("User not found".to_string()))?
        } else {
            return Err(AppError::ValidationError("Invalid challenge state".to_string()));
        };

        // Get user's credentials and convert to passkeys
        let credentials = self.get_user_credentials(&mut conn, user.id)?;
        let passkeys: Vec<Passkey> = credentials
            .into_iter()
            .map(|cred| self.credential_to_passkey(cred))
            .collect::<Result<Vec<_>>>()?;

        // Build PublicKeyCredential for authentication
        let auth_credential = PublicKeyCredential {
            id: req.id.clone(),
            raw_id: Base64UrlSafeData::from(URL_SAFE_NO_PAD.decode(&req.id)
                .map_err(|e| AppError::ValidationError(format!("Invalid credential ID: {e}")))?),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: Base64UrlSafeData::from(
                    URL_SAFE_NO_PAD.decode(&req.response.authenticator_data)
                        .map_err(|e| AppError::ValidationError(format!("Invalid authenticator data: {e}")))?
                ),
                client_data_json: Base64UrlSafeData::from(client_data_json),
                signature: Base64UrlSafeData::from(
                    URL_SAFE_NO_PAD.decode(&req.response.signature)
                        .map_err(|e| AppError::ValidationError(format!("Invalid signature: {e}")))?
                ),
                user_handle: if req.response.user_handle.is_empty() {
                    None
                } else {
                    Some(Base64UrlSafeData::from(
                        URL_SAFE_NO_PAD.decode(&req.response.user_handle)
                            .map_err(|e| AppError::ValidationError(format!("Invalid user handle: {e}")))?
                    ))
                },
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        };

        // We need to recreate the authentication state - in production you'd store this
        let (_, auth_state) = self.webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to recreate auth state: {e}")))?;

        // Complete authentication
        let auth_result = self.webauthn
            .finish_passkey_authentication(&auth_credential, &auth_state)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to complete authentication: {e}")))?;

        // Update credential counter
        let credential_id = URL_SAFE_NO_PAD.decode(&req.id)
            .map_err(|e| AppError::ValidationError(format!("Invalid credential ID: {e}")))?;

        diesel::update(crate::schema::credentials::table)
            .filter(crate::schema::credentials::credential_id.eq(&credential_id))
            .set((
                crate::schema::credentials::counter.eq(auth_result.counter() as i64),
                crate::schema::credentials::last_used.eq(Some(Utc::now())),
            ))
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to update credential: {e}")))?;

        Ok(ServerResponse::ok())
    }

    // Helper methods
    fn generate_user_id(&self) -> Vec<u8> {
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        id.to_vec()
    }

    fn find_user_by_username(&self, conn: &mut PgConnection, username: &str) -> Result<Option<User>> {
        use crate::schema::users::dsl;
        
        dsl::users
            .filter(dsl::username.eq(username))
            .filter(dsl::active.eq(true))
            .first::<User>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to find user: {e}")))
    }

    fn find_user_by_id(&self, conn: &mut PgConnection, user_id: Uuid) -> Result<Option<User>> {
        use crate::schema::users::dsl;
        
        dsl::users
            .filter(dsl::id.eq(user_id))
            .filter(dsl::active.eq(true))
            .first::<User>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to find user: {e}")))
    }

    fn get_user_credentials(&self, conn: &mut PgConnection, user_id: Uuid) -> Result<Vec<Credential>> {
        use crate::schema::credentials::dsl;
        
        dsl::credentials
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::active.eq(true))
            .load::<Credential>(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to get credentials: {e}")))
    }

    fn store_challenge(
        &self,
        conn: &mut PgConnection,
        challenge: &[u8],
        user_id: Option<Uuid>,
        challenge_type: String,
    ) -> Result<()> {
        let expires_at = Utc::now() + Duration::minutes(5); // 5 minute expiry
        
        let new_challenge = NewChallenge {
            challenge: challenge.to_vec(),
            user_id,
            challenge_type,
            session_id: None, // TODO: Implement session management
            expires_at,
        };

        diesel::insert_into(crate::schema::challenges::table)
            .values(&new_challenge)
            .execute(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to store challenge: {e}")))?;

        Ok(())
    }

    fn find_and_consume_challenge(
        &self,
        conn: &mut PgConnection,
        challenge: &[u8],
        challenge_type: &str,
    ) -> Result<Challenge> {
        use crate::schema::challenges::dsl;
        
        // Find the challenge
        let stored_challenge = dsl::challenges
            .filter(dsl::challenge.eq(challenge))
            .filter(dsl::challenge_type.eq(challenge_type))
            .filter(dsl::consumed.eq(false))
            .filter(dsl::expires_at.gt(Utc::now()))
            .first::<Challenge>(conn)
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AppError::ValidationError("Invalid or expired challenge".to_string()),
                _ => AppError::DatabaseError(format!("Failed to find challenge: {e}")),
            })?;

        // Mark as consumed
        diesel::update(dsl::challenges.find(stored_challenge.id))
            .set(dsl::consumed.eq(true))
            .execute(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to consume challenge: {e}")))?;

        Ok(stored_challenge)
    }

    fn credential_to_passkey(&self, credential: Credential) -> Result<Passkey> {
        // Convert credential data to passkey - this is a simplified approach
        // In production, you'd need to properly reconstruct all the passkey data
        
        // For now, we'll create a minimal passkey that contains the essential data
        // Note: This is not the complete implementation as Passkey constructor is complex
        // You'd typically store more detailed credential data and reconstruct it properly
        
        // This is a placeholder - the actual implementation would require storing
        // and reconstructing the complete credential/public key data
        Err(AppError::WebAuthnError("Credential to passkey conversion not fully implemented".to_string()))
    }
}