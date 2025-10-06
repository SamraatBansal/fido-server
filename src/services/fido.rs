//! FIDO2/WebAuthn service implementation

use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs::WebauthnBuilder;

use crate::config::WebAuthnConfig;
use crate::db::{DbConnection, models::*};
use crate::db::schema::{users, credentials, challenges};
use crate::error::{AppError, Result};
use crate::schema::*;

/// FIDO service for WebAuthn operations
pub struct FidoService {
    /// WebAuthn instance
    webauthn: Webauthn,
    /// Configuration
    config: WebAuthnConfig,
}

impl FidoService {
    /// Create new FIDO service
    pub fn new(config: WebAuthnConfig) -> Result<Self> {
        let rp_name = config.rp_name.clone();
        let rp_id = config.rp_id.clone();
        let rp_origin = config.rp_origin.clone();

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .map_err(|e| AppError::Config(format!("Failed to create Webauthn builder: {}", e)))?
            .rp_name(&rp_name);

        let webauthn = builder
            .build()
            .map_err(|e| AppError::Config(format!("Failed to build Webauthn instance: {}", e)))?;

        Ok(Self { webauthn, config })
    }

    /// Start registration process
    pub async fn start_registration(
        &self,
        conn: &mut DbConnection,
        username: &str,
        display_name: &str,
        user_verification: Option<UserVerificationPolicy>,
        attestation: Option<AttestationConveyancePreference>,
        resident_key: Option<ResidentKeyRequirement>,
        authenticator_attachment: Option<AuthenticatorAttachment>,
    ) -> Result<RegistrationStartResponse> {
        // Find or create user
        let user = self.find_or_create_user(conn, username, display_name).await?;

        // Create passkey registration challenge
        let passkey_registration = self.webauthn
            .start_passkey_registration(
                &User {
                    id: user.id.as_bytes().to_vec(),
                    name: username,
                    display_name,
                },
                user_verification.unwrap_or(UserVerificationPolicy::Preferred),
                attestation.unwrap_or(AttestationConveyancePreference::Direct),
                resident_key.unwrap_or(ResidentKeyRequirement::Preferred),
                authenticator_attachment,
            )
            .map_err(|e| AppError::WebAuthn(e))?;

        // Store challenge
        let challenge_hash = general_purpose::STANDARD.encode(&passkey_registration.challenge);
        let expires_at = Utc::now() + Duration::seconds(self.config.challenge_timeout as i64);
        
        let new_challenge = NewChallenge {
            challenge_hash,
            user_id: Some(user.id),
            challenge_type: "registration".to_string(),
            expires_at,
            credential_id: None,
        };

        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(conn)?;

        // Convert to response format
        let response = RegistrationStartResponse {
            challenge: general_purpose::STANDARD.encode(&passkey_registration.challenge),
            user: User {
                id: user.id,
                name: user.username,
                display_name: user.display_name,
            },
            rp: RelyingParty {
                id: self.config.rp_id.clone(),
                name: self.config.rp_name.clone(),
            },
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -7,  // ES256
                },
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -257, // RS256
                },
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -8,   // EdDSA
                },
            ],
            timeout: self.config.challenge_timeout * 1000, // Convert to milliseconds
            attestation: "direct".to_string(),
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment: authenticator_attachment.map(|a| match a {
                    AuthenticatorAttachment::Platform => "platform".to_string(),
                    AuthenticatorAttachment::CrossPlatform => "cross-platform".to_string(),
                }),
                require_resident_key: resident_key == Some(ResidentKeyRequirement::Required),
                resident_key: match resident_key.unwrap_or(ResidentKeyRequirement::Preferred) {
                    ResidentKeyRequirement::Discouraged => "discouraged".to_string(),
                    ResidentKeyRequirement::Preferred => "preferred".to_string(),
                    ResidentKeyRequirement::Required => "required".to_string(),
                },
                user_verification: match user_verification.unwrap_or(UserVerificationPolicy::Preferred) {
                    UserVerificationPolicy::Discouraged => "discouraged".to_string(),
                    UserVerificationPolicy::Preferred => "preferred".to_string(),
                    UserVerificationPolicy::Required => "required".to_string(),
                },
            },
            extensions: None,
        };

        Ok(response)
    }

    /// Finish registration process
    pub async fn finish_registration(
        &self,
        conn: &mut DbConnection,
        credential_id: &str,
        client_data_json: &str,
        attestation_object: &str,
        transports: Option<Vec<String>>,
    ) -> Result<RegistrationFinishResponse> {
        // Decode base64 data
        let client_data_json_bytes = general_purpose::STANDARD.decode(client_data_json)
            .map_err(|e| AppError::Base64(e))?;
        let attestation_object_bytes = general_purpose::STANDARD.decode(attestation_object)
            .map_err(|e| AppError::Base64(e))?;

        // Find and validate challenge
        let challenge = self.find_and_validate_challenge(conn, &client_data_json_bytes, "registration").await?;

        // Get user
        let user = users::table
            .filter(users::id.eq(challenge.user_id.unwrap()))
            .first::<User>(conn)?;

        // For now, we'll store the credential without full verification
        // In a production environment, you would verify the attestation object
        let credential_id_bytes = general_purpose::STANDARD.decode(credential_id)
            .map_err(|e| AppError::Base64(e))?;

        // Store credential
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id: credential_id_bytes,
            public_key: vec![], // Would be extracted from attestation object
            sign_count: 0,
            attestation_type: AttestationType::None, // Simplified
            transports: transports.unwrap_or_default(),
            backup_eligible: false,
            backup_state: false,
            user_verification_type: UserVerificationType::Preferred,
            aaguid: None,
        };

        diesel::insert_into(credentials::table)
            .values(&new_credential)
            .execute(conn)?;

        // Clean up challenge
        diesel::delete(challenges::table.filter(challenges::id.eq(challenge.id)))
            .execute(conn)?;

        Ok(RegistrationFinishResponse {
            credential_id: credential_id.to_string(),
            success: true,
            user_id: user.id,
        })
    }

    /// Start authentication process
    pub async fn start_authentication(
        &self,
        conn: &mut DbConnection,
        username: Option<&str>,
        user_verification: Option<UserVerificationPolicy>,
    ) -> Result<AuthenticationStartResponse> {
        let allow_credentials = if let Some(username) = username {
            // Find user and their credentials
            let user = users::table
                .filter(users::username.eq(username))
                .first::<User>(conn)
                .optional()?;

            if let Some(user) = user {
                let user_credentials = credentials::table
                    .filter(credentials::user_id.eq(user.id))
                    .load::<Credential>(conn)?;

                Some(user_credentials.into_iter().map(|cred| AllowCredential {
                    id: general_purpose::STANDARD.encode(&cred.credential_id),
                    cred_type: "public-key".to_string(),
                    transports: Some(cred.transports),
                }).collect())
            } else {
                None
            }
        } else {
            None // Userless flow
        };

        // Create authentication challenge
        let auth_challenge = self.webauthn
            .start_passkey_authentication()
            .map_err(|e| AppError::WebAuthn(e))?;

        // Store challenge
        let challenge_hash = general_purpose::STANDARD.encode(&auth_challenge.challenge);
        let expires_at = Utc::now() + Duration::seconds(self.config.challenge_timeout as i64);
        
        let new_challenge = NewChallenge {
            challenge_hash,
            user_id: None, // Will be set when user is known
            challenge_type: "authentication".to_string(),
            expires_at,
            credential_id: None,
        };

        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(conn)?;

        Ok(AuthenticationStartResponse {
            challenge: general_purpose::STANDARD.encode(&auth_challenge.challenge),
            timeout: self.config.challenge_timeout * 1000,
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification: match user_verification.unwrap_or(UserVerificationPolicy::Preferred) {
                UserVerificationPolicy::Discouraged => "discouraged".to_string(),
                UserVerificationPolicy::Preferred => "preferred".to_string(),
                UserVerificationPolicy::Required => "required".to_string(),
            },
            extensions: None,
        })
    }

    /// Finish authentication process
    pub async fn finish_authentication(
        &self,
        conn: &mut DbConnection,
        credential_id: &str,
        client_data_json: &str,
        _authenticator_data: &str,
        _signature: &str,
        _user_handle: Option<&str>,
    ) -> Result<AuthenticationFinishResponse> {
        // Decode base64 data
        let client_data_json_bytes = general_purpose::STANDARD.decode(client_data_json)
            .map_err(|e| AppError::Base64(e))?;

        // Find credential
        let credential_id_bytes = general_purpose::STANDARD.decode(credential_id)
            .map_err(|e| AppError::Base64(e))?;

        let credential = credentials::table
            .filter(credentials::credential_id.eq(&credential_id_bytes))
            .first::<Credential>(conn)
            .optional()?
            .ok_or_else(|| AppError::Credential("Credential not found".to_string()))?;

        // Get user
        let user = users::table
            .filter(users::id.eq(credential.user_id))
            .first::<User>(conn)?;

        // Find and validate challenge
        let challenge = self.find_and_validate_challenge(conn, &client_data_json_bytes, "authentication").await?;

        // For now, we'll just update the credential usage without full signature verification
        // In a production environment, you would verify the signature against the stored public key
        diesel::update(credentials::table.filter(credentials::id.eq(credential.id)))
            .set((
                credentials::sign_count.eq(credential.sign_count + 1),
                credentials::last_used_at.eq(Utc::now()),
            ))
            .execute(conn)?;

        // Clean up challenge
        diesel::delete(challenges::table.filter(challenges::id.eq(challenge.id)))
            .execute(conn)?;

        Ok(AuthenticationFinishResponse {
            success: true,
            user: User {
                id: user.id,
                name: user.username,
                display_name: user.display_name,
            },
            credential: CredentialInfo {
                id: credential_id.to_string(),
                cred_type: "public-key".to_string(),
                last_used_at: Some(Utc::now()),
                backup_eligible: credential.backup_eligible,
                backup_state: credential.backup_state,
            },
        })
    }

    /// List user credentials
    pub async fn list_credentials(
        &self,
        conn: &mut DbConnection,
        user_id: Uuid,
    ) -> Result<Vec<CredentialInfo>> {
        let user_credentials = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .load::<Credential>(conn)?;

        Ok(user_credentials.into_iter().map(|cred| CredentialInfo {
            id: general_purpose::STANDARD.encode(&cred.credential_id),
            cred_type: "public-key".to_string(),
            last_used_at: cred.last_used_at,
            backup_eligible: cred.backup_eligible,
            backup_state: cred.backup_state,
        }).collect())
    }

    /// Delete credential
    pub async fn delete_credential(
        &self,
        conn: &mut DbConnection,
        credential_id: &str,
        user_id: Uuid,
    ) -> Result<()> {
        let credential_id_bytes = general_purpose::STANDARD.decode(credential_id)
            .map_err(|e| AppError::Base64(e))?;

        let deleted_count = diesel::delete(
            credentials::table
                .filter(credentials::credential_id.eq(&credential_id_bytes))
                .filter(credentials::user_id.eq(user_id))
        )
        .execute(conn)?;

        if deleted_count == 0 {
            return Err(AppError::Credential("Credential not found or not owned by user".to_string()));
        }

        Ok(())
    }

    /// Find or create user
    async fn find_or_create_user(
        &self,
        conn: &mut DbConnection,
        username: &str,
        display_name: &str,
    ) -> Result<User> {
        // Try to find existing user
        if let Some(user) = users::table
            .filter(users::username.eq(username))
            .first::<User>(conn)
            .optional()?
        {
            Ok(user)
        } else {
            // Create new user
            let new_user = NewUser {
                username: username.to_string(),
                display_name: display_name.to_string(),
            };

            let user = diesel::insert_into(users::table)
                .values(&new_user)
                .returning(User::as_returning())
                .get_result(conn)?;

            Ok(user)
        }
    }

    /// Find and validate challenge
    async fn find_and_validate_challenge(
        &self,
        conn: &mut DbConnection,
        client_data_json: &[u8],
        challenge_type: &str,
    ) -> Result<Challenge> {
        // Parse client data JSON to extract challenge
        let client_data: serde_json::Value = serde_json::from_slice(client_data_json)
            .map_err(|e| AppError::Serialization(e))?;

        let challenge_from_client = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Challenge("Challenge not found in client data".to_string()))?;

        // Find challenge in database
        let challenge = challenges::table
            .filter(challenges::challenge_hash.eq(challenge_from_client))
            .filter(challenges::challenge_type.eq(challenge_type))
            .filter(challenges::expires_at.gt(Utc::now()))
            .first::<Challenge>(conn)
            .optional()?
            .ok_or_else(|| AppError::Challenge("Invalid or expired challenge".to_string()))?;

        Ok(challenge)
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired_challenges(&self, conn: &mut DbConnection) -> Result<usize> {
        let deleted_count = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(Utc::now()))
        )
        .execute(conn)?;

        Ok(deleted_count)
    }
}