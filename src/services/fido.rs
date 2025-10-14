use crate::config::AppConfig;
use crate::db::{models::*, DbConnection};
use crate::error::{AppError, Result};
use crate::schema::{challenges, credentials};
use crate::services::UserService;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub username: String,
    pub display_name: String,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl SuccessResponse {
    pub fn new() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
        }
    }
}

pub struct FidoService {
    webauthn: Arc<Webauthn>,
    config: Arc<AppConfig>,
}

impl FidoService {
    pub fn new(config: Arc<AppConfig>) -> Result<Self> {
        let webauthn = Arc::new(config.create_webauthn()?);
        Ok(Self { webauthn, config })
    }

    pub fn start_registration(
        &self,
        conn: &mut DbConnection,
        request: RegistrationRequest,
    ) -> Result<CreationChallengeResponse> {
        // Validate email format
        if !request.username.contains('@') {
            return Err(AppError::Validation("Invalid email format".to_string()));
        }

        // Find or create user
        let user = UserService::find_or_create_user(
            conn,
            &request.username,
            &request.display_name,
        )?;

        // Get existing credentials to exclude
        let existing_creds = self.get_user_credentials(conn, user.id)?;
        let exclude_credentials: Vec<CredentialID> = existing_creds
            .iter()
            .map(|cred| CredentialID::from(cred.credential_id.clone()))
            .collect();

        // Create registration challenge
        let user_uuid = user.to_webauthn_user();
        let (ccr, reg_state) = self.webauthn.start_passkey_registration(
            user_uuid,
            &request.username,
            &request.display_name,
            Some(exclude_credentials),
        )?;

        // Store challenge
        self.store_challenge(
            conn,
            &ccr.public_key.challenge,
            Some(&request.username),
            "registration",
        )?;

        Ok(ccr)
    }

    pub fn finish_registration(
        &self,
        conn: &mut DbConnection,
        credential: RegisterPublicKeyCredential,
    ) -> Result<SuccessResponse> {
        // Validate and consume challenge
        let challenge_bytes = self.validate_and_consume_challenge(
            conn,
            &credential.response.client_data_json.challenge,
            "registration",
        )?;

        // Find user by challenge
        let challenge_record = self.find_challenge_by_bytes(conn, &challenge_bytes)?;
        let username = challenge_record.username
            .ok_or_else(|| AppError::BadRequest("Challenge missing username".to_string()))?;
        
        let user = UserService::find_by_username(conn, &username)?;

        // Get existing credentials for verification
        let existing_creds = self.get_user_credentials(conn, user.id)?;
        let passkey_registrations: Vec<PasskeyRegistration> = existing_creds
            .iter()
            .map(|cred| cred.to_webauthn_credential())
            .collect::<Result<Vec<_>>>()?;

        // Verify registration
        let reg_result = self.webauthn.finish_passkey_registration(
            &credential,
            &PasskeyRegistrationState {
                policy: UserVerificationPolicy::Preferred,
                exclude_credentials: passkey_registrations.iter().map(|pr| &pr.cred_id).collect(),
                challenge: Base64UrlSafeData(challenge_bytes),
                credential_algorithms: vec![
                    COSEAlgorithm::ES256,
                    COSEAlgorithm::RS256,
                    COSEAlgorithm::PS256,
                    COSEAlgorithm::EdDSA,
                ],
            },
        )?;

        // Store credential
        let new_credential = Credential::from_webauthn_credential(
            user.id,
            &credential,
            "none", // attestation type
        )?;

        diesel::insert_into(credentials::table)
            .values(&new_credential)
            .execute(conn)
            .map_err(AppError::Database)?;

        Ok(SuccessResponse::new())
    }

    pub fn start_authentication(
        &self,
        conn: &mut DbConnection,
        request: AuthenticationRequest,
    ) -> Result<RequestChallengeResponse> {
        // Find user
        let user = UserService::find_by_username(conn, &request.username)?;

        // Get user credentials
        let user_creds = self.get_user_credentials(conn, user.id)?;
        if user_creds.is_empty() {
            return Err(AppError::Authentication("No credentials found for user".to_string()));
        }

        // Convert to webauthn credentials
        let passkey_registrations: Vec<PasskeyRegistration> = user_creds
            .iter()
            .map(|cred| cred.to_webauthn_credential())
            .collect::<Result<Vec<_>>>()?;

        // Create authentication challenge
        let (rcr, auth_state) = self.webauthn.start_passkey_authentication(&passkey_registrations)?;

        // Store challenge
        self.store_challenge(
            conn,
            &rcr.public_key.challenge,
            Some(&request.username),
            "authentication",
        )?;

        Ok(rcr)
    }

    pub fn finish_authentication(
        &self,
        conn: &mut DbConnection,
        credential: PublicKeyCredential,
    ) -> Result<SuccessResponse> {
        // Validate and consume challenge
        let challenge_bytes = self.validate_and_consume_challenge(
            conn,
            &credential.response.client_data_json.challenge,
            "authentication",
        )?;

        // Find user by challenge
        let challenge_record = self.find_challenge_by_bytes(conn, &challenge_bytes)?;
        let username = challenge_record.username
            .ok_or_else(|| AppError::BadRequest("Challenge missing username".to_string()))?;
        
        let user = UserService::find_by_username(conn, &username)?;

        // Get user credentials
        let user_creds = self.get_user_credentials(conn, user.id)?;
        let passkey_registrations: Vec<PasskeyRegistration> = user_creds
            .iter()
            .map(|cred| cred.to_webauthn_credential())
            .collect::<Result<Vec<_>>>()?;

        // Verify authentication
        let auth_result = self.webauthn.finish_passkey_authentication(
            &credential,
            &PasskeyAuthenticationState {
                credentials: passkey_registrations,
                policy: UserVerificationPolicy::Preferred,
                challenge: Base64UrlSafeData(challenge_bytes),
            },
        )?;

        // Update credential counter
        self.update_credential_counter(
            conn,
            &credential.raw_id.0,
            auth_result.counter(),
        )?;

        Ok(SuccessResponse::new())
    }

    fn store_challenge(
        &self,
        conn: &mut DbConnection,
        challenge: &Base64UrlSafeData,
        username: Option<&str>,
        challenge_type: &str,
    ) -> Result<()> {
        let expires_at = Utc::now() + Duration::milliseconds(self.config.webauthn.challenge_timeout_ms as i64);
        
        let new_challenge = NewChallenge {
            challenge: challenge.0.clone(),
            username: username.map(|s| s.to_string()),
            challenge_type: challenge_type.to_string(),
            expires_at,
        };

        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(conn)
            .map_err(AppError::Database)?;

        Ok(())
    }

    fn validate_and_consume_challenge(
        &self,
        conn: &mut DbConnection,
        challenge: &Base64UrlSafeData,
        expected_type: &str,
    ) -> Result<Vec<u8>> {
        let now = Utc::now();
        
        // Find and validate challenge
        let challenge_record: Challenge = challenges::table
            .filter(challenges::challenge.eq(&challenge.0))
            .filter(challenges::challenge_type.eq(expected_type))
            .filter(challenges::is_used.eq(false))
            .filter(challenges::expires_at.gt(now))
            .first(conn)
            .map_err(|_| AppError::InvalidChallenge)?;

        // Mark challenge as used
        diesel::update(challenges::table.filter(challenges::id.eq(challenge_record.id)))
            .set((
                challenges::is_used.eq(true),
                challenges::used_at.eq(Some(now)),
            ))
            .execute(conn)
            .map_err(AppError::Database)?;

        Ok(challenge_record.challenge)
    }

    fn find_challenge_by_bytes(
        &self,
        conn: &mut DbConnection,
        challenge_bytes: &[u8],
    ) -> Result<Challenge> {
        challenges::table
            .filter(challenges::challenge.eq(challenge_bytes))
            .filter(challenges::is_used.eq(true))
            .first(conn)
            .map_err(AppError::Database)
    }

    fn get_user_credentials(&self, conn: &mut DbConnection, user_id: Uuid) -> Result<Vec<Credential>> {
        credentials::table
            .filter(credentials::user_id.eq(user_id))
            .filter(credentials::is_active.eq(true))
            .load(conn)
            .map_err(AppError::Database)
    }

    fn update_credential_counter(
        &self,
        conn: &mut DbConnection,
        credential_id: &[u8],
        new_counter: u32,
    ) -> Result<()> {
        diesel::update(
            credentials::table.filter(credentials::credential_id.eq(credential_id))
        )
        .set((
            credentials::sign_count.eq(new_counter as i64),
            credentials::last_used_at.eq(Some(Utc::now())),
        ))
        .execute(conn)
        .map_err(AppError::Database)?;

        Ok(())
    }
}