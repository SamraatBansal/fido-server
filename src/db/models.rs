use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::schema::{challenges, credentials, users};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub username: &'a str,
    pub display_name: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(User))]
#[diesel(table_name = credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Vec<u8>,
    pub sign_count: i64,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_backup_eligible: bool,
    pub is_backed_up: bool,
    pub transports: Option<Vec<String>>,
    pub user_verification_requirement: String,
    pub is_active: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Vec<u8>,
    pub sign_count: i64,
    pub is_backup_eligible: bool,
    pub is_backed_up: bool,
    pub transports: Option<Vec<String>>,
    pub user_verification_requirement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = challenges)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub username: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub is_used: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge: Vec<u8>,
    pub username: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

impl Credential {
    pub fn to_webauthn_credential(&self) -> Result<PasskeyRegistration, crate::error::AppError> {
        let credential_id = CredentialID::from(self.credential_id.clone());
        
        // Parse the stored public key
        let public_key = serde_cbor_2::from_slice(&self.credential_public_key)
            .map_err(|e| crate::error::AppError::Internal(format!("Failed to deserialize public key: {}", e)))?;
        
        let aaguid = Uuid::from_slice(&self.aaguid)
            .map_err(|_| crate::error::AppError::Internal("Invalid AAGUID".to_string()))?;
        
        Ok(PasskeyRegistration {
            cred_id: credential_id,
            cred: public_key,
            counter: self.sign_count as u32,
            verified: true,
            backup_eligible: self.is_backup_eligible,
            backup_state: self.is_backed_up,
        })
    }

    pub fn from_webauthn_credential(
        user_id: Uuid,
        credential: &RegisterPublicKeyCredential,
        attestation_type: &str,
    ) -> Result<NewCredential, crate::error::AppError> {
        let credential_public_key = serde_cbor_2::to_vec(&credential.response.parsed_public_key)
            .map_err(|e| crate::error::AppError::Internal(format!("Failed to serialize public key: {}", e)))?;
        
        Ok(NewCredential {
            user_id,
            credential_id: credential.raw_id.0.clone(),
            credential_public_key,
            attestation_type: attestation_type.to_string(),
            aaguid: credential.response.parsed_attestation_data.aaguid.as_bytes().to_vec(),
            sign_count: credential.response.parsed_attestation_data.counter as i64,
            is_backup_eligible: credential.response.parsed_attestation_data.flags.backup_eligible(),
            is_backed_up: credential.response.parsed_attestation_data.flags.backup_state(),
            transports: credential.response.transports.as_ref().map(|t| {
                t.iter().map(|transport| format!("{:?}", transport)).collect()
            }),
            user_verification_requirement: "preferred".to_string(),
        })
    }
}

impl User {
    pub fn to_webauthn_user(&self) -> webauthn_rs::prelude::Uuid {
        webauthn_rs::prelude::Uuid::from_bytes(self.id.into_bytes())
    }
}