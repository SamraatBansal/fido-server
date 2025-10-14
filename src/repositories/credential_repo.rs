//! Credential repository implementation

use crate::error::{AppError, Result};
use crate::models::Credential;
use crate::repositories::CredentialRepository;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::pg::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::proto::{COSEAlgorithmIdentifier, AuthenticatorTransport};

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Varchar,
        public_key -> Bytea,
        sign_count -> BigInt,
        attestation_type -> Varchar,
        aaguid -> Nullable<Uuid>,
        transports -> Array<Text>,
        algorithm -> Integer,
        created_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
        is_active -> Bool,
    }
}

#[derive(Queryable, Insertable, AsChangeset)]
#[diesel(table_name = credentials)]
struct CredentialRow {
    id: Uuid,
    user_id: Uuid,
    credential_id: String,
    public_key: Vec<u8>,
    sign_count: i64,
    attestation_type: String,
    aaguid: Option<Uuid>,
    transports: Vec<String>,
    algorithm: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    is_active: bool,
}

impl From<Credential> for CredentialRow {
    fn from(credential: Credential) -> Self {
        CredentialRow {
            id: credential.id,
            user_id: credential.user_id,
            credential_id: credential.credential_id,
            public_key: credential.public_key,
            sign_count: credential.sign_count as i64,
            attestation_type: credential.attestation_type,
            aaguid: credential.aaguid,
            transports: credential.transports.iter().map(|t| format!("{:?}", t)).collect(),
            algorithm: credential.algorithm as i32,
            created_at: credential.created_at,
            last_used_at: credential.last_used_at,
            is_active: credential.is_active,
        }
    }
}

impl TryFrom<CredentialRow> for Credential {
    type Error = AppError;

    fn try_from(row: CredentialRow) -> Result<Self> {
        let transports: Result<Vec<AuthenticatorTransport>> = row.transports
            .iter()
            .map(|t| {
                match t.as_str() {
                    "usb" => Ok(AuthenticatorTransport::Usb),
                    "nfc" => Ok(AuthenticatorTransport::Nfc),
                    "ble" => Ok(AuthenticatorTransport::Ble),
                    "internal" => Ok(AuthenticatorTransport::Internal),
                    _ => Err(AppError::InvalidInput(format!("Invalid transport: {}", t))),
                }
            })
            .collect();

        let algorithm = match COSEAlgorithmIdentifier::from_i32(row.algorithm) {
            Some(alg) => alg,
            None => return Err(AppError::InvalidInput(format!("Invalid algorithm: {}", row.algorithm))),
        };

        Ok(Credential {
            id: row.id,
            user_id: row.user_id,
            credential_id: row.credential_id,
            public_key: row.public_key,
            sign_count: row.sign_count as u64,
            attestation_type: row.attestation_type,
            aaguid: row.aaguid,
            transports: transports?,
            algorithm,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            is_active: row.is_active,
        })
    }
}

pub struct CredentialRepositoryImpl {
    pool: Arc<Pool<ConnectionManager<PgConnection>>>,
}

impl CredentialRepositoryImpl {
    pub fn new(pool: Arc<Pool<ConnectionManager<PgConnection>>>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialRepository for CredentialRepositoryImpl {
    async fn create_credential(&self, credential: &Credential) -> Result<()> {
        let credential_row = CredentialRow::from(credential.clone());
        let mut conn = self.pool.get()?;
        
        diesel::insert_into(credentials::table)
            .values(&credential_row)
            .execute(&mut conn)?;
            
        Ok(())
    }

    async fn get_credential_by_id(&self, credential_id: &str) -> Result<Option<Credential>> {
        let mut conn = self.pool.get()?;
        
        let credential_row: Option<CredentialRow> = credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .first(&mut conn)
            .optional()?;
            
        match credential_row {
            Some(row) => Ok(Some(Credential::try_from(row)?)),
            None => Ok(None),
        }
    }

    async fn get_credentials_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.pool.get()?;
        
        let credential_rows: Vec<CredentialRow> = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .filter(credentials::is_active.eq(true))
            .load(&mut conn)?;
            
        let mut credentials = Vec::new();
        for row in credential_rows {
            credentials.push(Credential::try_from(row)?);
        }
            
        Ok(credentials)
    }

    async fn update_credential(&self, credential: &Credential) -> Result<()> {
        let credential_row = CredentialRow::from(credential.clone());
        let mut conn = self.pool.get()?;
        
        diesel::update(credentials::table.filter(credentials::id.eq(&credential.id)))
            .set(&credential_row)
            .execute(&mut conn)?;
            
        Ok(())
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<()> {
        let mut conn = self.pool.get()?;
        
        diesel::delete(credentials::table.filter(credentials::credential_id.eq(credential_id)))
            .execute(&mut conn)?;
            
        Ok(())
    }

    async fn credential_exists(&self, credential_id: &str) -> Result<bool> {
        let mut conn = self.pool.get()?;
        
        let count: i64 = credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .count()
            .get_result(&mut conn)?;
            
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_credential_crud_operations() {
        // These tests would require a test database
        // For now, we'll skip actual database tests
    }
}