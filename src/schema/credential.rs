//! Credential schema and database operations

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::DbPool;
use crate::error::{AppError, Result};

/// Credential model for database
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub attestation_type: Option<String>,
    pub aaguid: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// New credential for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub attestation_type: Option<String>,
    pub aaguid: Option<Uuid>,
}

/// Credential repository
pub struct CredentialRepository {
    pool: DbPool,
}

impl CredentialRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Create a new credential
    pub async fn create_credential(&self, new_credential: NewCredential) -> Result<Credential> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let credential = diesel::insert_into(credentials::table)
            .values(&new_credential)
            .returning(Credential::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create credential: {}", e)))?;

        Ok(credential)
    }

    /// Get credential by credential ID
    pub async fn get_credential_by_id(&self, credential_id: &str) -> Result<Option<Credential>> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let credential = credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .first::<Credential>(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get credential: {}", e)))?;

        Ok(credential)
    }

    /// Get credentials by user ID
    pub async fn get_credentials_by_user(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let credentials = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .order(credentials::created_at.desc())
            .load::<Credential>(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to get credentials: {}", e)))?;

        Ok(credentials)
    }

    /// Update sign count
    pub async fn update_sign_count(&self, credential_id: &str, sign_count: i32) -> Result<()> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        diesel::update(
            credentials::table.filter(credentials::credential_id.eq(credential_id))
        )
        .set((
            credentials::sign_count.eq(sign_count),
            credentials::last_used_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update sign count: {}", e)))?;

        Ok(())
    }

    /// Delete credential
    pub async fn delete_credential(&self, credential_id: &str) -> Result<()> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        diesel::delete(credentials::table.filter(credentials::credential_id.eq(credential_id)))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete credential: {}", e)))?;

        Ok(())
    }

    /// Delete all credentials for a user
    pub async fn delete_credentials_by_user(&self, user_id: &Uuid) -> Result<()> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        diesel::delete(credentials::table.filter(credentials::user_id.eq(user_id)))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete credentials: {}", e)))?;

        Ok(())
    }
}