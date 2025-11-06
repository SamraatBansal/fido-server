use crate::db::models::{ActiveCredential, Credential, NewCredential};
use crate::error::{AppError, Result};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct CredentialRepository {
    pool: PgPool,
}

impl CredentialRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_credential(&self, new_credential: NewCredential) -> Result<Credential> {
        let credential = sqlx::query_as!(
            Credential,
            r#"
            INSERT INTO credentials (
                user_id, credential_id, public_key, sign_count,
                backup_eligible, backup_state, attestation_type, 
                transports, aaguid
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, user_id, credential_id, public_key, sign_count,
                      backup_eligible, backup_state, attestation_type,
                      transports, aaguid, created_at, last_used_at, status
            "#,
            new_credential.user_id,
            new_credential.credential_id,
            new_credential.public_key,
            new_credential.sign_count,
            new_credential.backup_eligible,
            new_credential.backup_state,
            new_credential.attestation_type,
            new_credential.transports.as_deref(),
            new_credential.aaguid
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(credential)
    }

    pub async fn get_user_credentials(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let credentials = sqlx::query_as!(
            Credential,
            r#"
            SELECT id, user_id, credential_id, public_key, sign_count,
                   backup_eligible, backup_state, attestation_type,
                   transports, aaguid, created_at, last_used_at, status
            FROM credentials 
            WHERE user_id = $1 AND status = 'active'
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(credentials)
    }

    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let credential = sqlx::query_as!(
            Credential,
            r#"
            SELECT id, user_id, credential_id, public_key, sign_count,
                   backup_eligible, backup_state, attestation_type,
                   transports, aaguid, created_at, last_used_at, status
            FROM credentials 
            WHERE credential_id = $1 AND status = 'active'
            "#,
            credential_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(credential)
    }

    pub async fn get_active_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<ActiveCredential>> {
        let credential = sqlx::query_as!(
            ActiveCredential,
            r#"
            SELECT c.id, c.user_id, c.credential_id, c.public_key, c.sign_count,
                   c.backup_eligible, c.backup_state, c.attestation_type,
                   c.transports, c.aaguid, c.created_at, c.last_used_at, c.status,
                   u.username, u.display_name
            FROM active_credentials c
            JOIN users u ON c.user_id = u.id
            WHERE c.credential_id = $1
            "#,
            credential_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(credential)
    }

    pub async fn update_sign_count(
        &self,
        credential_id: &[u8],
        new_count: u32,
    ) -> Result<()> {
        let now = Utc::now();
        sqlx::query!(
            r#"
            UPDATE credentials 
            SET sign_count = $2, last_used_at = $3
            WHERE credential_id = $1 AND status = 'active'
            "#,
            credential_id,
            new_count as i64,
            now
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_credentials_for_user(&self, username: &str) -> Result<Vec<ActiveCredential>> {
        let credentials = sqlx::query_as!(
            ActiveCredential,
            r#"
            SELECT c.id, c.user_id, c.credential_id, c.public_key, c.sign_count,
                   c.backup_eligible, c.backup_state, c.attestation_type,
                   c.transports, c.aaguid, c.created_at, c.last_used_at, c.status,
                   u.username, u.display_name
            FROM active_credentials c
            JOIN users u ON c.user_id = u.id
            WHERE u.username = $1
            ORDER BY c.last_used_at DESC NULLS LAST, c.created_at DESC
            "#,
            username
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(credentials)
    }

    pub async fn deactivate_credential(&self, credential_uuid: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE credentials SET status = 'inactive' WHERE id = $1",
            credential_uuid
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn count_user_credentials(&self, user_id: Uuid) -> Result<i64> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM credentials WHERE user_id = $1 AND status = 'active'",
            user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count.unwrap_or(0))
    }
}