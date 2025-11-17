use crate::{error::Result, types::*};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // User operations
    pub async fn create_user(&self, user: NewUser) -> Result<User> {
        let row = sqlx::query!(
            r#"
            INSERT INTO users (username, display_name, user_handle)
            VALUES ($1, $2, $3)
            RETURNING id, username, display_name, user_handle, created_at, updated_at
            "#,
            user.username,
            user.display_name,
            user.user_handle
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(User {
            id: row.id,
            username: row.username,
            display_name: row.display_name,
            user_handle: row.user_handle,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT id, username, display_name, user_handle, created_at, updated_at
            FROM users
            WHERE username = $1
            "#,
            username
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            username: r.username,
            display_name: r.display_name,
            user_handle: r.user_handle,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT id, username, display_name, user_handle, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            username: r.username,
            display_name: r.display_name,
            user_handle: r.user_handle,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    pub async fn get_user_by_handle(&self, user_handle: &[u8]) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT id, username, display_name, user_handle, created_at, updated_at
            FROM users
            WHERE user_handle = $1
            "#,
            user_handle
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            username: r.username,
            display_name: r.display_name,
            user_handle: r.user_handle,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    // Credential operations
    pub async fn create_credential(&self, credential: NewCredential) -> Result<Credential> {
        let row = sqlx::query!(
            r#"
            INSERT INTO credentials (
                user_id, credential_id, public_key, sign_count, 
                backup_eligible, backup_state, attestation_format
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING 
                id, user_id, credential_id, public_key, sign_count,
                backup_eligible, backup_state, attestation_format,
                created_at, last_used_at, updated_at
            "#,
            credential.user_id,
            credential.credential_id,
            credential.public_key,
            credential.sign_count,
            credential.backup_eligible,
            credential.backup_state,
            credential.attestation_format
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Credential {
            id: row.id,
            user_id: row.user_id,
            credential_id: row.credential_id,
            public_key: row.public_key,
            sign_count: row.sign_count,
            backup_eligible: row.backup_eligible,
            backup_state: row.backup_state,
            attestation_format: row.attestation_format,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            updated_at: row.updated_at,
        })
    }

    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let row = sqlx::query!(
            r#"
            SELECT 
                id, user_id, credential_id, public_key, sign_count,
                backup_eligible, backup_state, attestation_format,
                created_at, last_used_at, updated_at
            FROM credentials
            WHERE credential_id = $1
            "#,
            credential_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Credential {
            id: r.id,
            user_id: r.user_id,
            credential_id: r.credential_id,
            public_key: r.public_key,
            sign_count: r.sign_count,
            backup_eligible: r.backup_eligible,
            backup_state: r.backup_state,
            attestation_format: r.attestation_format,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
            updated_at: r.updated_at,
        }))
    }

    pub async fn get_credentials_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let rows = sqlx::query!(
            r#"
            SELECT 
                id, user_id, credential_id, public_key, sign_count,
                backup_eligible, backup_state, attestation_format,
                created_at, last_used_at, updated_at
            FROM credentials
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Credential {
                id: r.id,
                user_id: r.user_id,
                credential_id: r.credential_id,
                public_key: r.public_key,
                sign_count: r.sign_count,
                backup_eligible: r.backup_eligible,
                backup_state: r.backup_state,
                attestation_format: r.attestation_format,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    pub async fn update_credential_sign_count(
        &self,
        credential_id: &[u8],
        sign_count: i64,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE credentials 
            SET sign_count = $1, last_used_at = NOW(), updated_at = NOW()
            WHERE credential_id = $2
            "#,
            sign_count,
            credential_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Registration challenge operations
    pub async fn store_registration_challenge(
        &self,
        challenge: NewRegistrationChallenge,
    ) -> Result<RegistrationChallenge> {
        let row = sqlx::query!(
            r#"
            INSERT INTO registration_challenges (user_id, challenge, state_data, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, challenge, state_data, expires_at, created_at
            "#,
            challenge.user_id,
            challenge.challenge,
            challenge.state_data,
            challenge.expires_at
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(RegistrationChallenge {
            id: row.id,
            user_id: row.user_id,
            challenge: row.challenge,
            state_data: row.state_data,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }

    pub async fn get_registration_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<Option<RegistrationChallenge>> {
        let row = sqlx::query!(
            r#"
            SELECT id, user_id, challenge, state_data, expires_at, created_at
            FROM registration_challenges
            WHERE challenge = $1 AND expires_at > NOW()
            "#,
            challenge
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| RegistrationChallenge {
            id: r.id,
            user_id: r.user_id,
            challenge: r.challenge,
            state_data: r.state_data,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }))
    }

    pub async fn delete_registration_challenge(&self, challenge: &[u8]) -> Result<()> {
        sqlx::query!(
            "DELETE FROM registration_challenges WHERE challenge = $1",
            challenge
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Authentication challenge operations
    pub async fn store_authentication_challenge(
        &self,
        challenge: NewAuthenticationChallenge,
    ) -> Result<AuthenticationChallenge> {
        let row = sqlx::query!(
            r#"
            INSERT INTO authentication_challenges (user_id, challenge, state_data, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, challenge, state_data, expires_at, created_at
            "#,
            challenge.user_id,
            challenge.challenge,
            challenge.state_data,
            challenge.expires_at
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(AuthenticationChallenge {
            id: row.id,
            user_id: row.user_id,
            challenge: row.challenge,
            state_data: row.state_data,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }

    pub async fn get_authentication_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<Option<AuthenticationChallenge>> {
        let row = sqlx::query!(
            r#"
            SELECT id, user_id, challenge, state_data, expires_at, created_at
            FROM authentication_challenges
            WHERE challenge = $1 AND expires_at > NOW()
            "#,
            challenge
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| AuthenticationChallenge {
            id: r.id,
            user_id: r.user_id,
            challenge: r.challenge,
            state_data: r.state_data,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }))
    }

    pub async fn delete_authentication_challenge(&self, challenge: &[u8]) -> Result<()> {
        sqlx::query!(
            "DELETE FROM authentication_challenges WHERE challenge = $1",
            challenge
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Cleanup expired challenges
    pub async fn cleanup_expired_challenges(&self) -> Result<()> {
        sqlx::query!("DELETE FROM registration_challenges WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        sqlx::query!("DELETE FROM authentication_challenges WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}