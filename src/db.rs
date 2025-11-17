use crate::{error::Result, types::*};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
}

impl Database {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // User operations
    pub async fn create_user(&self, user: NewUser) -> Result<User> {
        let row = sqlx::query(
            r#"
            INSERT INTO users (username, display_name, user_handle)
            VALUES ($1, $2, $3)
            RETURNING id, username, display_name, user_handle, created_at, updated_at
            "#
        )
        .bind(&user.username)
        .bind(&user.display_name)
        .bind(&user.user_handle)
        .fetch_one(&self.pool)
        .await?;

        Ok(User {
            id: row.get("id"),
            username: row.get("username"),
            display_name: row.get("display_name"),
            user_handle: row.get("user_handle"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, display_name, user_handle, created_at, updated_at
            FROM users
            WHERE username = $1
            "#
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            display_name: r.get("display_name"),
            user_handle: r.get("user_handle"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, display_name, user_handle, created_at, updated_at
            FROM users
            WHERE id = $1
            "#
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            display_name: r.get("display_name"),
            user_handle: r.get("user_handle"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn get_user_by_handle(&self, user_handle: &[u8]) -> Result<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, display_name, user_handle, created_at, updated_at
            FROM users
            WHERE user_handle = $1
            "#
        )
        .bind(user_handle)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            display_name: r.get("display_name"),
            user_handle: r.get("user_handle"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    // Credential operations
    pub async fn create_credential(&self, credential: NewCredential) -> Result<Credential> {
        let row = sqlx::query(
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
            "#
        )
        .bind(credential.user_id)
        .bind(&credential.credential_id)
        .bind(&credential.public_key)
        .bind(credential.sign_count)
        .bind(credential.backup_eligible)
        .bind(credential.backup_state)
        .bind(&credential.attestation_format)
        .fetch_one(&self.pool)
        .await?;

        Ok(Credential {
            id: row.get("id"),
            user_id: row.get("user_id"),
            credential_id: row.get("credential_id"),
            public_key: row.get("public_key"),
            sign_count: row.get("sign_count"),
            backup_eligible: row.get("backup_eligible"),
            backup_state: row.get("backup_state"),
            attestation_format: row.get("attestation_format"),
            created_at: row.get("created_at"),
            last_used_at: row.get("last_used_at"),
            updated_at: row.get("updated_at"),
        })
    }

    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let row = sqlx::query(
            r#"
            SELECT 
                id, user_id, credential_id, public_key, sign_count,
                backup_eligible, backup_state, attestation_format,
                created_at, last_used_at, updated_at
            FROM credentials
            WHERE credential_id = $1
            "#
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Credential {
            id: r.get("id"),
            user_id: r.get("user_id"),
            credential_id: r.get("credential_id"),
            public_key: r.get("public_key"),
            sign_count: r.get("sign_count"),
            backup_eligible: r.get("backup_eligible"),
            backup_state: r.get("backup_state"),
            attestation_format: r.get("attestation_format"),
            created_at: r.get("created_at"),
            last_used_at: r.get("last_used_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn get_credentials_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let rows = sqlx::query(
            r#"
            SELECT 
                id, user_id, credential_id, public_key, sign_count,
                backup_eligible, backup_state, attestation_format,
                created_at, last_used_at, updated_at
            FROM credentials
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Credential {
                id: r.get("id"),
                user_id: r.get("user_id"),
                credential_id: r.get("credential_id"),
                public_key: r.get("public_key"),
                sign_count: r.get("sign_count"),
                backup_eligible: r.get("backup_eligible"),
                backup_state: r.get("backup_state"),
                attestation_format: r.get("attestation_format"),
                created_at: r.get("created_at"),
                last_used_at: r.get("last_used_at"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }

    pub async fn update_credential_sign_count(
        &self,
        credential_id: &[u8],
        sign_count: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE credentials 
            SET sign_count = $1, last_used_at = NOW(), updated_at = NOW()
            WHERE credential_id = $2
            "#
        )
        .bind(sign_count)
        .bind(credential_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Registration challenge operations
    pub async fn store_registration_challenge(
        &self,
        challenge: NewRegistrationChallenge,
    ) -> Result<RegistrationChallenge> {
        let row = sqlx::query(
            r#"
            INSERT INTO registration_challenges (user_id, challenge, state_data, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, challenge, state_data, expires_at, created_at
            "#
        )
        .bind(challenge.user_id)
        .bind(&challenge.challenge)
        .bind(&challenge.state_data)
        .bind(challenge.expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(RegistrationChallenge {
            id: row.get("id"),
            user_id: row.get("user_id"),
            challenge: row.get("challenge"),
            state_data: row.get("state_data"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
        })
    }

    pub async fn get_registration_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<Option<RegistrationChallenge>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, challenge, state_data, expires_at, created_at
            FROM registration_challenges
            WHERE challenge = $1 AND expires_at > NOW()
            "#
        )
        .bind(challenge)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| RegistrationChallenge {
            id: r.get("id"),
            user_id: r.get("user_id"),
            challenge: r.get("challenge"),
            state_data: r.get("state_data"),
            expires_at: r.get("expires_at"),
            created_at: r.get("created_at"),
        }))
    }

    pub async fn delete_registration_challenge(&self, challenge: &[u8]) -> Result<()> {
        sqlx::query("DELETE FROM registration_challenges WHERE challenge = $1")
            .bind(challenge)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // Authentication challenge operations
    pub async fn store_authentication_challenge(
        &self,
        challenge: NewAuthenticationChallenge,
    ) -> Result<AuthenticationChallenge> {
        let row = sqlx::query(
            r#"
            INSERT INTO authentication_challenges (user_id, challenge, state_data, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, challenge, state_data, expires_at, created_at
            "#
        )
        .bind(challenge.user_id)
        .bind(&challenge.challenge)
        .bind(&challenge.state_data)
        .bind(challenge.expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(AuthenticationChallenge {
            id: row.get("id"),
            user_id: row.get("user_id"),
            challenge: row.get("challenge"),
            state_data: row.get("state_data"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
        })
    }

    pub async fn get_authentication_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<Option<AuthenticationChallenge>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, challenge, state_data, expires_at, created_at
            FROM authentication_challenges
            WHERE challenge = $1 AND expires_at > NOW()
            "#
        )
        .bind(challenge)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| AuthenticationChallenge {
            id: r.get("id"),
            user_id: r.get("user_id"),
            challenge: r.get("challenge"),
            state_data: r.get("state_data"),
            expires_at: r.get("expires_at"),
            created_at: r.get("created_at"),
        }))
    }

    pub async fn delete_authentication_challenge(&self, challenge: &[u8]) -> Result<()> {
        sqlx::query("DELETE FROM authentication_challenges WHERE challenge = $1")
            .bind(challenge)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // Cleanup expired challenges
    pub async fn cleanup_expired_challenges(&self) -> Result<()> {
        sqlx::query("DELETE FROM registration_challenges WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        sqlx::query("DELETE FROM authentication_challenges WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}