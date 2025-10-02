use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub passkey: Passkey,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    pub id: Uuid,
    pub credential_id: Uuid,
    pub external_id: String,
    pub external_type: String,
    pub created_at: DateTime<Utc>,
}

pub struct Storage {
    pool: PgPool,
}

impl Storage {
    pub async fn new(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        let storage = Storage { pool };
        storage.migrate().await?;
        Ok(storage)
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    pub async fn create_user(
        &self,
        user_id: &str,
        username: &str,
        display_name: &str,
    ) -> anyhow::Result<User> {
        let now = Utc::now();
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (user_id, username, display_name, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $4)
            RETURNING *
            "#,
            user_id,
            username,
            display_name,
            now
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> anyhow::Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn create_credential(
        &self,
        user_id: Uuid,
        credential_id: &str,
        passkey: &Passkey,
    ) -> anyhow::Result<Credential> {
        let now = Utc::now();
        let passkey_json = serde_json::to_value(passkey)?;
        
        let credential = sqlx::query_as!(
            Credential,
            r#"
            INSERT INTO credentials (user_id, credential_id, passkey, created_at, is_active)
            VALUES ($1, $2, $3, $4, true)
            RETURNING *
            "#,
            user_id,
            credential_id,
            passkey_json,
            now
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(credential)
    }

    pub async fn get_credentials_by_user(&self, user_id: &str) -> anyhow::Result<Vec<Credential>> {
        let credentials = sqlx::query_as!(
            Credential,
            r#"
            SELECT c.* FROM credentials c
            JOIN users u ON c.user_id = u.id
            WHERE u.user_id = $1 AND c.is_active = true
            ORDER BY c.created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(credentials)
    }

    pub async fn get_credential_by_id(&self, credential_id: &str) -> anyhow::Result<Option<Credential>> {
        let credential = sqlx::query_as!(
            Credential,
            "SELECT * FROM credentials WHERE credential_id = $1 AND is_active = true",
            credential_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(credential)
    }

    pub async fn revoke_credential(&self, credential_id: &str) -> anyhow::Result<()> {
        sqlx::query!(
            "UPDATE credentials SET is_active = false WHERE credential_id = $1",
            credential_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_credential_last_used(&self, credential_id: &str) -> anyhow::Result<()> {
        let now = Utc::now();
        sqlx::query!(
            "UPDATE credentials SET last_used_at = $1 WHERE credential_id = $2",
            now,
            credential_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_mapping(
        &self,
        credential_id: Uuid,
        external_id: &str,
        external_type: &str,
    ) -> anyhow::Result<Mapping> {
        let now = Utc::now();
        let mapping = sqlx::query_as!(
            Mapping,
            r#"
            INSERT INTO mappings (credential_id, external_id, external_type, created_at)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
            credential_id,
            external_id,
            external_type,
            now
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(mapping)
    }

    pub async fn get_mapping_by_id(&self, mapping_id: Uuid) -> anyhow::Result<Option<Mapping>> {
        let mapping = sqlx::query_as!(
            Mapping,
            "SELECT * FROM mappings WHERE id = $1",
            mapping_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(mapping)
    }

    pub async fn get_mapping_by_credential(&self, credential_id: &str) -> anyhow::Result<Vec<Mapping>> {
        let mappings = sqlx::query_as!(
            Mapping,
            r#"
            SELECT m.* FROM mappings m
            JOIN credentials c ON m.credential_id = c.id
            WHERE c.credential_id = $1
            ORDER BY m.created_at DESC
            "#,
            credential_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(mappings)
    }

    pub async fn delete_mapping(&self, mapping_id: Uuid) -> anyhow::Result<()> {
        sqlx::query!("DELETE FROM mappings WHERE id = $1", mapping_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}