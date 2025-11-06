use crate::db::models::{Challenge, NewChallenge};
use crate::error::{AppError, Result};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct ChallengeRepository {
    pool: PgPool,
}

impl ChallengeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn store_challenge(&self, challenge: NewChallenge) -> Result<Challenge> {
        let stored_challenge = sqlx::query_as!(
            Challenge,
            r#"
            INSERT INTO challenges (id, user_id, challenge_type, challenge_data, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, user_id, challenge_type, challenge_data, expires_at, created_at
            "#,
            challenge.id,
            challenge.user_id,
            challenge.challenge_type,
            challenge.challenge_data,
            challenge.expires_at
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(stored_challenge)
    }

    pub async fn get_challenge(&self, challenge_id: &str) -> Result<Option<Challenge>> {
        let challenge = sqlx::query_as!(
            Challenge,
            r#"
            SELECT id, user_id, challenge_type, challenge_data, expires_at, created_at
            FROM challenges
            WHERE id = $1 AND expires_at > NOW()
            "#,
            challenge_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(challenge)
    }

    pub async fn consume_challenge(&self, challenge_id: &str) -> Result<Option<Challenge>> {
        let challenge = sqlx::query_as!(
            Challenge,
            r#"
            DELETE FROM challenges
            WHERE id = $1 AND expires_at > NOW()
            RETURNING id, user_id, challenge_type, challenge_data, expires_at, created_at
            "#,
            challenge_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(challenge)
    }

    pub async fn get_and_consume_challenge(
        &self,
        challenge_id: &str,
        user_id: Option<Uuid>,
    ) -> Result<Option<Challenge>> {
        let challenge = if let Some(uid) = user_id {
            sqlx::query_as!(
                Challenge,
                r#"
                DELETE FROM challenges
                WHERE id = $1 AND user_id = $2 AND expires_at > NOW()
                RETURNING id, user_id, challenge_type, challenge_data, expires_at, created_at
                "#,
                challenge_id,
                uid
            )
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_as!(
                Challenge,
                r#"
                DELETE FROM challenges
                WHERE id = $1 AND user_id IS NULL AND expires_at > NOW()
                RETURNING id, user_id, challenge_type, challenge_data, expires_at, created_at
                "#,
                challenge_id
            )
            .fetch_optional(&self.pool)
            .await?
        };

        Ok(challenge)
    }

    pub async fn cleanup_expired_challenges(&self) -> Result<u64> {
        let result = sqlx::query!(
            "DELETE FROM challenges WHERE expires_at <= NOW()"
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn get_user_challenges(&self, user_id: Uuid) -> Result<Vec<Challenge>> {
        let challenges = sqlx::query_as!(
            Challenge,
            r#"
            SELECT id, user_id, challenge_type, challenge_data, expires_at, created_at
            FROM challenges
            WHERE user_id = $1 AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(challenges)
    }

    pub async fn delete_user_challenges(&self, user_id: Uuid, challenge_type: &str) -> Result<u64> {
        let result = sqlx::query!(
            "DELETE FROM challenges WHERE user_id = $1 AND challenge_type = $2",
            user_id,
            challenge_type
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}