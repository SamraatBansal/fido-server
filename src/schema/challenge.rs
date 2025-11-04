//! Challenge schema and database operations

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::DbPool;
use crate::error::{AppError, Result};

/// Challenge model for database
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: String,
    pub username: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// New challenge for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub challenge: String,
    pub username: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

/// Challenge repository
pub struct ChallengeRepository {
    pool: DbPool,
}

impl ChallengeRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Create a new challenge
    pub async fn create_challenge(&self, new_challenge: NewChallenge) -> Result<Challenge> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let challenge = diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .returning(Challenge::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create challenge: {}", e)))?;

        Ok(challenge)
    }

    /// Get challenge by challenge string
    pub async fn get_challenge_by_string(&self, challenge: &str) -> Result<Option<Challenge>> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let challenge_record = challenges::table
            .filter(challenges::challenge.eq(challenge))
            .first::<Challenge>(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get challenge: {}", e)))?;

        Ok(challenge_record)
    }

    /// Consume and delete a challenge
    pub async fn consume_challenge(&self, challenge: &str) -> Result<Option<Challenge>> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let challenge_record = challenges::table
            .filter(challenges::challenge.eq(challenge))
            .first::<Challenge>(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get challenge: {}", e)))?;

        // Delete the challenge if found
        if challenge_record.is_some() {
            diesel::delete(challenges::table.filter(challenges::challenge.eq(challenge)))
                .execute(&mut conn)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to delete challenge: {}", e)))?;
        }

        Ok(challenge_record)
    }

    /// Delete expired challenges
    pub async fn cleanup_expired_challenges(&self) -> Result<usize> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let deleted_count = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(Utc::now()))
        )
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to cleanup expired challenges: {}", e)))?;

        Ok(deleted_count)
    }

    /// Delete all challenges for a username
    pub async fn delete_challenges_by_username(&self, username: &str) -> Result<()> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        diesel::delete(challenges::table.filter(challenges::username.eq(username)))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete challenges: {}", e)))?;

        Ok(())
    }
}

/// Challenge type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

impl ChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeType::Registration => "registration",
            ChallengeType::Authentication => "authentication",
        }
    }
}

impl From<&str> for ChallengeType {
    fn from(s: &str) -> Self {
        match s {
            "registration" => ChallengeType::Registration,
            "authentication" => ChallengeType::Authentication,
            _ => panic!("Invalid challenge type: {}", s),
        }
    }
}