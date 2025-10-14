//! Challenge repository implementation

use crate::error::{AppError, Result};
use crate::models::{Challenge, ChallengeType};
use crate::repositories::ChallengeRepository;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::pg::PgConnection;
use std::sync::Arc;
use uuid::Uuid;

diesel::table! {
    challenges (id) {
        id -> Uuid,
        challenge_hash -> Bytea,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        is_used -> Bool,
    }
}

#[derive(Queryable, Insertable, AsChangeset)]
#[diesel(table_name = challenges)]
struct ChallengeRow {
    id: Uuid,
    challenge_hash: Vec<u8>,
    user_id: Option<Uuid>,
    challenge_type: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    created_at: chrono::DateTime<chrono::Utc>,
    is_used: bool,
}

impl From<Challenge> for ChallengeRow {
    fn from(challenge: Challenge) -> Self {
        ChallengeRow {
            id: challenge.id,
            challenge_hash: challenge.challenge_hash,
            user_id: challenge.user_id,
            challenge_type: challenge.challenge_type.as_str().to_string(),
            expires_at: challenge.expires_at,
            created_at: challenge.created_at,
            is_used: challenge.is_used,
        }
    }
}

impl TryFrom<ChallengeRow> for Challenge {
    type Error = AppError;

    fn try_from(row: ChallengeRow) -> Result<Self> {
        let challenge_type = match row.challenge_type.as_str() {
            "registration" => ChallengeType::Registration,
            "authentication" => ChallengeType::Authentication,
            _ => return Err(AppError::InvalidInput(format!("Invalid challenge type: {}", row.challenge_type))),
        };

        Ok(Challenge {
            id: row.id,
            challenge_hash: row.challenge_hash,
            user_id: row.user_id,
            challenge_type,
            expires_at: row.expires_at,
            created_at: row.created_at,
            is_used: row.is_used,
        })
    }
}

pub struct ChallengeRepositoryImpl {
    pool: Arc<Pool<ConnectionManager<PgConnection>>>,
}

impl ChallengeRepositoryImpl {
    pub fn new(pool: Arc<Pool<ConnectionManager<PgConnection>>>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChallengeRepository for ChallengeRepositoryImpl {
    async fn create_challenge(&self, challenge: &Challenge) -> Result<()> {
        let challenge_row = ChallengeRow::from(challenge.clone());
        let mut conn = self.pool.get()?;
        
        diesel::insert_into(challenges::table)
            .values(&challenge_row)
            .execute(&mut conn)?;
            
        Ok(())
    }

    async fn get_challenge_by_hash(&self, challenge_hash: &[u8], user_id: Option<&Uuid>, challenge_type: &ChallengeType) -> Result<Option<Challenge>> {
        let mut conn = self.pool.get()?;
        let challenge_type_str = challenge_type.as_str();
        
        let mut query = challenges::table
            .filter(challenges::challenge_hash.eq(challenge_hash))
            .filter(challenges::challenge_type.eq(challenge_type_str))
            .filter(challenges::is_used.eq(false))
            .into_boxed();

        if let Some(uid) = user_id {
            query = query.filter(challenges::user_id.eq(uid));
        } else {
            query = query.filter(challenges::user_id.is_null());
        }
        
        let challenge_row: Option<ChallengeRow> = query
            .first(&mut conn)
            .optional()?;
            
        match challenge_row {
            Some(row) => Ok(Some(Challenge::try_from(row)?)),
            None => Ok(None),
        }
    }

    async fn mark_challenge_used(&self, challenge_id: &Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        
        diesel::update(challenges::table.filter(challenges::id.eq(challenge_id)))
            .set(challenges::is_used.eq(true))
            .execute(&mut conn)?;
            
        Ok(())
    }

    async fn cleanup_expired_challenges(&self) -> Result<u64> {
        let mut conn = self.pool.get()?;
        
        let count = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(chrono::Utc::now()))
        ).execute(&mut conn)?;
            
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_crud_operations() {
        // These tests would require a test database
        // For now, we'll skip actual database tests
    }
}