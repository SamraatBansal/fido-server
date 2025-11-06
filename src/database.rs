use chrono::{DateTime, Utc};
use diesel::prelude::*;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::*;
use crate::schema::*;

pub type DbPool = deadpool_diesel::postgres::Pool;

pub async fn create_pool(database_url: &str) -> Result<DbPool> {
    let mgr = deadpool_diesel::postgres::Manager::new(database_url, deadpool_diesel::postgres::RecyclingMethod::Fast);
    let pool = deadpool_diesel::postgres::Pool::builder(mgr)
        .build()
        .map_err(|e| AppError::DatabaseError(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::Unknown,
            Box::new(e.to_string()),
        )))?;
    Ok(pool)
}

#[derive(Clone)]
pub struct DatabaseService {
    pool: DbPool,
}

impl DatabaseService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    // User operations
    pub async fn create_user(&self, username: &str, display_name: &str) -> Result<User> {
        let conn = self.pool.get().await?;
        
        let new_user = NewUser {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
        };

        let user = conn.interact(move |conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .get_result::<User>(conn)
        }).await??;

        Ok(user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get().await?;
        
        let user = users::table
            .filter(users::username.eq(username))
            .first::<User>(&mut conn)
            .await
            .optional()?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let mut conn = self.pool.get().await?;
        
        let user = users::table
            .find(user_id)
            .first::<User>(&mut conn)
            .await
            .optional()?;

        Ok(user)
    }

    // Credential operations
    pub async fn store_credential(&self, new_credential: NewCredential) -> Result<Credential> {
        let mut conn = self.pool.get().await?;
        
        let credential = diesel::insert_into(credentials::table)
            .values(&new_credential)
            .get_result::<Credential>(&mut conn)
            .await?;

        Ok(credential)
    }

    pub async fn get_credentials_for_user(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.pool.get().await?;
        
        let credentials = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .load::<Credential>(&mut conn)
            .await?;

        Ok(credentials)
    }

    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let mut conn = self.pool.get().await?;
        
        let credential = credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .first::<Credential>(&mut conn)
            .await
            .optional()?;

        Ok(credential)
    }

    pub async fn update_credential_sign_count(&self, credential_id: &[u8], new_count: u32) -> Result<()> {
        let mut conn = self.pool.get().await?;
        
        diesel::update(credentials::table.filter(credentials::credential_id.eq(credential_id)))
            .set((
                credentials::sign_count.eq(new_count as i64),
                credentials::last_used.eq(Some(Utc::now())),
            ))
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    // Registration challenge operations
    pub async fn store_registration_challenge(
        &self,
        user_id: Uuid,
        challenge: &[u8],
        state_data: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<RegistrationChallenge> {
        let mut conn = self.pool.get().await?;
        
        // Clean up expired challenges first
        self.cleanup_expired_registration_challenges().await?;
        
        let new_challenge = NewRegistrationChallenge {
            user_id,
            challenge: challenge.to_vec(),
            state_data: state_data.to_vec(),
            expires_at,
        };

        let challenge = diesel::insert_into(registration_challenges::table)
            .values(&new_challenge)
            .get_result::<RegistrationChallenge>(&mut conn)
            .await?;

        Ok(challenge)
    }

    pub async fn get_registration_challenge(
        &self,
        user_id: Uuid,
        challenge: &[u8],
    ) -> Result<Option<RegistrationChallenge>> {
        let mut conn = self.pool.get().await?;
        
        let now = Utc::now();
        let challenge_record = registration_challenges::table
            .filter(
                registration_challenges::user_id
                    .eq(user_id)
                    .and(registration_challenges::challenge.eq(challenge))
                    .and(registration_challenges::expires_at.gt(now)),
            )
            .first::<RegistrationChallenge>(&mut conn)
            .await
            .optional()?;

        Ok(challenge_record)
    }

    pub async fn delete_registration_challenge(&self, user_id: Uuid, challenge: &[u8]) -> Result<()> {
        let mut conn = self.pool.get().await?;
        
        diesel::delete(
            registration_challenges::table.filter(
                registration_challenges::user_id
                    .eq(user_id)
                    .and(registration_challenges::challenge.eq(challenge)),
            ),
        )
        .execute(&mut conn)
        .await?;

        Ok(())
    }

    // Authentication challenge operations
    pub async fn store_authentication_challenge(
        &self,
        user_id: Uuid,
        challenge: &[u8],
        state_data: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<AuthenticationChallenge> {
        let mut conn = self.pool.get().await?;
        
        // Clean up expired challenges first
        self.cleanup_expired_authentication_challenges().await?;
        
        let new_challenge = NewAuthenticationChallenge {
            user_id,
            challenge: challenge.to_vec(),
            state_data: state_data.to_vec(),
            expires_at,
        };

        let challenge = diesel::insert_into(authentication_challenges::table)
            .values(&new_challenge)
            .get_result::<AuthenticationChallenge>(&mut conn)
            .await?;

        Ok(challenge)
    }

    pub async fn get_authentication_challenge(
        &self,
        user_id: Uuid,
        challenge: &[u8],
    ) -> Result<Option<AuthenticationChallenge>> {
        let mut conn = self.pool.get().await?;
        
        let now = Utc::now();
        let challenge_record = authentication_challenges::table
            .filter(
                authentication_challenges::user_id
                    .eq(user_id)
                    .and(authentication_challenges::challenge.eq(challenge))
                    .and(authentication_challenges::expires_at.gt(now)),
            )
            .first::<AuthenticationChallenge>(&mut conn)
            .await
            .optional()?;

        Ok(challenge_record)
    }

    pub async fn delete_authentication_challenge(&self, user_id: Uuid, challenge: &[u8]) -> Result<()> {
        let mut conn = self.pool.get().await?;
        
        diesel::delete(
            authentication_challenges::table.filter(
                authentication_challenges::user_id
                    .eq(user_id)
                    .and(authentication_challenges::challenge.eq(challenge)),
            ),
        )
        .execute(&mut conn)
        .await?;

        Ok(())
    }

    // Cleanup operations
    pub async fn cleanup_expired_registration_challenges(&self) -> Result<()> {
        let mut conn = self.pool.get().await?;
        
        let now = Utc::now();
        diesel::delete(
            registration_challenges::table.filter(registration_challenges::expires_at.lt(now)),
        )
        .execute(&mut conn)
        .await?;

        Ok(())
    }

    pub async fn cleanup_expired_authentication_challenges(&self) -> Result<()> {
        let mut conn = self.pool.get().await?;
        
        let now = Utc::now();
        diesel::delete(
            authentication_challenges::table.filter(authentication_challenges::expires_at.lt(now)),
        )
        .execute(&mut conn)
        .await?;

        Ok(())
    }
}

impl From<deadpool_diesel::PoolError> for AppError {
    fn from(err: deadpool_diesel::PoolError) -> Self {
        AppError::DatabaseError(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::Unknown,
            Box::new(err.to_string()),
        ))
    }
}

impl From<deadpool_diesel::InteractError> for AppError {
    fn from(err: deadpool_diesel::InteractError) -> Self {
        AppError::DatabaseError(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::Unknown,
            Box::new(err.to_string()),
        ))
    }
}