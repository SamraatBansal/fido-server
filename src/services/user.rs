//! User service implementation

use diesel::prelude::*;
use uuid::Uuid;

use crate::db::{models::*, DbPool};
use crate::error::{AppError, Result};
use crate::schema::users;

/// User service for managing user data
#[derive(Clone)]
pub struct UserService {
    pool: DbPool,
}

impl UserService {
    /// Create a new user service
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Create a new user
    pub async fn create_user(&self, username: &str, display_name: &str) -> Result<User> {
        let new_user = NewUser {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
        };

        let mut conn = self.pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        let user = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result::<User>(&mut conn)
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        Ok(user)
    }

    /// Find user by username
    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        let user = users::table
            .filter(users::username.eq(username))
            .first::<User>(&mut conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        Ok(user)
    }

    /// Find user by ID
    pub async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let mut conn = self.pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        let user = users::table
            .find(user_id)
            .first::<User>(&mut conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        Ok(user)
    }

    /// Get or create user by username and display name
    pub async fn get_or_create_user(&self, username: &str, display_name: &str) -> Result<User> {
        if let Some(user) = self.find_by_username(username).await? {
            Ok(user)
        } else {
            self.create_user(username, display_name).await
        }
    }
}