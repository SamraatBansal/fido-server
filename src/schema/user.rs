//! User schema and database operations

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::DbPool;
use crate::error::{AppError, Result};

/// User model for database
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New user for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

/// User repository
pub struct UserRepository {
    pool: DbPool,
}

impl UserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Create a new user
    pub async fn create_user(&self, new_user: NewUser) -> Result<User> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let user = diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {}", e)))?;

        Ok(user)
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let user = users::table
            .filter(users::username.eq(username))
            .first::<User>(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get user: {}", e)))?;

        Ok(user)
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, user_id: &Uuid) -> Result<Option<User>> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let user = users::table
            .filter(users::id.eq(user_id))
            .first::<User>(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get user: {}", e)))?;

        Ok(user)
    }

    /// Update user
    pub async fn update_user(&self, user_id: &Uuid, updated_user: &UpdateUser) -> Result<User> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        let user = diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(updated_user)
            .returning(User::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update user: {}", e)))?;

        Ok(user)
    }

    /// Delete user
    pub async fn delete_user(&self, user_id: &Uuid) -> Result<()> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

        diesel::delete(users::table.filter(users::id.eq(user_id)))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete user: {}", e)))?;

        Ok(())
    }
}

/// Update user struct
#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct UpdateUser {
    pub display_name: Option<String>,
}