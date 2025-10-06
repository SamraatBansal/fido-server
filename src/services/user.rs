//! User management service

use diesel::prelude::*;
use uuid::Uuid;
use chrono::Utc;

use crate::db::{DbConnection, models::*};
use crate::db::schema::users;
use crate::error::{AppError, Result};

/// User service for user management operations
pub struct UserService;

impl UserService {
    /// Create new user
    pub fn create_user(
        conn: &mut DbConnection,
        username: &str,
        display_name: &str,
    ) -> Result<User> {
        // Check if user already exists
        let existing_user = users::table
            .filter(users::username.eq(username))
            .first::<User>(conn)
            .optional()?;

        if existing_user.is_some() {
            return Err(AppError::User("User already exists".to_string()));
        }

        let new_user = NewUser {
            username: username.to_string(),
            display_name: display_name.to_string(),
        };

        let user = diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(conn)?;

        Ok(user)
    }

    /// Get user by ID
    pub fn get_user_by_id(
        conn: &mut DbConnection,
        user_id: Uuid,
    ) -> Result<Option<User>> {
        let user = users::table
            .filter(users::id.eq(user_id))
            .first::<User>(conn)
            .optional()?;

        Ok(user)
    }

    /// Get user by username
    pub fn get_user_by_username(
        conn: &mut DbConnection,
        username: &str,
    ) -> Result<Option<User>> {
        let user = users::table
            .filter(users::username.eq(username))
            .first::<User>(conn)
            .optional()?;

        Ok(user)
    }

    /// Update user
    pub fn update_user(
        conn: &mut DbConnection,
        user_id: Uuid,
        display_name: Option<&str>,
    ) -> Result<User> {
        let user = diesel::update(users::table.filter(users::id.eq(user_id)))
            .set((
                users::display_name.eq(display_name.unwrap_or("")),
                users::updated_at.eq(Utc::now()),
            ))
            .returning(User::as_returning())
            .get_result(conn)?;

        Ok(user)
    }

    /// Delete user
    pub fn delete_user(
        conn: &mut DbConnection,
        user_id: Uuid,
    ) -> Result<()> {
        let deleted_count = diesel::delete(users::table.filter(users::id.eq(user_id)))
            .execute(conn)?;

        if deleted_count == 0 {
            return Err(AppError::User("User not found".to_string()));
        }

        Ok(())
    }

    /// List all users
    pub fn list_users(
        conn: &mut DbConnection,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<User>> {
        let mut query = users::table.into_boxed();

        if let Some(limit) = limit {
            query = query.limit(limit);
        }

        if let Some(offset) = offset {
            query = query.offset(offset);
        }

        let users = query.load::<User>(conn)?;
        Ok(users)
    }

    /// Get user with credentials
    pub fn get_user_with_credentials(
        conn: &mut DbConnection,
        user_id: Uuid,
    ) -> Result<Option<UserWithCredentials>> {
        use crate::db::schema::credentials;

        let user = users::table
            .filter(users::id.eq(user_id))
            .first::<User>(conn)
            .optional()?;

        if let Some(user) = user {
            let user_credentials = credentials::table
                .filter(credentials::user_id.eq(user_id))
                .load::<Credential>(conn)?;

            Ok(Some(UserWithCredentials {
                user,
                credentials: user_credentials,
            }))
        } else {
            Ok(None)
        }
    }
}