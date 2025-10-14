use crate::db::{models::*, DbConnection};
use crate::error::{AppError, Result};
use crate::schema::users;
use diesel::prelude::*;
use uuid::Uuid;

pub struct UserService;

impl UserService {
    pub fn create_user(
        conn: &mut DbConnection,
        username: &str,
        display_name: &str,
    ) -> Result<User> {
        let new_user = NewUser {
            username,
            display_name,
        };

        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .map_err(AppError::Database)
    }

    pub fn find_by_username(conn: &mut DbConnection, username: &str) -> Result<User> {
        users::table
            .filter(users::username.eq(username))
            .filter(users::is_active.eq(true))
            .first(conn)
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AppError::UserNotFound,
                _ => AppError::Database(e),
            })
    }

    pub fn find_by_id(conn: &mut DbConnection, user_id: Uuid) -> Result<User> {
        users::table
            .filter(users::id.eq(user_id))
            .filter(users::is_active.eq(true))
            .first(conn)
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AppError::UserNotFound,
                _ => AppError::Database(e),
            })
    }

    pub fn find_or_create_user(
        conn: &mut DbConnection,
        username: &str,
        display_name: &str,
    ) -> Result<User> {
        match Self::find_by_username(conn, username) {
            Ok(user) => Ok(user),
            Err(AppError::UserNotFound) => Self::create_user(conn, username, display_name),
            Err(e) => Err(e),
        }
    }

    pub fn update_user(
        conn: &mut DbConnection,
        user_id: Uuid,
        display_name: Option<&str>,
    ) -> Result<User> {
        let mut changeset = users::table.filter(users::id.eq(user_id));

        if let Some(name) = display_name {
            changeset = changeset.filter(users::display_name.eq(name));
        }

        diesel::update(changeset)
            .set(users::updated_at.eq(chrono::Utc::now()))
            .get_result(conn)
            .map_err(AppError::Database)
    }

    pub fn deactivate_user(conn: &mut DbConnection, user_id: Uuid) -> Result<()> {
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::is_active.eq(false))
            .execute(conn)
            .map_err(AppError::Database)?;
        Ok(())
    }
}