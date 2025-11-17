use crate::schema::users;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_handle: Vec<u8>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub user_handle: Vec<u8>,
}

impl NewUser {
    pub fn new(username: String, display_name: String) -> Self {
        let user_handle = uuid::Uuid::new_v4().as_bytes().to_vec();
        Self {
            username,
            display_name,
            user_handle,
        }
    }
}