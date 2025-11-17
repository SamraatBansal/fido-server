use crate::schema::{authentication_challenges, registration_challenges};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(belongs_to(super::user::User, foreign_key = user_id))]
#[diesel(table_name = registration_challenges)]
pub struct RegistrationChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: NaiveDateTime,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = registration_challenges)]
pub struct NewRegistrationChallenge {
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(belongs_to(super::user::User, foreign_key = user_id))]
#[diesel(table_name = authentication_challenges)]
pub struct AuthenticationChallenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: NaiveDateTime,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = authentication_challenges)]
pub struct NewAuthenticationChallenge {
    pub user_id: Option<Uuid>,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: NaiveDateTime,
}