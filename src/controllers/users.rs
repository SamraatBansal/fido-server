//! User management controller

use actix_web::{web, HttpResponse, Result};
use diesel::prelude::*;
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

use crate::db::{DbPool, NewUser, UpdateUser, User, Credential, UserWithCredentials};
use crate::error::AppError;
use crate::schema::{
    CreateUserRequest, CredentialSummaryResponse, DeleteCredentialResponse,
    UpdateUserRequest, UserResponse, UserWithCredentialsResponse,
};

/// Get user by ID
///
/// Retrieves user information including their credentials.
#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}",
    responses(
        (status = 200, description = "User retrieved successfully", body = UserWithCredentialsResponse),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    tag = "users"
)]
pub async fn get_user(
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    
    let mut conn = pool.get().map_err(|e| {
        AppError::Database(format!("Failed to get database connection: {}", e))
    })?;

    // Get user
    let user: User = crate::schema::users::table
        .filter(crate::schema::users::id.eq(user_id))
        .first(&mut conn)
        .optional()
        .map_err(|e| AppError::Database(format!("Failed to fetch user: {}", e)))?
        .ok_or(AppError::UserNotFound)?;

    // Get user credentials
    let credentials: Vec<Credential> = crate::schema::credentials::table
        .filter(crate::schema::credentials::user_id.eq(user_id))
        .load(&mut conn)
        .map_err(|e| AppError::Database(format!("Failed to fetch credentials: {}", e)))?;

    let response = UserWithCredentialsResponse {
        user: UserResponse {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            created_at: user.created_at,
            updated_at: user.updated_at,
        },
        credentials: credentials
            .into_iter()
            .map(|cred| CredentialSummaryResponse {
                id: cred.id,
                credential_id: base64::encode(&cred.credential_id),
                attestation_format: cred.attestation_format,
                created_at: cred.created_at,
                last_used_at: cred.last_used_at,
                backup_eligible: cred.backup_eligible,
                backup_state: cred.backup_state,
                transports: cred.transports,
                sign_count: cred.sign_count,
            })
            .collect(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Create a new user
#[utoipa::path(
    post,
    path = "/api/v1/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully", body = UserResponse),
        (status = 400, description = "Invalid request"),
        (status = 409, description = "Username already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = "users"
)]
pub async fn create_user(
    pool: web::Data<DbPool>,
    payload: web::Json<CreateUserRequest>,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = payload.validate() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Validation failed",
            "details": validation_errors
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        AppError::Database(format!("Failed to get database connection: {}", e))
    })?;

    // Check if username already exists
    let existing_user: Option<User> = crate::schema::users::table
        .filter(crate::schema::users::username.eq(&payload.username))
        .first(&mut conn)
        .optional()
        .map_err(|e| AppError::Database(format!("Failed to check existing user: {}", e)))?;

    if existing_user.is_some() {
        return Ok(HttpResponse::Conflict().json(json!({
            "error": "Username already exists",
            "message": "A user with this username already exists"
        })));
    }

    // Create new user
    let new_user = NewUser {
        username: payload.username.clone(),
        display_name: payload.display_name.clone(),
    };

    let user: User = diesel::insert_into(crate::schema::users::table)
        .values(&new_user)
        .get_result(&mut conn)
        .map_err(|e| AppError::Database(format!("Failed to create user: {}", e)))?;

    let response = UserResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        created_at: user.created_at,
        updated_at: user.updated_at,
    };

    Ok(HttpResponse::Created().json(response))
}

/// Update user information
#[utoipa::path(
    put,
    path = "/api/v1/users/{user_id}",
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated successfully", body = UserResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    tag = "users"
)]
pub async fn update_user(
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
    payload: web::Json<UpdateUserRequest>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();

    // Validate request
    if let Err(validation_errors) = payload.validate() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Validation failed",
            "details": validation_errors
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        AppError::Database(format!("Failed to get database connection: {}", e))
    })?;

    // Update user
    let update_user = UpdateUser {
        display_name: payload.display_name.clone(),
    };

    let user: User = diesel::update(crate::schema::users::table.find(user_id))
        .set(&update_user)
        .get_result(&mut conn)
        .optional()
        .map_err(|e| AppError::Database(format!("Failed to update user: {}", e)))?
        .ok_or(AppError::UserNotFound)?;

    let response = UserResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        created_at: user.created_at,
        updated_at: user.updated_at,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Delete user
#[utoipa::path(
    delete,
    path = "/api/v1/users/{user_id}",
    responses(
        (status = 204, description = "User deleted successfully"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    tag = "users"
)]
pub async fn delete_user(
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();

    let mut conn = pool.get().map_err(|e| {
        AppError::Database(format!("Failed to get database connection: {}", e))
    })?;

    // Delete user (cascades to credentials)
    let deleted_rows = diesel::delete(crate::schema::users::table.find(user_id))
        .execute(&mut conn)
        .map_err(|e| AppError::Database(format!("Failed to delete user: {}", e)))?;

    if deleted_rows == 0 {
        return Ok(HttpResponse::NotFound().json(json!({
            "error": "User not found",
            "message": "No user exists with the provided ID"
        })));
    }

    Ok(HttpResponse::NoContent().finish())
}

/// Delete user credential
#[utoipa::path(
    delete,
    path = "/api/v1/users/{user_id}/credentials/{credential_id}",
    responses(
        (status = 200, description = "Credential deleted successfully", body = DeleteCredentialResponse),
        (status = 404, description = "User or credential not found"),
        (status = 500, description = "Internal server error")
    ),
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("credential_id" = Uuid, Path, description = "Credential ID")
    ),
    tag = "users"
)]
pub async fn delete_credential(
    path: web::Path<(Uuid, Uuid)>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse> {
    let (user_id, credential_id) = path.into_inner();

    let mut conn = pool.get().map_err(|e| {
        AppError::Database(format!("Failed to get database connection: {}", e))
    })?;

    // Verify credential belongs to user
    let credential: Credential = crate::schema::credentials::table
        .filter(crate::schema::credentials::id.eq(credential_id))
        .filter(crate::schema::credentials::user_id.eq(user_id))
        .first(&mut conn)
        .optional()
        .map_err(|e| AppError::Database(format!("Failed to fetch credential: {}", e)))?
        .ok_or(AppError::NotFound("Credential not found".to_string()))?;

    // Delete credential
    diesel::delete(crate::schema::credentials::table.find(credential.id))
        .execute(&mut conn)
        .map_err(|e| AppError::Database(format!("Failed to delete credential: {}", e)))?;

    let response = DeleteCredentialResponse {
        status: "success".to_string(),
        message: "Credential deleted successfully".to_string(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get user credentials
#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}/credentials",
    responses(
        (status = 200, description = "Credentials retrieved successfully", body = Vec<CredentialSummaryResponse>),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    tag = "users"
)]
pub async fn get_user_credentials(
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();

    let mut conn = pool.get().map_err(|e| {
        AppError::Database(format!("Failed to get database connection: {}", e))
    })?;

    // Verify user exists
    let user: User = crate::schema::users::table
        .filter(crate::schema::users::id.eq(user_id))
        .first(&mut conn)
        .optional()
        .map_err(|e| AppError::Database(format!("Failed to fetch user: {}", e)))?
        .ok_or(AppError::UserNotFound)?;

    // Get credentials
    let credentials: Vec<Credential> = crate::schema::credentials::table
        .filter(crate::schema::credentials::user_id.eq(user_id))
        .load(&mut conn)
        .map_err(|e| AppError::Database(format!("Failed to fetch credentials: {}", e)))?;

    let response: Vec<CredentialSummaryResponse> = credentials
        .into_iter()
        .map(|cred| CredentialSummaryResponse {
            id: cred.id,
            credential_id: base64::encode(&cred.credential_id),
            attestation_format: cred.attestation_format,
            created_at: cred.created_at,
            last_used_at: cred.last_used_at,
            backup_eligible: cred.backup_eligible,
            backup_state: cred.backup_state,
            transports: cred.transports,
            sign_count: cred.sign_count,
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use serde_json::json;
    use uuid::Uuid;

    #[actix_web::test]
    async fn test_create_user_validation() {
        let app = test::init_service(
            App::new().route("/api/v1/users", web::post().to(create_user)),
        )
        .await;

        // Test invalid request (short username)
        let req = test::TestRequest::post()
            .uri("/api/v1/users")
            .set_json(json!({
                "username": "ab",
                "display_name": "Test User"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
    }

    #[actix_web::test]
    async fn test_get_user_not_found() {
        let app = test::init_service(
            App::new().route(
                "/api/v1/users/{user_id}",
                web::get().to(get_user),
            ),
        )
        .await;

        let user_id = Uuid::new_v4();
        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/users/{}", user_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_not_found());
    }
}