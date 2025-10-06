//! User management HTTP controllers

use actix_web::{web, HttpResponse, Result as ActixResult};
use uuid::Uuid;

use crate::db::DbPool;
use crate::error::{AppError, Result};
use crate::schema::*;
use crate::services::user::UserService;

/// User controller state
pub struct UserController {
    /// User service
    user_service: UserService,
}

impl UserController {
    /// Create new user controller
    pub fn new() -> Self {
        Self {
            user_service: UserService,
        }
    }

    /// Create user
    pub async fn create_user(
        &self,
        pool: web::Data<DbPool>,
        req: web::Json<serde_json::Value>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;

        let username = req.get("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Validation("Username is required".to_string()))?;

        let display_name = req.get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or(username);

        let user = self.user_service
            .create_user(&mut conn, username, display_name)?;

        Ok(HttpResponse::Created().json(SuccessResponse::new(user)))
    }

    /// Get user by ID
    pub async fn get_user(
        &self,
        pool: web::Data<DbPool>,
        path: web::Path<Uuid>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;
        let user_id = path.into_inner();

        let user = self.user_service
            .get_user_by_id(&mut conn, user_id)?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(user)))
    }

    /// Get user by username
    pub async fn get_user_by_username(
        &self,
        pool: web::Data<DbPool>,
        path: web::Path<String>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;
        let username = path.into_inner();

        let user = self.user_service
            .get_user_by_username(&mut conn, &username)?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(user)))
    }

    /// Update user
    pub async fn update_user(
        &self,
        pool: web::Data<DbPool>,
        path: web::Path<Uuid>,
        req: web::Json<serde_json::Value>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;
        let user_id = path.into_inner();

        let display_name = req.get("display_name")
            .and_then(|v| v.as_str());

        let user = self.user_service
            .update_user(&mut conn, user_id, display_name)?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(user)))
    }

    /// Delete user
    pub async fn delete_user(
        &self,
        pool: web::Data<DbPool>,
        path: web::Path<Uuid>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;
        let user_id = path.into_inner();

        self.user_service
            .delete_user(&mut conn, user_id)?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(serde_json::json!({
            "message": "User deleted successfully"
        }))))
    }

    /// List users
    pub async fn list_users(
        &self,
        pool: web::Data<DbPool>,
        query: web::Query<serde_json::Value>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;

        let limit = query.get("limit")
            .and_then(|v| v.as_i64())
            .map(|v| v as i64);

        let offset = query.get("offset")
            .and_then(|v| v.as_i64())
            .map(|v| v as i64);

        let users = self.user_service
            .list_users(&mut conn, limit, offset)?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(users)))
    }

    /// Get user with credentials
    pub async fn get_user_with_credentials(
        &self,
        pool: web::Data<DbPool>,
        path: web::Path<Uuid>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;
        let user_id = path.into_inner();

        let user_with_creds = self.user_service
            .get_user_with_credentials(&mut conn, user_id)?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(user_with_creds)))
    }
}

/// Configure user routes
pub fn configure(cfg: &mut web::ServiceConfig, controller: web::Data<UserController>) {
    cfg.service(
        web::scope("/api/v1/users")
            .route("", web::post().to({
                let controller = controller.clone();
                move |pool, req| controller.create_user(pool, req)
            }))
            .route("/{user_id}", web::get().to({
                let controller = controller.clone();
                move |pool, path| controller.get_user(pool, path)
            }))
            .route("/username/{username}", web::get().to({
                let controller = controller.clone();
                move |pool, path| controller.get_user_by_username(pool, path)
            }))
            .route("/{user_id}", web::put().to({
                let controller = controller.clone();
                move |pool, path, req| controller.update_user(pool, path, req)
            }))
            .route("/{user_id}", web::delete().to({
                let controller = controller.clone();
                move |pool, path| controller.delete_user(pool, path)
            }))
            .route("", web::get().to({
                let controller = controller.clone();
                move |pool, query| controller.list_users(pool, query)
            }))
            .route("/{user_id}/credentials", web::get().to({
                let controller = controller.clone();
                move |pool, path| controller.get_user_with_credentials(pool, path)
            })),
    );
}