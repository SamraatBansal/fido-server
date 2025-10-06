//! API route configuration

use actix_web::web;
use crate::config::Config;
use crate::controllers::fido::FidoController;
use crate::controllers::user::UserController;
use crate::middleware::{cors, rate_limit, security};
use crate::services::fido::FidoService;

/// Configure API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // Load configuration
    let config = crate::config::load_config().unwrap_or_else(|_| Config::default());
    
    // Initialize services
    let fido_service = FidoService::new(config.webauthn.clone()).expect("Failed to create FIDO service");
    let fido_controller = FidoController::new(fido_service);
    let user_controller = UserController::new();

    // Configure CORS
    let cors = cors::configure_cors(&config.server);
    
    // Configure rate limiting
    let rate_limit = rate_limit::RateLimitMiddleware::new(config.security.rate_limit_per_minute);
    
    // Configure security headers
    let security_headers = security::SecurityHeadersMiddleware::new();

    cfg.service(
        web::scope("")
            .wrap(cors)
            .wrap(rate_limit)
            .wrap(security_headers)
            .app_data(web::Data::new(fido_controller))
            .app_data(web::Data::new(user_controller))
            .configure(configure_fido_routes)
            .configure(configure_user_routes)
    );
}

/// Configure FIDO routes
fn configure_fido_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/register/start", web::post().to(fido_start_registration))
            .route("/register/finish", web::post().to(fido_finish_registration))
            .route("/authenticate/start", web::post().to(fido_start_authentication))
            .route("/authenticate/finish", web::post().to(fido_finish_authentication))
            .route("/credentials/{user_id}", web::get().to(fido_list_credentials))
            .route("/credentials/{user_id}/{credential_id}", web::delete().to(fido_delete_credential))
    );
}

/// Configure user routes
fn configure_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1/users")
            .route("", web::post().to(user_create))
            .route("/{user_id}", web::get().to(user_get))
            .route("/username/{username}", web::get().to(user_get_by_username))
            .route("/{user_id}", web::put().to(user_update))
            .route("/{user_id}", web::delete().to(user_delete))
            .route("", web::get().to(user_list))
            .route("/{user_id}/credentials", web::get().to(user_get_with_credentials))
    );
}

// FIDO route handlers
async fn fido_start_registration(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<FidoController>,
    req: web::Json<crate::schema::RegistrationStartRequest>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.start_registration(pool, req).await
}

async fn fido_finish_registration(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<FidoController>,
    req: web::Json<crate::schema::RegistrationFinishRequest>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.finish_registration(pool, req).await
}

async fn fido_start_authentication(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<FidoController>,
    req: web::Json<crate::schema::AuthenticationStartRequest>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.start_authentication(pool, req).await
}

async fn fido_finish_authentication(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<FidoController>,
    req: web::Json<crate::schema::AuthenticationFinishRequest>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.finish_authentication(pool, req).await
}

async fn fido_list_credentials(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<FidoController>,
    path: web::Path<uuid::Uuid>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.list_credentials(pool, path).await
}

async fn fido_delete_credential(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<FidoController>,
    path: web::Path<(uuid::Uuid, String)>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.delete_credential(pool, path).await
}

// User route handlers
async fn user_create(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<UserController>,
    req: web::Json<serde_json::Value>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.create_user(pool, req).await
}

async fn user_get(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<UserController>,
    path: web::Path<uuid::Uuid>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.get_user(pool, path).await
}

async fn user_get_by_username(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<UserController>,
    path: web::Path<String>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.get_user_by_username(pool, path).await
}

async fn user_update(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<UserController>,
    path: web::Path<uuid::Uuid>,
    req: web::Json<serde_json::Value>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.update_user(pool, path, req).await
}

async fn user_delete(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<UserController>,
    path: web::Path<uuid::Uuid>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.delete_user(pool, path).await
}

async fn user_list(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<UserController>,
    query: web::Query<serde_json::Value>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.list_users(pool, query).await
}

async fn user_get_with_credentials(
    pool: web::Data<crate::db::DbPool>,
    controller: web::Data<UserController>,
    path: web::Path<uuid::Uuid>,
) -> actix_web::Result<actix_web::HttpResponse> {
    controller.get_user_with_credentials(pool, path).await
}