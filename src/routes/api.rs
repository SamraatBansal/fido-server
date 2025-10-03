//! API routes configuration

use crate::controllers::authentication::{AuthenticationFinishRequest, AuthenticationStartRequest};
use crate::controllers::mapping::CreateMappingRequest;
use crate::controllers::registration::{RegistrationFinishRequest, RegistrationStartRequest};
use crate::AppState;
use actix_web::{web, HttpRequest};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(
                web::scope("/registration")
                    .route("/start", web::post().to(start_registration))
                    .route("/finish", web::post().to(finish_registration)),
            )
            .service(
                web::scope("/authentication")
                    .route("/start", web::post().to(start_authentication))
                    .route("/finish", web::post().to(finish_authentication)),
            )
            .service(
                web::scope("/mapping")
                    .route("/create", web::post().to(create_mapping))
                    .route("/{id}", web::get().to(get_mapping))
                    .route("/{id}", web::delete().to(delete_mapping))
                    .route(
                        "/by-credential/{credId}",
                        web::get().to(get_mappings_by_credential),
                    ),
            ),
    );
}

// Registration endpoints
async fn start_registration(
    req: web::Json<RegistrationStartRequest>,
    app_state: web::Data<AppState>,
    http_req: HttpRequest,
) -> Result<actix_web::HttpResponse, actix_web::Error> {
    app_state
        .registration_controller
        .start_registration(req, http_req)
        .await
        .map_err(actix_web::error::Error::from)
}

async fn finish_registration(
    req: web::Json<RegistrationFinishRequest>,
    app_state: web::Data<AppState>,
    http_req: HttpRequest,
) -> Result<actix_web::HttpResponse, actix_web::Error> {
    app_state
        .registration_controller
        .finish_registration(req, http_req)
        .await
        .map_err(actix_web::error::Error::from)
}

// Authentication endpoints
async fn start_authentication(
    req: web::Json<AuthenticationStartRequest>,
    app_state: web::Data<AppState>,
    http_req: HttpRequest,
) -> Result<actix_web::HttpResponse, actix_web::Error> {
    app_state
        .authentication_controller
        .start_authentication(req, http_req)
        .await
        .map_err(actix_web::error::Error::from)
}

async fn finish_authentication(
    req: web::Json<AuthenticationFinishRequest>,
    app_state: web::Data<AppState>,
    http_req: HttpRequest,
) -> Result<actix_web::HttpResponse, actix_web::Error> {
    app_state
        .authentication_controller
        .finish_authentication(req, http_req)
        .await
        .map_err(actix_web::error::Error::from)
}

// Mapping endpoints
async fn create_mapping(
    req: web::Json<CreateMappingRequest>,
    app_state: web::Data<AppState>,
) -> Result<actix_web::HttpResponse, actix_web::Error> {
    app_state
        .mapping_controller
        .create_mapping(req)
        .await
        .map_err(actix_web::error::Error::from)
}

async fn get_mapping(
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> Result<actix_web::HttpResponse, actix_web::Error> {
    app_state
        .mapping_controller
        .get_mapping(path)
        .await
        .map_err(actix_web::error::Error::from)
}

async fn delete_mapping(
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> Result<actix_web::HttpResponse, actix_web::Error> {
    app_state
        .mapping_controller
        .delete_mapping(path)
        .await
        .map_err(actix_web::error::Error::from)
}

async fn get_mappings_by_credential(
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> Result<actix_web::HttpResponse, actix_web::Error> {
    app_state
        .mapping_controller
        .get_mappings_by_credential(path)
        .await
        .map_err(actix_web::error::Error::from)
}
