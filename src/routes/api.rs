//! API routes configuration

use actix_web::{web, HttpResponse};
use crate::controllers::webauthn::*;
use crate::services::webauthn::*;

pub fn configure<W>(cfg: &mut web::ServiceConfig, controller: web::Data<WebAuthnController<W>>)
where
    W: crate::services::webauthn::WebAuthnService + 'static,
{
    cfg.service(
        web::scope("/attestation")
            .route("/options", web::post().to(attestation_options))
            .route("/result", web::post().to(attestation_result)),
    )
    .service(
        web::scope("/assertion")
            .route("/options", web::post().to(assertion_options))
            .route("/result", web::post().to(assertion_result)),
    );
}

pub fn configure_api(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health_check));
}

async fn health_check() -> actix_web::Result<impl actix_web::Responder> {
    Ok(actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

// Handler functions
async fn attestation_options<W>(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    controller: web::Data<WebAuthnController<W>>,
) -> actix_web::Result<HttpResponse>
where
    W: crate::services::webauthn::WebAuthnService + 'static,
{
    controller.attestation_options(request).await
}

async fn attestation_result<W>(
    request: web::Json<ServerPublicKeyCredential>,
    controller: web::Data<WebAuthnController<W>>,
) -> actix_web::Result<HttpResponse>
where
    W: crate::services::webauthn::WebAuthnService + 'static,
{
    controller.attestation_result(request).await
}

async fn assertion_options<W>(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    controller: web::Data<WebAuthnController<W>>,
) -> actix_web::Result<HttpResponse>
where
    W: crate::services::webauthn::WebAuthnService + 'static,
{
    controller.assertion_options(request).await
}

async fn assertion_result<W>(
    request: web::Json<ServerPublicKeyCredential>,
    controller: web::Data<WebAuthnController<W>>,
) -> actix_web::Result<HttpResponse>
where
    W: crate::services::webauthn::WebAuthnService + 'static,
{
    controller.assertion_result(request).await
}