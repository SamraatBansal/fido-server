//! API routes configuration

use actix_web::{web, Scope};
use crate::controllers::webauthn::*;

pub fn configure<W>(cfg: &mut web::ServiceConfig, controller: web::Data<WebAuthnController<W>>)
where
    W: crate::services::webauthn::WebAuthnService + 'static,
{
    cfg.service(
        web::scope("/attestation")
            .route("/options", web::post().to(make_attestation_options_handler(controller.clone())))
            .route("/result", web::post().to(make_attestation_result_handler(controller.clone()))),
    )
    .service(
        web::scope("/assertion")
            .route("/options", web::post().to(make_assertion_options_handler(controller.clone())))
            .route("/result", web::post().to(make_assertion_result_handler(controller))),
    );
}

pub fn configure_api<W>(cfg: &mut web::ServiceConfig)
where
    W: crate::services::webauthn::WebAuthnService + 'static,
{
    // This will be configured in main.rs with the actual controller
    cfg.route("/health", web::get().to(health_check));
}

async fn health_check() -> actix_web::Result<impl actix_web::Responder> {
    Ok(actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}