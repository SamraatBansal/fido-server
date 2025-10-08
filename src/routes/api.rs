//! API routes configuration

use actix_web::web;

use crate::controllers::{
    authentication::{start_assertion, verify_assertion},
    health::health_check,
    registration::{start_attestation, verify_attestation},
};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(
                web::scope("/v1")
                    .service(
                        web::scope("/webauthn")
                            .service(
                                web::scope("/registration")
                                    .route("/challenge", web::post().to(start_attestation))
                                    .route("/verify", web::post().to(verify_attestation)),
                            )
                            .service(
                                web::scope("/authentication")
                                    .route("/challenge", web::post().to(start_assertion))
                                    .route("/verify", web::post().to(verify_assertion)),
                            ),
                    )
                    .route("/health", web::get().to(health_check)),
            ),
    );
}