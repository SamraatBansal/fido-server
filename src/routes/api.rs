//! API routes configuration

use actix_web::web;
use std::sync::Arc;
use crate::controllers::{RegistrationController, AuthenticationController, HealthController};

/// Configure all API routes
pub fn configure(
    cfg: &mut web::ServiceConfig,
    registration_controller: Arc<RegistrationController>,
    authentication_controller: Arc<AuthenticationController>,
    health_controller: Arc<HealthController>,
) {
    cfg.service(
        web::scope("/api")
            .configure(|cfg| {
                crate::controllers::registration::configure(cfg, registration_controller);
                crate::controllers::authentication::configure(cfg, authentication_controller);
                crate::controllers::health::configure(cfg, health_controller);
            })
    );
}