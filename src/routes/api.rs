//! API route configuration

use actix_web::web;

use crate::controllers::{health, registration, authentication, credentials};
use crate::middleware::{auth, rate_limit};

/// Configure API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(v1::configure)
    );
}