use crate::controllers::{assertion_options, assertion_result, attestation_options, attestation_result, health};
use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(health)
        .service(attestation_options)
        .service(attestation_result)
        .service(assertion_options)
        .service(assertion_result);
}