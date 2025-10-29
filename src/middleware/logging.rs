//! Logging middleware

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::{middleware::Logger, web};
use std::time::Instant;

pub fn request_logger() -> Logger {
    Logger::new("%a %{User-Agent}i \"%r\" %s %b \"%{Referer}i\" %D")
}