//! Logging middleware

use actix_web::middleware::Logger;

pub fn request_logger() -> Logger {
    Logger::new("%a %{User-Agent}i \"%r\" %s %b \"%{Referer}i\" %D")
}