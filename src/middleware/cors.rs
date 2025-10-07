use actix_cors::Cors;
use actix_web::http::header;

pub fn cors_config() -> Cors {
    Cors::default()
        .allowed_origin("http://localhost:3000")
        .allowed_origin("http://localhost:8080")
        .allowed_origin("https://localhost:3000")
        .allowed_origin("https://localhost:8080")
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
        ])
        .supports_credentials()
        .max_age(3600)
}