use actix_web::{web, App, HttpServer, middleware::Logger};
use fido2_server::{api, config::AppConfig};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::init();
    
    let config = AppConfig::from_env().expect("Failed to load configuration");
    let bind_address = format!("{}:{}", config.host, config.port);
    
    println!("Starting FIDO2 server on {}", bind_address);
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(config.clone()))
            .wrap(Logger::default())
            .wrap(actix_cors::Cors::permissive())
            .configure(api::configure_routes)
    })
    .bind(&bind_address)?
    .run()
    .await
}