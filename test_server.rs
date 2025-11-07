//! Simple test server for FIDO endpoints

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer, HttpResponse};
use serde_json::json;

// Simple health check endpoint
async fn health_check() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "FIDO Server Test",
        "version": "0.1.0"
    })))
}

// Mock attestation options endpoint
async fn attestation_options(req: web::Json<serde_json::Value>) -> actix_web::Result<HttpResponse> {
    println!("Received attestation options request: {}", serde_json::to_string_pretty(&req.into_inner()).unwrap());
    
    let response = json!({
        "status": "ok",
        "errorMessage": "",
        "rp": {
            "name": "Example Corporation"
        },
        "user": {
            "id": "S3932ee31vKEC0JtJMIQ",
            "name": "johndoe@example.com",
            "displayName": "John Doe"
        },
        "challenge": "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN",
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": -7
            }
        ],
        "timeout": 10000,
        "excludeCredentials": [],
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });
    
    Ok(HttpResponse::Ok().json(response))
}

// Mock attestation result endpoint
async fn attestation_result(req: web::Json<serde_json::Value>) -> actix_web::Result<HttpResponse> {
    println!("Received attestation result request: {}", serde_json::to_string_pretty(&req.into_inner()).unwrap());
    
    let response = json!({
        "status": "ok",
        "errorMessage": ""
    });
    
    Ok(HttpResponse::Ok().json(response))
}

// Mock assertion options endpoint
async fn assertion_options(req: web::Json<serde_json::Value>) -> actix_web::Result<HttpResponse> {
    println!("Received assertion options request: {}", serde_json::to_string_pretty(&req.into_inner()).unwrap());
    
    let response = json!({
        "status": "ok",
        "errorMessage": "",
        "challenge": "6283u0svT-YIF3pSolzkQHStwkJCaLKx",
        "timeout": 20000,
        "rpId": "localhost",
        "allowCredentials": [
            {
                "id": "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m",
                "type": "public-key"
            }
        ],
        "userVerification": "required"
    });
    
    Ok(HttpResponse::Ok().json(response))
}

// Mock assertion result endpoint
async fn assertion_result(req: web::Json<serde_json::Value>) -> actix_web::Result<HttpResponse> {
    println!("Received assertion result request: {}", serde_json::to_string_pretty(&req.into_inner()).unwrap());
    
    let response = json!({
        "status": "ok",
        "errorMessage": ""
    });
    
    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    println!("Starting FIDO Test Server on http://localhost:8080");

    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .route("/health", web::get().to(health_check))
            .route("/attestation/options", web::post().to(attestation_options))
            .route("/attestation/result", web::post().to(attestation_result))
            .route("/assertion/options", web::post().to(assertion_options))
            .route("/assertion/result", web::post().to(assertion_result))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}