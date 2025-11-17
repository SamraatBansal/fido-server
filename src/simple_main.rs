use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use base64::prelude::*;
use webauthn_rs::prelude::*;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationOptionsRequest {
    username: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationOptionsResponse {
    status: String,
    #[serde(rename = "errorMessage")]
    error_message: String,
    rp: serde_json::Value,
    user: serde_json::Value,
    challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub_key_cred_params: serde_json::Value,
    timeout: u32,
    #[serde(rename = "excludeCredentials")]
    exclude_credentials: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationResultRequest {
    id: String,
    response: AttestationResponse,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AssertionOptionsRequest {
    username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AssertionOptionsResponse {
    status: String,
    #[serde(rename = "errorMessage")]
    error_message: String,
    challenge: String,
    timeout: u32,
    #[serde(rename = "rpId")]
    rp_id: String,
    #[serde(rename = "allowCredentials")]
    allow_credentials: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AssertionResultRequest {
    id: String,
    response: AssertionResponse,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerResponse {
    status: String,
    #[serde(rename = "errorMessage")]
    error_message: String,
}

// Simple in-memory storage
type Storage = Mutex<HashMap<String, serde_json::Value>>;

struct AppState {
    webauthn: Webauthn,
    storage: Storage,
}

#[actix_web::post("/attestation/options")]
async fn attestation_options(
    data: web::Data<AppState>,
    req: web::Json<AttestationOptionsRequest>,
) -> Result<HttpResponse> {
    log::info!("Attestation options for user: {}", req.username);

    let user_id = Uuid::new_v4();
    let user_id_bytes = user_id.as_bytes().to_vec();

    let (ccr, reg_state) = data
        .webauthn
        .start_passkey_registration(
            user_id,
            &req.username,
            &req.display_name,
            None,
        )
        .map_err(|e| {
            log::error!("WebAuthn registration start error: {:?}", e);
            actix_web::error::ErrorInternalServerError("WebAuthn error")
        })?;

    // Store registration state
    let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(ccr.public_key.challenge.as_ref());
    let storage_key = format!("reg_challenge_{}", challenge_b64);
    
    data.storage.lock().unwrap().insert(
        storage_key,
        json!({
            "user_id": user_id.to_string(),
            "username": req.username,
            "display_name": req.display_name,
            "state": format!("{:?}", reg_state), // Simple serialization for demo
        })
    );

    let response = AttestationOptionsResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        rp: json!({
            "name": "Example Corporation"
        }),
        user: json!({
            "id": BASE64_URL_SAFE_NO_PAD.encode(&user_id_bytes),
            "name": req.username,
            "displayName": req.display_name
        }),
        challenge: challenge_b64,
        pub_key_cred_params: json!([{
            "type": "public-key",
            "alg": -7
        }]),
        timeout: 10000,
        exclude_credentials: json!([]),
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::post("/attestation/result")]
async fn attestation_result(
    data: web::Data<AppState>,
    req: web::Json<AttestationResultRequest>,
) -> Result<HttpResponse> {
    log::info!("Attestation result for credential: {}", req.id);

    // For demo purposes, we'll just validate the structure and return success
    if req.response.client_data_json.is_empty() || req.response.attestation_object.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse {
            status: "failed".to_string(),
            error_message: "Missing required fields".to_string(),
        }));
    }

    // In a real implementation, we would:
    // 1. Decode and validate the clientDataJSON
    // 2. Extract and validate the challenge
    // 3. Look up the registration state
    // 4. Complete the WebAuthn registration
    // 5. Store the credential

    Ok(HttpResponse::Ok().json(ServerResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
    }))
}

#[actix_web::post("/assertion/options")]
async fn assertion_options(
    data: web::Data<AppState>,
    req: web::Json<AssertionOptionsRequest>,
) -> Result<HttpResponse> {
    log::info!("Assertion options for user: {}", req.username);

    // For demo, create a challenge
    let challenge = uuid::Uuid::new_v4().as_bytes().to_vec();
    let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(&challenge);

    // Store challenge
    data.storage.lock().unwrap().insert(
        format!("auth_challenge_{}", challenge_b64),
        json!({
            "username": req.username,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })
    );

    let response = AssertionOptionsResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        challenge: challenge_b64,
        timeout: 20000,
        rp_id: "localhost".to_string(),
        allow_credentials: json!([]),
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::post("/assertion/result")]
async fn assertion_result(
    data: web::Data<AppState>,
    req: web::Json<AssertionResultRequest>,
) -> Result<HttpResponse> {
    log::info!("Assertion result for credential: {}", req.id);

    // For demo purposes, validate structure
    if req.response.client_data_json.is_empty() 
        || req.response.authenticator_data.is_empty() 
        || req.response.signature.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse {
            status: "failed".to_string(),
            error_message: "Missing required fields".to_string(),
        }));
    }

    Ok(HttpResponse::Ok().json(ServerResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
    }))
}

#[actix_web::get("/health")]
async fn health() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "FIDO Server",
        "version": env!("CARGO_PKG_VERSION")
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting Simple FIDO Server...");

    // Create WebAuthn instance
    let rp_id = "localhost";
    let origin = Url::parse("http://localhost:8080").expect("Invalid origin URL");
    let webauthn = WebauthnBuilder::new(rp_id, &origin)
        .expect("Failed to create WebAuthnBuilder")
        .rp_name("Example Corporation")
        .build()
        .expect("Failed to build WebAuthn");

    let app_state = web::Data::new(AppState {
        webauthn,
        storage: Mutex::new(HashMap::new()),
    });

    log::info!("Server running at http://localhost:8080");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:8080")
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://localhost:3001")
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(app_state.clone())
            .wrap(Logger::default())
            .wrap(cors)
            .service(health)
            .service(attestation_options)
            .service(attestation_result)
            .service(assertion_options)
            .service(assertion_result)
    })
    .bind("localhost:8080")?
    .run()
    .await
}