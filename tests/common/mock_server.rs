//! Mock server setup for testing FIDO2/WebAuthn APIs

use actix_web::{dev::ServiceResponse, test, App, HttpResponse};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Mock server state
#[derive(Debug, Default)]
pub struct MockServerState {
    pub challenges: Arc<Mutex<HashMap<String, MockChallenge>>>,
    pub credentials: Arc<Mutex<HashMap<String, MockCredential>>>,
    pub users: Arc<Mutex<HashMap<String, MockUser>>>,
    pub request_log: Arc<Mutex<Vec<MockRequest>>>,
}

#[derive(Debug, Clone)]
pub struct MockChallenge {
    pub id: String,
    pub challenge: String,
    pub user_id: Option<String>,
    pub challenge_type: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub used: bool,
}

#[derive(Debug, Clone)]
pub struct MockCredential {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
pub struct MockUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct MockRequest {
    pub method: String,
    pub path: String,
    pub body: Option<Value>,
    pub headers: HashMap<String, String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl MockServerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_challenge(&self, challenge: MockChallenge) {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.insert(challenge.id.clone(), challenge);
    }

    pub fn get_challenge(&self, challenge: &str) -> Option<MockChallenge> {
        let challenges = self.challenges.lock().unwrap();
        challenges.get(challenge).cloned()
    }

    pub fn use_challenge(&self, challenge: &str) -> bool {
        let mut challenges = self.challenges.lock().unwrap();
        if let Some(ch) = challenges.get_mut(challenge) {
            if !ch.used {
                ch.used = true;
                return true;
            }
        }
        false
    }

    pub fn add_credential(&self, credential: MockCredential) {
        let mut credentials = self.credentials.lock().unwrap();
        credentials.insert(credential.id.clone(), credential);
    }

    pub fn get_credential(&self, credential_id: &str) -> Option<MockCredential> {
        let credentials = self.credentials.lock().unwrap();
        credentials.get(credential_id).cloned()
    }

    pub fn get_user_credentials(&self, user_id: &str) -> Vec<MockCredential> {
        let credentials = self.credentials.lock().unwrap();
        credentials
            .values()
            .filter(|cred| cred.user_id == user_id)
            .cloned()
            .collect()
    }

    pub fn add_user(&self, user: MockUser) {
        let mut users = self.users.lock().unwrap();
        users.insert(user.username.clone(), user);
    }

    pub fn get_user(&self, username: &str) -> Option<MockUser> {
        let users = self.users.lock().unwrap();
        users.get(username).cloned()
    }

    pub fn log_request(&self, method: &str, path: &str, body: Option<Value>) {
        let mut log = self.request_log.lock().unwrap();
        log.push(MockRequest {
            method: method.to_string(),
            path: path.to_string(),
            body,
            headers: HashMap::new(),
            timestamp: chrono::Utc::now(),
        });
    }

    pub fn clear_all(&self) {
        self.challenges.lock().unwrap().clear();
        self.credentials.lock().unwrap().clear();
        self.users.lock().unwrap().clear();
        self.request_log.lock().unwrap().clear();
    }
}

/// Mock server implementation
pub struct MockServer {
    pub state: Arc<MockServerState>,
}

impl MockServer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(MockServerState::new()),
        }
    }

    pub fn create_app(&self) -> App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >,
    > {
        let state = self.state.clone();
        
        test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(state))
                .service(
                    actix_web::web::scope("/api/v1")
                        .route("/attestation/options", actix_web::web::post().to(mock_attestation_options))
                        .route("/attestation/result", actix_web::web::post().to(mock_attestation_result))
                        .route("/assertion/options", actix_web::web::post().to(mock_assertion_options))
                        .route("/assertion/result", actix_web::web::post().to(mock_assertion_result))
                        .route("/health", actix_web::web::get().to(mock_health))
                ),
        )
    }
}

/// Mock handler for attestation options
async fn mock_attestation_options(
    state: actix_web::web::Data<Arc<MockServerState>>,
    req_body: actix_web::web::Json<Value>,
) -> Result<HttpResponse, actix_web::Error> {
    state.log_request("POST", "/api/v1/attestation/options", Some(req_body.into_inner()));

    let challenge = format!("challenge_{}", Uuid::new_v4());
    let user_id = format!("user_{}", Uuid::new_v4());

    // Store mock challenge
    let mock_challenge = MockChallenge {
        id: challenge.clone(),
        challenge: challenge.clone(),
        user_id: Some(user_id.clone()),
        challenge_type: "registration".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        used: false,
    };
    state.add_challenge(mock_challenge);

    // Store mock user
    let mock_user = MockUser {
        id: user_id.clone(),
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        created_at: chrono::Utc::now(),
    };
    state.add_user(mock_user);

    let response = serde_json::json!({
        "challenge": challenge,
        "rp": {
            "name": "Test RP",
            "id": "localhost"
        },
        "user": {
            "id": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id),
            "name": "test@example.com",
            "displayName": "Test User"
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257}
        ],
        "timeout": 60000,
        "attestation": "direct",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": false,
            "userVerification": "preferred"
        }
    });

    Ok(HttpResponse::Ok().json(response))
}

/// Mock handler for attestation result
async fn mock_attestation_result(
    state: actix_web::web::Data<Arc<MockServerState>>,
    req_body: actix_web::web::Json<Value>,
) -> Result<HttpResponse, actix_web::Error> {
    state.log_request("POST", "/api/v1/attestation/result", Some(req_body.into_inner()));

    let response = serde_json::json!({
        "status": "ok",
        "errorMessage": ""
    });

    Ok(HttpResponse::Ok().json(response))
}

/// Mock handler for assertion options
async fn mock_assertion_options(
    state: actix_web::web::Data<Arc<MockServerState>>,
    req_body: actix_web::web::Json<Value>,
) -> Result<HttpResponse, actix_web::Error> {
    state.log_request("POST", "/api/v1/assertion/options", Some(req_body.into_inner()));

    let challenge = format!("challenge_{}", Uuid::new_v4());
    let credential_id = format!("cred_{}", Uuid::new_v4());

    // Store mock challenge
    let mock_challenge = MockChallenge {
        id: challenge.clone(),
        challenge: challenge.clone(),
        user_id: Some("user_123".to_string()),
        challenge_type: "authentication".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        used: false,
    };
    state.add_challenge(mock_challenge);

    // Store mock credential
    let mock_credential = MockCredential {
        id: credential_id.clone(),
        user_id: "user_123".to_string(),
        public_key: vec![0x04, 0x01, 0x02, 0x03],
        sign_count: 0,
        created_at: chrono::Utc::now(),
        last_used_at: None,
    };
    state.add_credential(mock_credential);

    let response = serde_json::json!({
        "challenge": challenge,
        "rpId": "localhost",
        "allowCredentials": [
            {
                "type": "public-key",
                "id": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
                "transports": ["internal", "usb"]
            }
        ],
        "timeout": 60000,
        "userVerification": "preferred"
    });

    Ok(HttpResponse::Ok().json(response))
}

/// Mock handler for assertion result
async fn mock_assertion_result(
    state: actix_web::web::Data<Arc<MockServerState>>,
    req_body: actix_web::web::Json<Value>,
) -> Result<HttpResponse, actix_web::Error> {
    state.log_request("POST", "/api/v1/assertion/result", Some(req_body.into_inner()));

    let response = serde_json::json!({
        "status": "ok",
        "errorMessage": ""
    });

    Ok(HttpResponse::Ok().json(response))
}

/// Mock handler for health check
async fn mock_health(
    state: actix_web::web::Data<Arc<MockServerState>>,
) -> Result<HttpResponse, actix_web::Error> {
    state.log_request("GET", "/api/v1/health", None);

    let response = serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "version": "0.1.0",
        "database": "connected"
    });

    Ok(HttpResponse::Ok().json(response))
}

/// Mock server with error scenarios
pub struct ErrorMockServer {
    pub state: Arc<MockServerState>,
    pub error_mode: Arc<Mutex<String>>,
}

impl ErrorMockServer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(MockServerState::new()),
            error_mode: Arc::new(Mutex::new("none".to_string())),
        }
    }

    pub fn set_error_mode(&self, mode: &str) {
        let mut error_mode = self.error_mode.lock().unwrap();
        *error_mode = mode.to_string();
    }

    pub fn create_app(&self) -> App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >,
    > {
        let state = self.state.clone();
        let error_mode = self.error_mode.clone();
        
        test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(state))
                .app_data(actix_web::web::Data::new(error_mode))
                .service(
                    actix_web::web::scope("/api/v1")
                        .route("/attestation/options", actix_web::web::post().to(error_mock_attestation_options))
                        .route("/attestation/result", actix_web::web::post().to(error_mock_attestation_result))
                        .route("/assertion/options", actix_web::web::post().to(error_mock_assertion_options))
                        .route("/assertion/result", actix_web::web::post().to(error_mock_assertion_result))
                ),
        )
    }
}

/// Error mock handlers
async fn error_mock_attestation_options(
    error_mode: actix_web::web::Data<Arc<Mutex<String>>>,
    req_body: actix_web::web::Json<Value>,
) -> Result<HttpResponse, actix_web::Error> {
    let mode = error_mode.lock().unwrap().clone();
    
    match mode.as_str() {
        "server_error" => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Internal server error"
        }))),
        "timeout" => Ok(HttpResponse::RequestTimeout().json(serde_json::json!({
            "error": "Request timeout"
        }))),
        "rate_limit" => Ok(HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "Rate limit exceeded"
        }))),
        _ => Ok(HttpResponse::Ok().json(serde_json::json!({
            "challenge": "mock_challenge",
            "rp": {"name": "Test RP", "id": "localhost"},
            "user": {"id": "mock_user", "name": "test@example.com", "displayName": "Test User"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "timeout": 60000,
            "attestation": "direct"
        }))),
    }
}

async fn error_mock_attestation_result(
    error_mode: actix_web::web::Data<Arc<Mutex<String>>>,
    req_body: actix_web::web::Json<Value>,
) -> Result<HttpResponse, actix_web::Error> {
    let mode = error_mode.lock().unwrap().clone();
    
    match mode.as_str() {
        "invalid_attestation" => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid attestation statement"
        }))),
        "duplicate_credential" => Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "Credential already exists"
        }))),
        "expired_challenge" => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Challenge expired"
        }))),
        _ => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
            "errorMessage": ""
        }))),
    }
}

async fn error_mock_assertion_options(
    error_mode: actix_web::web::Data<Arc<Mutex<String>>>,
    req_body: actix_web::web::Json<Value>,
) -> Result<HttpResponse, actix_web::Error> {
    let mode = error_mode.lock().unwrap().clone();
    
    match mode.as_str() {
        "user_not_found" => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        }))),
        "no_credentials" => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "No credentials found for user"
        }))),
        _ => Ok(HttpResponse::Ok().json(serde_json::json!({
            "challenge": "mock_challenge",
            "rpId": "localhost",
            "allowCredentials": [],
            "timeout": 60000,
            "userVerification": "preferred"
        }))),
    }
}

async fn error_mock_assertion_result(
    error_mode: actix_web::web::Data<Arc<Mutex<String>>>,
    req_body: actix_web::web::Json<Value>,
) -> Result<HttpResponse, actix_web::Error> {
    let mode = error_mode.lock().unwrap().clone();
    
    match mode.as_str() {
        "invalid_signature" => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid signature"
        }))),
        "credential_not_found" => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Credential not found"
        }))),
        "replay_attack" => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Replay attack detected"
        }))),
        _ => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
            "errorMessage": ""
        }))),
    }
}