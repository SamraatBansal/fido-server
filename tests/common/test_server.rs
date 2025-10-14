//! Test server utilities for integration testing

use actix_web::App;
use actix_test::TestServer;

/// Create a test server instance for integration testing
pub async fn create_test_server() -> TestServer {
    actix_test::start(|| {
        App::new()
            .configure(webauthn_rp_server::routes::api::configure)
    })
}

/// Test server configuration for specific test scenarios
pub struct TestServerConfig {
    pub enable_cors: bool,
    pub enable_rate_limiting: bool,
    pub database_url: Option<String>,
}

impl Default for TestServerConfig {
    fn default() -> Self {
        Self {
            enable_cors: true,
            enable_rate_limiting: false,
            database_url: None,
        }
    }
}

/// Create a configured test server
pub async fn create_configured_test_server(_config: TestServerConfig) -> TestServer {
    actix_test::start(move || {
        let mut app = App::new();
        
        // Configure routes
        app = app.configure(webauthn_rp_server::routes::api::configure);
        
        app
    })
}