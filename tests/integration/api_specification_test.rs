//! API specification compliance tests

#[cfg(test)]
mod tests {
    use actix_web::{test, web, App};
    use fido2_webauthn_server::routes::api::configure;
    use fido2_webauthn_server::services::{WebAuthnService, UserService};
    use serde_json::json;

    #[actix_web::test]
    async fn test_attestation_options_specification_compliance() {
        // Create services
        let webauthn_service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");
        let user_service = UserService::new();

        // Create test app
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .app_data(web::Data::new(user_service))
                .configure(configure)
        ).await;

        // Test valid request
        let request = json!({
            "username": "alice@example.com",
            "displayName": "Alice Smith",
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body_bytes = test::read_body(resp).await;
        let body: serde_json::Value = serde_json::from_slice(&body_bytes)
            .expect("Failed to parse JSON response");
        
        // Verify response structure according to specification
        assert_eq!(body["status"], "ok");
        assert_eq!(body["errorMessage"], "");
        assert!(body["challenge"].is_string());
        assert!(body["rp"]["name"].is_string());
        assert!(body["rp"]["id"].is_string());
        assert_eq!(body["user"]["name"], "alice@example.com");
        assert_eq!(body["user"]["displayName"], "Alice Smith");
        assert!(body["pubKeyCredParams"].is_array());
        assert!(body["timeout"].is_number());
        assert_eq!(body["attestation"], "direct");
    }

    #[actix_web::test]
    async fn test_attestation_options_missing_fields() {
        // Create services
        let webauthn_service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");
        let user_service = UserService::new();

        // Create test app
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .app_data(web::Data::new(user_service))
                .configure(configure)
        ).await;

        // Test request with missing username
        let request = json!({
            "displayName": "Alice Smith",
            "attestation": "direct"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);

        let body_bytes = test::read_body(resp).await;
        let body: serde_json::Value = serde_json::from_slice(&body_bytes)
            .expect("Failed to parse JSON response");
        
        // Verify error response structure
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].is_string());
        assert_ne!(body["errorMessage"], "");
    }

    #[actix_web::test]
    async fn test_attestation_result_specification_compliance() {
        // Create services
        let webauthn_service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");
        let user_service = UserService::new();

        // Create test app
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .app_data(web::Data::new(user_service))
                .configure(configure)
        ).await;

        // Test valid attestation result
        let request = json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "rawId": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "type": "public-key",
            "getClientExtensionResults": {}
        });

        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body_bytes = test::read_body(resp).await;
        let body: serde_json::Value = serde_json::from_slice(&body_bytes)
            .expect("Failed to parse JSON response");
        
        // Verify response structure according to specification
        assert_eq!(body["status"], "ok");
        assert_eq!(body["errorMessage"], "");
    }

    #[actix_web::test]
    async fn test_assertion_options_specification_compliance() {
        // Create services
        let webauthn_service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");
        let user_service = UserService::new();

        // Create test app
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .app_data(web::Data::new(user_service))
                .configure(configure)
        ).await;

        // Test valid request
        let request = json!({
            "username": "alice@example.com",
            "userVerification": "preferred"
        });

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body_bytes = test::read_body(resp).await;
        let body: serde_json::Value = serde_json::from_slice(&body_bytes)
            .expect("Failed to parse JSON response");
        
        // Verify response structure according to specification
        assert_eq!(body["status"], "ok");
        assert_eq!(body["errorMessage"], "");
        assert!(body["challenge"].is_string());
        assert_eq!(body["rpId"], "localhost");
        assert!(body["allowCredentials"].is_array());
        assert!(body["timeout"].is_number());
        assert_eq!(body["userVerification"], "required");
    }

    #[actix_web::test]
    async fn test_assertion_result_specification_compliance() {
        // Create services
        let webauthn_service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");
        let user_service = UserService::new();

        // Create test app
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .app_data(web::Data::new(user_service))
                .configure(configure)
        ).await;

        // Test valid assertion result
        let request = json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "rawId": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "type": "public-key",
            "getClientExtensionResults": {}
        });

        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body_bytes = test::read_body(resp).await;
        let body: serde_json::Value = serde_json::from_slice(&body_bytes)
            .expect("Failed to parse JSON response");
        
        // Verify response structure according to specification
        assert_eq!(body["status"], "ok");
        assert_eq!(body["errorMessage"], "");
    }
}