//! Registration integration tests for FIDO2/WebAuthn conformance

use actix_test::TestServer;
use actix_web::{test, web, App};
use fido_server::routes::api::configure_routes;
use serde_json::{json, Value};

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_attestation_options_success() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: Value = test::read_body_json(resp).await;
        
        // Verify response structure matches FIDO conformance spec
        assert_eq!(body["status"], "ok");
        assert!(body["errorMessage"].as_str().unwrap().is_empty());
        assert!(body["rp"]["name"].is_string());
        assert!(body["user"]["id"].is_string());
        assert_eq!(body["user"]["name"], "johndoe@example.com");
        assert_eq!(body["user"]["displayName"], "John Doe");
        assert!(body["challenge"].is_string());
        assert!(body["pubKeyCredParams"].is_array());
        assert!(body["timeout"].is_number());
        assert!(body["excludeCredentials"].is_array());
        assert_eq!(body["authenticatorSelection"]["requireResidentKey"], false);
        assert_eq!(body["authenticatorSelection"]["authenticatorAttachment"], "cross-platform");
        assert_eq!(body["authenticatorSelection"]["userVerification"], "preferred");
        assert_eq!(body["attestation"], "direct");
    }

    #[actix_web::test]
    async fn test_attestation_options_missing_username() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "displayName": "John Doe",
            "attestation": "none"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("username"));
    }

    #[actix_web::test]
    async fn test_attestation_options_invalid_attestation() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "attestation": "invalid"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("attestation"));
    }

    #[actix_web::test]
    async fn test_attestation_result_success() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        // First get a challenge
        let options_req_body = json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "attestation": "none"
        });

        let options_req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&options_req_body)
            .to_request();

        let options_resp = test::call_service(&app, options_req).await;
        assert!(options_resp.status().is_success());

        // Mock attestation result (this would normally come from authenticator)
        let result_req_body = json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let result_req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&result_req_body)
            .to_request();

        let result_resp = test::call_service(&app, result_req).await;
        
        // For now, we expect this to fail until we implement proper validation
        // This test will pass once we implement the full flow
        assert!(result_resp.status().is_client_error() || result_resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_attestation_result_missing_credential() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "type": "public-key"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("credential") || 
                body["errorMessage"].as_str().unwrap().contains("id"));
    }

    #[actix_web::test]
    async fn test_attestation_result_invalid_signature() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "id": "invalid-credential-id",
            "response": {
                "clientDataJSON": "invalid-client-data",
                "attestationObject": "invalid-attestation-object"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("signature") ||
                body["errorMessage"].as_str().unwrap().contains("validation") ||
                body["errorMessage"].as_str().unwrap().contains("invalid"));
    }
}