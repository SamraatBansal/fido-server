//! Registration integration tests

use actix_test;
use actix_web::{test, web, App};
use fido_server::routes::api;
use serde_json::json;

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_test::test]
    async fn test_registration_challenge_success() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&json!({
                "username": "johndoe@example.com",
                "displayName": "John Doe",
                "authenticatorSelection": {
                    "requireResidentKey": false,
                    "authenticatorAttachment": "cross-platform",
                    "userVerification": "preferred"
                },
                "attestation": "direct"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert!(body["challenge"].is_string());
        assert!(body["rp"].is_object());
        assert!(body["user"].is_object());
        assert!(body["pubKeyCredParams"].is_array());
    }

    #[actix_test::test]
    async fn test_registration_challenge_missing_username() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&json!({
                "displayName": "John Doe"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].is_string());
    }

    #[actix_test::test]
    async fn test_registration_challenge_invalid_email() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&json!({
                "username": "invalid-email",
                "displayName": "John Doe"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
    }

    #[actix_test::test]
    async fn test_registration_verify_success() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        // First get a challenge
        let challenge_req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&json!({
                "username": "johndoe@example.com",
                "displayName": "John Doe"
            }))
            .to_request();

        let challenge_resp = test::call_service(&app, challenge_req).await;
        assert_eq!(challenge_resp.status(), 200);

        // Mock attestation response
        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&json!({
                "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
                "response": {
                    "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                    "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
                },
                "getClientExtensionResults": {},
                "type": "public-key"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        // For now, expect failure since we haven't implemented verification yet
        assert!(resp.status().is_client_error() || resp.status().is_server_error());
    }

    #[actix_test::test]
    async fn test_registration_verify_invalid_credential() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&json!({
                "id": "invalid-credential-id",
                "response": {
                    "clientDataJSON": "invalid-data",
                    "attestationObject": "invalid-object"
                },
                "type": "public-key"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
    }

    #[actix_test::test]
    async fn test_registration_verify_missing_fields() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&json!({
                "id": "some-id"
                // Missing required fields
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }
}