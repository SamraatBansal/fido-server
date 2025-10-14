//! Registration integration tests

use actix_test::{self, TestServer};
use actix_web::{http::StatusCode, App};
use fido_server::{routes, configure_app};
use serde_json::json;

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_attestation_options_success() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        });

        let resp = app
            .post("/attestation/options")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "ok");
        assert!(result["challenge"].as_str().is_some());
        assert!(result["rp"]["name"].as_str().is_some());
        assert_eq!(result["user"]["name"], "johndoe@example.com");
        assert_eq!(result["user"]["displayName"], "John Doe");
        assert!(result["pubKeyCredParams"].as_array().is_some());
    }

    #[actix_web::test]
    async fn test_attestation_options_missing_username() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        });

        let resp = app
            .post("/attestation/options")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "failed");
        assert!(result["errorMessage"].as_str().is_some());
    }

    #[actix_web::test]
    async fn test_attestation_options_missing_display_name() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "username": "johndoe@example.com",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        });

        let resp = app
            .post("/attestation/options")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "failed");
        assert!(result["errorMessage"].as_str().is_some());
    }

    #[actix_web::test]
    async fn test_attestation_result_success() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        // First, get a challenge
        let challenge_request = json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "attestation": "none"
        });

        let challenge_resp = app
            .post("/attestation/options")
            .send_json(&challenge_request)
            .await;

        assert_eq!(challenge_resp.status(), StatusCode::OK);

        // Mock attestation result (simplified for test)
        let request_body = json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let resp = app
            .post("/attestation/result")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "ok");
        assert_eq!(result["errorMessage"], "");
    }

    #[actix_web::test]
    async fn test_attestation_result_missing_credential() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let resp = app
            .post("/attestation/result")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "failed");
        assert!(result["errorMessage"].as_str().is_some());
    }

    #[actix_web::test]
    async fn test_attestation_result_invalid_signature() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "id": "invalid_credential_id",
            "response": {
                "clientDataJSON": "invalid_client_data",
                "attestationObject": "invalid_attestation"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let resp = app
            .post("/attestation/result")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "failed");
        assert!(result["errorMessage"].as_str().is_some());
    }
}