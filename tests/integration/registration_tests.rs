//! Registration integration tests

use actix_web::{test, App, http::StatusCode};
use serde_json::json;
use fido_server::routes::configure;

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
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
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "ok");
    assert!(result["challenge"].as_str().is_some());
    assert_eq!(result["rp"]["name"], "Example Corporation");
    assert_eq!(result["user"]["name"], "johndoe@example.com");
    assert_eq!(result["user"]["displayName"], "John Doe");
    assert!(result["pubKeyCredParams"].as_array().is_some());
    assert_eq!(result["attestation"], "direct");
}

#[actix_web::test]
async fn test_attestation_options_missing_username() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
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
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("username"));
}

#[actix_web::test]
async fn test_attestation_options_missing_display_name() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "username": "johndoe@example.com",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("displayName"));
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    // First, get attestation options to establish a challenge
    let options_req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
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

    let options_resp = test::call_service(&app, options_req).await;
    let options_result: serde_json::Value = test::read_body_json(options_resp).await;
    let challenge = options_result["challenge"].as_str().unwrap();

    // Mock attestation response (this would normally come from an authenticator)
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": format!("{{\"challenge\":\"{}\",\"origin\":\"http://localhost:3000\",\"type\":\"webauthn.create\"}}", challenge),
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
}

#[actix_web::test]
async fn test_attestation_result_invalid_challenge() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "{\"challenge\":\"invalid_challenge\",\"origin\":\"http://localhost:3000\",\"type\":\"webauthn.create\"}",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("challenge"));
}

#[actix_web::test]
async fn test_attestation_result_missing_fields() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("response"));
}