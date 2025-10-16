//! Registration integration tests

use actix_web::{test, web, App};
use fido_server::routes::api::configure;
use fido_server::models::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredential,
    ServerAuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
};

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    assert_eq!(body["rp"]["name"], "Example Corporation");
    assert_eq!(body["user"]["name"], "johndoe@example.com");
    assert_eq!(body["user"]["displayName"], "John Doe");
    assert!(!body["challenge"].as_str().unwrap().is_empty());
    assert_eq!(body["pubKeyCredParams"][0]["type"], "public-key");
    assert_eq!(body["pubKeyCredParams"][0]["alg"], -7);
    assert_eq!(body["timeout"], 10000);
    assert_eq!(body["attestation"], "direct");
}

#[actix_web::test]
async fn test_attestation_options_default_values() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    assert_eq!(body["attestation"], "none");
    assert!(body["excludeCredentials"].as_array().unwrap().is_empty());
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&ServerPublicKeyCredential {
            id: "test-credential-id".to_string(),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
                attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            },
            get_client_extension_results: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
}

#[actix_web::test]
async fn test_attestation_result_missing_credential_id() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let mut credential = ServerPublicKeyCredential {
        id: "".to_string(), // Empty ID should cause error
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAttestationResponse {
            client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
        },
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&credential)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 400);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("Missing credential ID"));
}

#[actix_web::test]
async fn test_attestation_result_missing_client_data() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let credential = ServerPublicKeyCredential {
        id: "test-credential-id".to_string(),
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAttestationResponse {
            client_data_json: "".to_string(), // Empty client data should cause error
            attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
        },
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&credential)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 400);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("Missing clientDataJSON"));
}

#[actix_web::test]
async fn test_attestation_result_missing_attestation_object() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let credential = ServerPublicKeyCredential {
        id: "test-credential-id".to_string(),
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAttestationResponse {
            client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            attestation_object: "".to_string(), // Empty attestation object should cause error
        },
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&credential)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 400);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("Missing attestationObject"));
}