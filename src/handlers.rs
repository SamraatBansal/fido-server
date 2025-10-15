use actix_web::{web, HttpResponse, Result as ActixResult};
use crate::models::*;
use crate::error::{AppError, Result};
use crate::services::WebAuthnService;

pub async fn attestation_options(
    request: web::Json<AttestationOptionsRequest>,
    service: web::Data<WebAuthnService>,
) -> ActixResult<HttpResponse> {
    match service.begin_registration(&request).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => Ok(e.error_response()),
    }
}

pub async fn attestation_result(
    request: web::Json<AttestationResultRequest>,
    service: web::Data<WebAuthnService>,
) -> ActixResult<HttpResponse> {
    match service.complete_registration(&request).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => Ok(e.error_response()),
    }
}

pub async fn assertion_options(
    request: web::Json<AssertionOptionsRequest>,
    service: web::Data<WebAuthnService>,
) -> ActixResult<HttpResponse> {
    match service.begin_authentication(&request).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => Ok(e.error_response()),
    }
}

pub async fn assertion_result(
    request: web::Json<AssertionResultRequest>,
    service: web::Data<WebAuthnService>,
) -> ActixResult<HttpResponse> {
    match service.complete_authentication(&request).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => Ok(e.error_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use crate::services::MockWebAuthnService;
    use mockall::predicate::*;

    #[actix_web::test]
    async fn test_attestation_options_success() {
        let mut mock_service = MockWebAuthnService::new();
        
        let expected_response = AttestationOptionsResponse {
            base: ServerResponse::ok(),
            rp: Some(RelyingParty {
                name: "Example Corporation".to_string(),
                id: None,
            }),
            user: Some(UserEntity {
                id: "S3932ee31vKEC0JtJMIQ".to_string(),
                name: "johndoe@example.com".to_string(),
                display_name: "John Doe".to_string(),
            }),
            challenge: Some("uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string()),
            pub_key_cred_params: Some(vec![PubKeyCredParam {
                cred_type: "public-key".to_string(),
                alg: -7,
            }]),
            timeout: Some(10000),
            exclude_credentials: Some(vec![CredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: "opQf1WmYAa5aupUKJIQp".to_string(),
                transports: None,
            }]),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
        };

        mock_service
            .expect_begin_registration()
            .with(always())
            .times(1)
            .returning(move |_| Ok(expected_response.clone()));

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_service))
                .route("/attestation/options", web::post().to(attestation_options))
        ).await;

        let request_body = AttestationOptionsRequest {
            username: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: "direct".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let response_body: AttestationOptionsResponse = test::read_body_json(resp).await;
        assert_eq!(response_body.base.status, "ok");
        assert!(response_body.challenge.is_some());
        assert!(response_body.user.is_some());
    }

    #[actix_web::test]
    async fn test_attestation_options_validation_error() {
        let mut mock_service = MockWebAuthnService::new();
        
        mock_service
            .expect_begin_registration()
            .with(always())
            .times(1)
            .returning(|_| Err(AppError::ValidationError("Missing username field!".to_string())));

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_service))
                .route("/attestation/options", web::post().to(attestation_options))
        ).await;

        let request_body = AttestationOptionsRequest {
            username: "".to_string(), // Invalid empty username
            display_name: "John Doe".to_string(),
            authenticator_selection: None,
            attestation: "none".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);

        let response_body: ServerResponse = test::read_body_json(resp).await;
        assert_eq!(response_body.status, "failed");
        assert!(response_body.error_message.contains("Missing username field!"));
    }

    #[actix_web::test]
    async fn test_assertion_options_user_not_found() {
        let mut mock_service = MockWebAuthnService::new();
        
        mock_service
            .expect_begin_authentication()
            .with(always())
            .times(1)
            .returning(|_| Err(AppError::UserNotFound));

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_service))
                .route("/assertion/options", web::post().to(assertion_options))
        ).await;

        let request_body = AssertionOptionsRequest {
            username: "nonexistent@example.com".to_string(),
            user_verification: Some("required".to_string()),
        };

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);

        let response_body: ServerResponse = test::read_body_json(resp).await;
        assert_eq!(response_body.status, "failed");
        assert_eq!(response_body.error_message, "User does not exist!");
    }
}