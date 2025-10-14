//! Authentication (Assertion) controllers
//!
//! Handles the FIDO2/WebAuthn authentication flow endpoints:
//! - POST /assertion/options - Generate authentication options
//! - POST /assertion/result - Verify assertion response

use actix_web::{web, HttpResponse, Result as ActixResult};
use base64::Engine;
use rand::RngCore;

use crate::schema::{
    AssertionPublicKeyCredential, ServerPublicKeyCredentialDescriptor,
    ServerPublicKeyCredentialGetOptionsRequest, ServerPublicKeyCredentialGetOptionsResponse,
    ServerResponse,
};
use crate::AppError;

/// Generate assertion options for authentication
pub async fn assertion_options(
    req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> ActixResult<HttpResponse, AppError> {
    // Generate a random challenge
    let mut challenge_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

    // TODO: Look up user's credentials from database
    // For now, return a mock credential
    let allow_credentials = vec![ServerPublicKeyCredentialDescriptor {
        type_: "public-key".to_string(),
        id: "BASE64URL".to_string(),
        transports: Some(vec!["usb".to_string(), "nfc".to_string()]),
    }];

    let response = ServerPublicKeyCredentialGetOptionsResponse {
        base: ServerResponse::ok(),
        challenge,
        rp_id: "example.com".to_string(),
        allow_credentials: Some(allow_credentials),
        timeout: Some(60000),
        user_verification: req.user_verification.clone(),
        extensions: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Verify assertion result
pub async fn assertion_result(
    req: web::Json<AssertionPublicKeyCredential>,
) -> ActixResult<HttpResponse, AppError> {
    // Basic validation
    if req.type_ != "public-key" {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid credential type")));
    }

    if req.id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing credential ID")));
    }

    if req.response.base.client_data_json.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing clientDataJSON")));
    }

    if req.response.authenticator_data.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing authenticatorData")));
    }

    if req.response.signature.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing signature")));
    }

    // Validate base64url encoding
    if base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.response.base.client_data_json)
        .is_err()
    {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid clientDataJSON encoding")));
    }

    if base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.response.authenticator_data)
        .is_err()
    {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid authenticatorData encoding")));
    }

    if base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.response.signature)
        .is_err()
    {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid signature encoding")));
    }

    // TODO: Implement full WebAuthn assertion verification
    // For now, return success for valid format
    Ok(HttpResponse::Ok().json(ServerResponse::ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use crate::schema::ServerAuthenticatorAssertionResponse;

    #[actix_web::test]
    async fn test_assertion_options_success() {
        let req = ServerPublicKeyCredentialGetOptionsRequest {
            username: "alice".to_string(),
            user_verification: Some("preferred".to_string()),
        };

        let result = assertion_options(web::Json(req)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[actix_web::test]
    async fn test_assertion_result_invalid_type() {
        let mut credential = create_test_assertion_credential();
        credential.type_ = "invalid".to_string();

        let result = assertion_result(web::Json(credential)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[actix_web::test]
    async fn test_assertion_result_missing_id() {
        let mut credential = create_test_assertion_credential();
        credential.id = String::new();

        let result = assertion_result(web::Json(credential)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[actix_web::test]
    async fn test_assertion_result_missing_signature() {
        let mut credential = create_test_assertion_credential();
        credential.response.signature = String::new();

        let result = assertion_result(web::Json(credential)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[actix_web::test]
    async fn test_assertion_result_invalid_base64() {
        let mut credential = create_test_assertion_credential();
        credential.response.base.client_data_json = "invalid-base64!".to_string();

        let result = assertion_result(web::Json(credential)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }

    fn create_test_assertion_credential() -> AssertionPublicKeyCredential {
        AssertionPublicKeyCredential {
            id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            raw_id: None,
            response: ServerAuthenticatorAssertionResponse {
                base: crate::schema::ServerAuthenticatorResponse {
                    client_data_json: "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9".to_string(),
                },
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
                signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
                user_handle: Some("".to_string()),
            },
            type_: "public-key".to_string(),
            get_client_extension_results: None,
        }
    }
}