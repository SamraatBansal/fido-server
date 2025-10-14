//! Registration (Attestation) controllers
//!
//! Handles the FIDO2/WebAuthn registration flow endpoints:
//! - POST /attestation/options - Generate registration options
//! - POST /attestation/result - Verify attestation response

use actix_web::{web, HttpResponse, Result as ActixResult};
use base64::Engine;
use rand::RngCore;
use uuid::Uuid;

use crate::schema::{
    AttestationPublicKeyCredential, PublicKeyCredentialParameters, PublicKeyCredentialRpEntity,
    ServerPublicKeyCredentialCreationOptionsRequest, ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredentialUserEntity, ServerResponse,
};
use crate::AppError;

/// Generate attestation options for registration
pub async fn attestation_options(
    req: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> ActixResult<HttpResponse, AppError> {
    // Generate a random challenge
    let mut challenge_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

    // Generate user ID
    let user_id_bytes = Uuid::new_v4().as_bytes().to_vec();
    let user_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id_bytes);

    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        base: ServerResponse::ok(),
        rp: PublicKeyCredentialRpEntity {
            name: "Example Corporation".to_string(),
            id: Some("example.com".to_string()),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: user_id,
            name: req.username.clone(),
            display_name: req.display_name.clone(),
        },
        challenge,
        pub_key_cred_params: vec![
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7, // ES256
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -257, // RS256
            },
        ],
        timeout: Some(60000),
        exclude_credentials: None,
        authenticator_selection: req.authenticator_selection.clone(),
        attestation: req.attestation.clone(),
        extensions: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Verify attestation result
pub async fn attestation_result(
    req: web::Json<AttestationPublicKeyCredential>,
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

    if req.response.attestation_object.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing attestationObject")));
    }

    // Validate base64url encoding
    if base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.response.base.client_data_json)
        .is_err()
    {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid clientDataJSON encoding")));
    }

    if base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.response.attestation_object)
        .is_err()
    {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid attestationObject encoding")));
    }

    // TODO: Implement full WebAuthn attestation verification
    // For now, return success for valid format
    Ok(HttpResponse::Ok().json(ServerResponse::ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use crate::schema::{AuthenticatorSelectionCriteria, ServerAuthenticatorAttestationResponse};

    #[actix_web::test]
    async fn test_attestation_options_success() {
        let req = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "alice".to_string(),
            display_name: "Alice Smith".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: Some("platform".to_string()),
                require_resident_key: Some(false),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
        };

        let result = attestation_options(web::Json(req)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[actix_web::test]
    async fn test_attestation_result_invalid_type() {
        let mut credential = create_test_attestation_credential();
        credential.type_ = "invalid".to_string();

        let result = attestation_result(web::Json(credential)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[actix_web::test]
    async fn test_attestation_result_missing_id() {
        let mut credential = create_test_attestation_credential();
        credential.id = String::new();

        let result = attestation_result(web::Json(credential)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[actix_web::test]
    async fn test_attestation_result_invalid_base64() {
        let mut credential = create_test_attestation_credential();
        credential.response.base.client_data_json = "invalid-base64!".to_string();

        let result = attestation_result(web::Json(credential)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }

    fn create_test_attestation_credential() -> AttestationPublicKeyCredential {
        AttestationPublicKeyCredential {
            id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            raw_id: None,
            response: ServerAuthenticatorAttestationResponse {
                base: crate::schema::ServerAuthenticatorResponse {
                    client_data_json: "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9".to_string(),
                },
                attestation_object: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI".to_string(),
            },
            type_: "public-key".to_string(),
            get_client_extension_results: None,
        }
    }
}