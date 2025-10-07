//! Full WebAuthn flow integration tests

#[cfg(test)]
mod tests {
    use actix_web::{test, App};
    use fido_server::routes::api::configure;

    #[tokio::test]
    async fn test_complete_registration_flow() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        // Step 1: Start registration
        let start_req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "display_name": "Test User"
            }))
            .to_request();
        
        let start_resp = test::call_service(&app, start_req).await;
        assert!(start_resp.status().is_success());
        
        let start_body: serde_json::Value = test::read_body_json(start_resp).await;
        let challenge_id = start_body["challengeId"].as_str().unwrap();
        
        // Step 2: Finish registration (mock credential)
        let finish_req = test::TestRequest::post()
            .uri("/api/v1/register/finish")
            .set_json(&serde_json::json!({
                "challenge_id": challenge_id,
                "credential": {
                    "id": "dGVzdC1jcmVkZW50aWFsLWlk",
                    "raw_id": "dGVzdC1jcmVkZW50aWFsLWlk",
                    "type": "public-key",
                    "response": {
                        "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="
                    }
                }
            }))
            .to_request();
        
        let finish_resp = test::call_service(&app, finish_req).await;
        let status = finish_resp.status();
        println!("Finish registration response status: {}", status);
        if !status.is_success() {
            let body = test::read_body(finish_resp).await;
            println!("Response body: {}", String::from_utf8_lossy(&body));
        }
        assert!(status.is_success());
    }

    #[tokio::test]
    async fn test_complete_authentication_flow() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        // First, register a user
        let start_reg_req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": "auth-test@example.com",
                "display_name": "Auth Test User"
            }))
            .to_request();
        
        let start_reg_resp = test::call_service(&app, start_reg_req).await;
        assert!(start_reg_resp.status().is_success());
        
        let start_reg_body: serde_json::Value = test::read_body_json(start_reg_resp).await;
        let reg_challenge_id = start_reg_body["challengeId"].as_str().unwrap();
        
        // Finish registration
        let finish_reg_req = test::TestRequest::post()
            .uri("/api/v1/register/finish")
            .set_json(&serde_json::json!({
                "challenge_id": reg_challenge_id,
                "credential": {
                    "id": "auth-test-credential-id",
                    "raw_id": "YXV0aC10ZXN0LWNyZWRlbnRpYWwtaWQ=",
                    "type": "public-key",
                    "response": {
                        "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="
                    }
                }
            }))
            .to_request();
        
        let finish_reg_resp = test::call_service(&app, finish_reg_req).await;
        assert!(finish_reg_resp.status().is_success());
        
        // Now test authentication
        let start_auth_req = test::TestRequest::post()
            .uri("/api/v1/authenticate/start")
            .set_json(&serde_json::json!({
                "username": "auth-test@example.com"
            }))
            .to_request();
        
        let start_auth_resp = test::call_service(&app, start_auth_req).await;
        assert!(start_auth_resp.status().is_success());
        
        let start_auth_body: serde_json::Value = test::read_body_json(start_auth_resp).await;
        let auth_challenge_id = start_auth_body["challengeId"].as_str().unwrap();
        
        // Finish authentication
        let finish_auth_req = test::TestRequest::post()
            .uri("/api/v1/authenticate/finish")
            .set_json(&serde_json::json!({
                "challenge_id": auth_challenge_id,
                "credential": {
                    "id": "auth-test-credential-id",
                    "raw_id": "YXV0aC10ZXN0LWNyZWRlbnRpYWwtaWQ=",
                    "type": "public-key",
                    "response": {
                        "authenticator_data": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ==",
                        "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==",
                        "signature": "MEUCIQCdwBCYm5PjT_Q-wwOuyRvEYR_8f2vHqGhJp3b7b8jwIgYKqL8xRf9N8f2vHqGhJp3b7b8jwYKqL8xRf9N8f2vHqGhJp3b7b8jw",
                        "user_handle": null
                    }
                }
            }))
            .to_request();
        
        let finish_auth_resp = test::call_service(&app, finish_auth_req).await;
        assert!(finish_auth_resp.status().is_success());
    }
}