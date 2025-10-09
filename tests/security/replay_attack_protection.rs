//! Security tests for replay attack protection

use actix_web::http::StatusCode;
use crate::common::{create_test_app, post_json, read_body_json};
use fido2_webauthn_server::schema::*;

#[cfg(test)]
mod replay_attack_tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_uniqueness_prevents_replay() {
        let app = create_test_app().await;

        // Generate multiple challenges for the same user
        let request = RegistrationRequestFactory::valid();
        
        let response1 = post_json(&app, "/attestation/options", request.clone()).await;
        let response2 = post_json(&app, "/attestation/options", request.clone()).await;
        let response3 = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response1.status(), StatusCode::OK);
        assert_eq!(response2.status(), StatusCode::OK);
        assert_eq!(response3.status(), StatusCode::OK);
        
        let options1: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response1).await;
        let options2: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response2).await;
        let options3: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response3).await;
        
        // All challenges should be different
        let challenges = vec![&options1.challenge, &options2.challenge, &options3.challenge];
        let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
        
        assert_eq!(unique_challenges.len(), 3, "All challenges should be unique");
        
        // Verify challenges are cryptographically random
        assert!(fido2_webauthn_server::utils::crypto::verify_entropy(&challenges), 
                "Challenges should have good entropy");
    }

    #[tokio::test]
    async fn test_authentication_challenge_uniqueness() {
        let app = create_test_app().await;

        let request = AuthenticationRequestFactory::valid();
        
        let response1 = post_json(&app, "/assertion/options", request.clone()).await;
        let response2 = post_json(&app, "/assertion/options", request.clone()).await;
        let response3 = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response1.status(), StatusCode::OK);
        assert_eq!(response2.status(), StatusCode::OK);
        assert_eq!(response3.status(), StatusCode::OK);
        
        let options1: crate::fixtures::ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response1).await;
        let options2: crate::fixtures::ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response2).await;
        let options3: crate::fixtures::ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response3).await;
        
        // All challenges should be different
        let challenges = vec![&options1.challenge, &options2.challenge, &options3.challenge];
        let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
        
        assert_eq!(unique_challenges.len(), 3, "All authentication challenges should be unique");
        
        // Verify challenges are cryptographically random
        assert!(fido2_webauthn_server::utils::crypto::verify_entropy(&challenges), 
                "Authentication challenges should have good entropy");
    }

    #[tokio::test]
    async fn test_challenge_entropy_verification() {
        // Generate a large number of challenges to test entropy
        let mut challenges = Vec::new();
        
        for _ in 0..1000 {
            challenges.push(fido2_webauthn_server::utils::crypto::generate_secure_challenge());
        }
        
        // Verify entropy
        assert!(fido2_webauthn_server::utils::crypto::verify_entropy(&challenges), 
                "Generated challenges should have sufficient entropy");
        
        // Test statistical uniqueness
        let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
        assert_eq!(unique_challenges.len(), challenges.len(), 
                  "All challenges should be statistically unique");
    }

    #[tokio::test]
    async fn test_challenge_length_consistency() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        
        // Generate multiple challenges and check length consistency
        for _ in 0..10 {
            let response = post_json(&app, "/attestation/options", request.clone()).await;
            assert_eq!(response.status(), StatusCode::OK);
            
            let options_response: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
                read_body_json(response).await;
            
            let challenge = &options_response.challenge;
            
            // Challenge should be reasonable length (base64url encoded 32 bytes = 43 chars)
            assert!(challenge.len() >= 16, "Challenge should be at least 16 characters");
            assert!(challenge.len() <= 128, "Challenge should not exceed 128 characters");
            
            // When decoded, should be at least 16 bytes
            let decoded = fido2_webauthn_server::utils::crypto::decode_base64url(challenge).unwrap();
            assert!(decoded.len() >= 16, "Decoded challenge should be at least 16 bytes");
        }
    }

    #[tokio::test]
    async fn test_challenge_base64url_encoding() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        let challenge = &options_response.challenge;
        
        // Should be valid base64url (no +, /, or = characters)
        assert!(!challenge.contains('+'), "Challenge should not contain '+'");
        assert!(!challenge.contains('/'), "Challenge should not contain '/'");
        assert!(!challenge.contains('='), "Challenge should not contain '='");
        
        // Should be decodable
        assert!(fido2_webauthn_server::utils::crypto::decode_base64url(challenge).is_ok(), 
                "Challenge should be valid base64url");
    }

    #[tokio::test]
    async fn test_user_id_uniqueness() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        
        // Generate multiple user IDs for different requests
        let mut user_ids = Vec::new();
        
        for _ in 0..10 {
            let response = post_json(&app, "/attestation/options", request.clone()).await;
            assert_eq!(response.status(), StatusCode::OK);
            
            let options_response: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
                read_body_json(response).await;
            
            user_ids.push(options_response.user.id.clone());
        }
        
        // All user IDs should be different
        let unique_user_ids: std::collections::HashSet<_> = user_ids.iter().collect();
        assert_eq!(unique_user_ids.len(), user_ids.len(), "All user IDs should be unique");
        
        // User IDs should be valid base64url
        for user_id in &user_ids {
            assert!(fido2_webauthn_server::utils::crypto::decode_base64url(user_id).is_ok(), 
                    "User ID should be valid base64url");
            
            let decoded = fido2_webauthn_server::utils::crypto::decode_base64url(user_id).unwrap();
            assert_eq!(decoded.len(), 16, "User ID should be 16 bytes when decoded (UUID)");
        }
    }

    #[tokio::test]
    async fn test_credential_id_uniqueness_in_fixtures() {
        // Test that our fixture factory generates unique credential IDs
        let mut credential_ids = std::collections::HashSet::new();
        
        for _ in 0..100 {
            let cred_id = generate_test_credential_id();
            assert!(!credential_ids.contains(&cred_id), "Credential ID should be unique");
            credential_ids.insert(cred_id);
        }
        
        assert_eq!(credential_ids.len(), 100, "Should have 100 unique credential IDs");
    }

    #[tokio::test]
    async fn test_timing_attack_resistance() {
        let app = create_test_app().await;

        // Test that response times are consistent regardless of input validity
        let valid_request = RegistrationRequestFactory::valid();
        let invalid_request = RegistrationRequestFactory::empty_username();
        
        // Measure time for valid request
        let start = std::time::Instant::now();
        let response1 = post_json(&app, "/attestation/options", valid_request).await;
        let valid_time = start.elapsed();
        
        // Measure time for invalid request
        let start = std::time::Instant::now();
        let response2 = post_json(&app, "/attestation/options", invalid_request).await;
        let invalid_time = start.elapsed();
        
        // Both should complete, but we're checking that there's no extremely long delay
        // that could indicate timing-based information leakage
        assert!(valid_time.as_millis() < 1000, "Valid request should complete quickly");
        assert!(invalid_time.as_millis() < 1000, "Invalid request should complete quickly");
        
        // Time difference should not be excessive (within reasonable bounds)
        let time_diff = if valid_time > invalid_time {
            valid_time - invalid_time
        } else {
            invalid_time - valid_time
        };
        
        // Allow some variance but not extreme differences
        assert!(time_diff.as_millis() < 500, "Response times should be consistent");
    }

    #[tokio::test]
    async fn test_challenge_reuse_detection() {
        // This test would be more relevant with a real challenge store
        // For now, we test that challenges are unique which prevents reuse
        
        let app = create_test_app().await;
        let request = RegistrationRequestFactory::valid();
        
        // Get two challenges
        let response1 = post_json(&app, "/attestation/options", request.clone()).await;
        let response2 = post_json(&app, "/attestation/options", request).await;
        
        let options1: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response1).await;
        let options2: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response2).await;
        
        // Challenges should be different (prevents simple replay)
        assert_ne!(options1.challenge, options2.challenge, 
                  "Different requests should generate different challenges");
    }

    #[tokio::test]
    async fn test_concurrent_challenge_generation() {
        use std::sync::Arc;
        use std::sync::Mutex;
        use tokio::task::JoinSet;
        
        let app = Arc::new(create_test_app().await);
        let challenges = Arc::new(Mutex::new(Vec::new()));
        
        // Generate challenges concurrently
        let mut set = JoinSet::new();
        
        for i in 0..50 {
            let app_clone = Arc::clone(&app);
            let challenges_clone = Arc::clone(&challenges);
            let request = RegistrationRequestFactory::valid();
            
            set.spawn(async move {
                let response = post_json(&*app_clone, "/attestation/options", request).await;
                if response.status() == StatusCode::OK {
                    let options_response: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
                        read_body_json(response).await;
                    challenges_clone.lock().unwrap().push(options_response.challenge);
                }
            });
        }
        
        // Wait for all tasks to complete
        while let Some(_) = set.join_next().await {}
        
        // Check that all challenges are unique
        let challenges_vec = challenges.lock().unwrap();
        let unique_challenges: std::collections::HashSet<_> = challenges_vec.iter().collect();
        
        assert_eq!(unique_challenges.len(), challenges_vec.len(), 
                  "Concurrent challenge generation should produce unique challenges");
    }

    #[tokio::test]
    async fn test_challenge_predictability_resistance() {
        // Test that challenges are not predictable based on previous values
        let mut challenges = Vec::new();
        
        // Generate sequence of challenges
        for _ in 0..10 {
            challenges.push(fido2_webauthn_server::utils::crypto::generate_secure_challenge());
        }
        
        // Simple statistical test - challenges should not follow obvious patterns
        for i in 1..challenges.len() {
            // Challenges should be different
            assert_ne!(challenges[i], challenges[i-1], "Consecutive challenges should differ");
            
            // Simple pattern detection - check if challenges are incrementing in a predictable way
            let bytes1 = fido2_webauthn_server::utils::crypto::decode_base64url(&challenges[i-1]).unwrap();
            let bytes2 = fido2_webauthn_server::utils::crypto::decode_base64url(&challenges[i]).unwrap();
            
            // Should not be sequential (this is a basic check)
            let mut sequential = true;
            for j in 0..bytes1.len().min(bytes2.len()) {
                if bytes2[j] != bytes1[j].wrapping_add(1) {
                    sequential = false;
                    break;
                }
            }
            
            assert!(!sequential, "Challenges should not be sequential");
        }
    }
}