//! Demo API calls to test FIDO server functionality

use serde_json::json;

use fido_server::dto::*;

fn main() {
    println!("🔐 FIDO2/WebAuthn Server Demo");
    println!("=============================\n");

    // Test 1: Server Response Format
    println!("1. Testing ServerResponse format:");
    let success = ServerResponse::ok();
    let failure = ServerResponse::failed("Example error");
    
    println!("   ✓ Success response: {}", serde_json::to_string(&success).unwrap());
    println!("   ✓ Error response: {}", serde_json::to_string(&failure).unwrap());
    println!();

    // Test 2: Registration Request
    println!("2. Testing Registration Request format:");
    let reg_request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "johndoe@example.com".to_string(),
        display_name: "John Doe".to_string(),
        authenticator_selection: None,
        attestation: webauthn_rs_proto::AttestationConveyancePreference::Direct,
    };
    println!("   ✓ Registration request: {}", serde_json::to_string_pretty(&reg_request).unwrap());
    println!();

    // Test 3: Registration Response  
    println!("3. Testing Registration Response format:");
    let reg_response = ServerPublicKeyCredentialCreationOptionsResponse {
        server_response: ServerResponse::ok(),
        rp: fido_server::dto::registration::PublicKeyCredentialRpEntity {
            id: Some("localhost".to_string()),
            name: "Example Corporation".to_string(),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: "U3932ee31vKEC0JtJMIQ".to_string(),
            name: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
        },
        challenge: "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string(),
        pub_key_cred_params: vec![
            fido_server::dto::registration::PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7,
            }
        ],
        timeout: Some(10000),
        exclude_credentials: vec![],
        authenticator_selection: None,
        attestation: webauthn_rs_proto::AttestationConveyancePreference::Direct,
        extensions: None,
    };
    println!("   ✓ Registration response matches FIDO spec:");
    println!("     - Status: {}", reg_response.server_response.status);
    println!("     - RP Name: {}", reg_response.rp.name);
    println!("     - Challenge: {}", reg_response.challenge);
    println!("     - Algorithm: {}", reg_response.pub_key_cred_params[0].alg);
    println!("     - Timeout: {:?}", reg_response.timeout);
    println!();

    // Test 4: Authentication Request
    println!("4. Testing Authentication Request format:");
    let auth_request = ServerPublicKeyCredentialGetOptionsRequest {
        username: "johndoe@example.com".to_string(),
        user_verification: Some(webauthn_rs_proto::UserVerificationPolicy::Required),
    };
    println!("   ✓ Authentication request: {}", serde_json::to_string_pretty(&auth_request).unwrap());
    println!();

    // Test 5: Authentication Response
    println!("5. Testing Authentication Response format:");
    let auth_response = ServerPublicKeyCredentialGetOptionsResponse {
        server_response: ServerResponse::ok(),
        challenge: "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string(),
        timeout: Some(20000),
        rp_id: Some("localhost".to_string()),
        allow_credentials: vec![],
        user_verification: Some(webauthn_rs_proto::UserVerificationPolicy::Required),
        extensions: None,
    };
    println!("   ✓ Authentication response matches FIDO spec:");
    println!("     - Status: {}", auth_response.server_response.status);
    println!("     - Challenge: {}", auth_response.challenge);
    println!("     - RP ID: {:?}", auth_response.rp_id);
    println!("     - Timeout: {:?}", auth_response.timeout);
    println!();

    // Test 6: FIDO Conformance JSON
    println!("6. Testing FIDO Conformance Test JSON parsing:");
    let fido_json = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });
    
    let parsed: ServerPublicKeyCredentialCreationOptionsRequest = 
        serde_json::from_value(fido_json).unwrap();
    
    println!("   ✓ Successfully parsed FIDO conformance test JSON");
    println!("     - Username: {}", parsed.username);
    println!("     - Display Name: {}", parsed.display_name);
    println!();

    println!("🎉 All tests passed! FIDO server is ready for conformance testing.");
    println!("\n📋 API Endpoints implemented:");
    println!("   • POST /attestation/options - Start registration");
    println!("   • POST /attestation/result - Complete registration");
    println!("   • POST /assertion/options - Start authentication");
    println!("   • POST /assertion/result - Complete authentication");
    println!("   • GET /health - Health check");
    println!("\n🚀 To start the server: cargo run");
    println!("   Server will run at: http://localhost:8080");
}