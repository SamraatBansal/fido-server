use serde_json;

#[derive(Debug, serde::Deserialize)]
struct NewmanAttestationRequest {
    username: String,
    displayName: String,
    authenticatorSelection: Option<NewmanAuthenticatorSelection>,
    attestation: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct NewmanAuthenticatorSelection {
    requireResidentKey: Option<bool>,
    authenticatorAttachment: Option<String>,
    userVerification: Option<String>,
}

fn main() {
    // Test the Newman request format
    let newman_request = r#"{
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }"#;
    
    match serde_json::from_str::<NewmanAttestationRequest>(newman_request) {
        Ok(req) => println!("Successfully parsed: {:?}", req),
        Err(e) => println!("Parse error: {}", e),
    }
}