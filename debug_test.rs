use webauthn_rp_server::dto::*;

fn main() {
    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        base: ServerResponse::ok(),
        rp: PublicKeyCredentialRpEntity {
            name: "Example Corporation".to_string(),
            id: Some("example.com".to_string()),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: "S3932ee31vKEC0JtJMIQ".to_string(),
            name: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
        },
        challenge: "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string(),
        pub_key_cred_params: vec![
            PublicKeyCredentialParameters {
                credential_type: "public-key".to_string(),
                alg: -7,
            }
        ],
        timeout: Some(10000),
        exclude_credentials: vec![],
        authenticator_selection: None,
        attestation: "direct".to_string(),
        extensions: None,
    };

    let json = serde_json::to_string_pretty(&response).unwrap();
    println!("{}", json);
}
