//! Unit tests for individual components

#[cfg(test)]
mod tests {
    use webauthn_rp_server::dto::*;
    
    #[test]
    fn test_dto_serialization() {
        // Basic test to ensure DTOs can be serialized/deserialized
        let response = ServerResponse::ok();
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ServerResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.status, deserialized.status);
    }
}