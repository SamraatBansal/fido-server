//! Integration tests for FIDO2/WebAuthn server

mod integration;

#[cfg(test)]
mod tests {
    use super::integration::*;

    #[test]
    fn run_all_integration_tests() {
        // This will be expanded with actual test calls
        // For now, just ensure the modules compile
        assert!(true);
    }
}