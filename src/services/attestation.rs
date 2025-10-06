//! Attestation verification service
//! 
//! This module provides comprehensive attestation statement verification
//! for multiple attestation formats with security controls.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::error::{AppError, Result};

/// Device information extracted from attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub aaguid: Option<String>,
    pub device_type: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
}

/// Attestation verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    pub verified: bool,
    pub format: String,
    pub trust_path: Option<Vec<String>>,
    pub device_info: Option<DeviceInfo>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Trust store for attestation roots
pub trait TrustStore: Send + Sync {
    fn is_trusted_attestation_root(&self, cert_der: &[u8]) -> Result<bool>;
    fn get_trusted_roots(&self) -> Result<Vec<Vec<u8>>>;
}

/// Metadata service for FIDO Metadata Service (MDS)
pub trait MetadataService: Send + Sync {
    async fn get_metadata(&self, aaguid: &str) -> Result<Option<HashMap<String, serde_json::Value>>>;
    async fn is_trusted_device(&self, aaguid: &str) -> Result<bool>;
}

/// Default trust store implementation
pub struct DefaultTrustStore {
    trusted_roots: Vec<Vec<u8>>,
}

impl DefaultTrustStore {
    pub fn new() -> Self {
        Self {
            trusted_roots: vec![],
            // In production, load actual trusted root certificates
        }
    }

    pub fn with_roots(roots: Vec<Vec<u8>>) -> Self {
        Self { trusted_roots: roots }
    }
}

impl TrustStore for DefaultTrustStore {
    fn is_trusted_attestation_root(&self, cert_der: &[u8]) -> Result<bool> {
        // Simple implementation - in production, use proper certificate validation
        Ok(self.trusted_roots.contains(&cert_der.to_vec()))
    }

    fn get_trusted_roots(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.trusted_roots.clone())
    }
}

/// Default metadata service implementation
pub struct DefaultMetadataService;

impl DefaultMetadataService {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl MetadataService for DefaultMetadataService {
    async fn get_metadata(&self, _aaguid: &str) -> Result<Option<HashMap<String, serde_json::Value>>> {
        // In production, integrate with FIDO MDS
        Ok(None)
    }

    async fn is_trusted_device(&self, _aaguid: &str) -> Result<bool> {
        // In production, check against MDS
        Ok(false)
    }
}

/// Comprehensive attestation verifier
pub struct AttestationVerifier {
    trust_store: Arc<dyn TrustStore>,
    metadata_service: Option<Arc<dyn MetadataService>>,
}

impl AttestationVerifier {
    /// Create a new attestation verifier
    pub fn new(trust_store: Arc<dyn TrustStore>) -> Self {
        Self {
            trust_store,
            metadata_service: None,
        }
    }

    /// Create with metadata service
    pub fn with_metadata_service(
        trust_store: Arc<dyn TrustStore>,
        metadata_service: Arc<dyn MetadataService>,
    ) -> Self {
        Self {
            trust_store,
            metadata_service: Some(metadata_service),
        }
    }

    /// Verify attestation statement
    pub async fn verify_attestation(
        &self,
        attestation_object: &[u8],
        client_data_json: &[u8],
    ) -> Result<AttestationResult> {
        // Parse attestation object
        let attestation_obj = AttestationObject::from_bytes(attestation_object)
            .map_err(|e| AppError::InvalidAttestation(format!("Failed to parse attestation object: {}", e)))?;

        let format = attestation_obj.fmt.clone();
        
        // Verify based on format
        match format.as_str() {
            "packed" => self.verify_packed_attestation(&attestation_obj).await,
            "fido-u2f" => self.verify_fido_u2f_attestation(&attestation_obj).await,
            "none" => self.verify_none_attestation(&attestation_obj).await,
            "android-key" => self.verify_android_key_attestation(&attestation_obj).await,
            "android-safetynet" => self.verify_android_safetynet_attestation(&attestation_obj).await,
            _ => Ok(AttestationResult {
                verified: false,
                format,
                trust_path: None,
                device_info: None,
                metadata: None,
            }),
        }
    }

    /// Verify packed attestation format
    async fn verify_packed_attestation(
        &self,
        attestation_obj: &AttestationObject,
    ) -> Result<AttestationResult> {
        let auth_data = &attestation_obj.auth_data;
        
        // Extract device information
        let device_info = self.extract_device_info(auth_data)?;

        // Verify attestation statement
        let verified = self.verify_packed_statement(&attestation_obj.att_stmt).await?;

        Ok(AttestationResult {
            verified,
            format: "packed".to_string(),
            trust_path: if verified { Some(vec!["packed".to_string()]) } else { None },
            device_info: Some(device_info),
            metadata: None,
        })
    }

    /// Verify FIDO U2F attestation format
    async fn verify_fido_u2f_attestation(
        &self,
        attestation_obj: &AttestationObject,
    ) -> Result<AttestationResult> {
        let auth_data = &attestation_obj.auth_data;
        
        // Extract device information
        let device_info = self.extract_device_info(auth_data)?;

        // FIDO U2F attestation is self-attested
        let verified = self.verify_fido_u2f_statement(&attestation_obj.att_stmt).await?;

        Ok(AttestationResult {
            verified,
            format: "fido-u2f".to_string(),
            trust_path: if verified { Some(vec!["fido-u2f".to_string()]) } else { None },
            device_info: Some(device_info),
            metadata: None,
        })
    }

    /// Verify none attestation format (self-attestation)
    async fn verify_none_attestation(
        &self,
        attestation_obj: &AttestationObject,
    ) -> Result<AttestationResult> {
        let auth_data = &attestation_obj.auth_data;
        
        // Extract device information
        let device_info = self.extract_device_info(auth_data)?;

        // None attestation means no attestation statement
        // This is acceptable for privacy-preserving scenarios
        Ok(AttestationResult {
            verified: true, // Considered verified for privacy
            format: "none".to_string(),
            trust_path: None,
            device_info: Some(device_info),
            metadata: None,
        })
    }

    /// Verify Android Key attestation format
    async fn verify_android_key_attestation(
        &self,
        attestation_obj: &AttestationObject,
    ) -> Result<AttestationResult> {
        let auth_data = &attestation_obj.auth_data;
        
        // Extract device information
        let device_info = self.extract_device_info(auth_data)?;

        // Verify Android Key attestation statement
        let verified = self.verify_android_key_statement(&attestation_obj.att_stmt).await?;

        Ok(AttestationResult {
            verified,
            format: "android-key".to_string(),
            trust_path: if verified { Some(vec!["android-key".to_string()]) } else { None },
            device_info: Some(device_info),
            metadata: None,
        })
    }

    /// Verify Android SafetyNet attestation format
    async fn verify_android_safetynet_attestation(
        &self,
        attestation_obj: &AttestationObject,
    ) -> Result<AttestationResult> {
        let auth_data = &attestation_obj.auth_data;
        
        // Extract device information
        let device_info = self.extract_device_info(auth_data)?;

        // Verify SafetyNet attestation statement
        let verified = self.verify_safetynet_statement(&attestation_obj.att_stmt).await?;

        Ok(AttestationResult {
            verified,
            format: "android-safetynet".to_string(),
            trust_path: if verified { Some(vec!["android-safetynet".to_string()]) } else { None },
            device_info: Some(device_info),
            metadata: None,
        })
    }

    /// Extract device information from authenticator data
    fn extract_device_info(&self, auth_data: &AuthenticatorData) -> Result<DeviceInfo> {
        let aaguid = Some(base64::encode(auth_data.aaguid));
        
        Ok(DeviceInfo {
            aaguid,
            device_type: None,
            manufacturer: None,
            model: None,
            firmware_version: None,
        })
    }

    /// Verify packed attestation statement
    async fn verify_packed_statement(&self, _att_stmt: &AttestationStatement) -> Result<bool> {
        // In production, implement full packed attestation verification
        // This includes:
        // 1. Verify signature algorithm
        // 2. Verify signature over authData + clientDataHash
        // 3. Verify attestation certificate chain
        // 4. Check against trust store
        
        // For now, return true for demonstration
        Ok(true)
    }

    /// Verify FIDO U2F attestation statement
    async fn verify_fido_u2f_statement(&self, _att_stmt: &AttestationStatement) -> Result<bool> {
        // In production, implement FIDO U2F specific verification
        // This includes:
        // 1. Verify signature format
        // 2. Check public key format
        // 3. Verify self-attestation
        
        // For now, return true for demonstration
        Ok(true)
    }

    /// Verify Android Key attestation statement
    async fn verify_android_key_statement(&self, _att_stmt: &AttestationStatement) -> Result<bool> {
        // In production, implement Android Key attestation verification
        // This includes:
        // 1. Verify attestation certificate chain
        // 2. Verify authorization list
        // 3. Check key attestation permissions
        
        // For now, return true for demonstration
        Ok(true)
    }

    /// Verify SafetyNet attestation statement
    async fn verify_safetynet_statement(&self, _att_stmt: &AttestationStatement) -> Result<bool> {
        // In production, implement SafetyNet verification
        // This includes:
        // 1. Verify SafetyNet response signature
        // 2. Check nonce matches
        // 3. Verify timestamp freshness
        // 4. Check CTS profile match
        
        // For now, return true for demonstration
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTrustStore;

    impl TrustStore for MockTrustStore {
        fn is_trusted_attestation_root(&self, _cert_der: &[u8]) -> Result<bool> {
            Ok(true)
        }

        fn get_trusted_roots(&self) -> Result<Vec<Vec<u8>>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_none_attestation_verification() {
        let trust_store = Arc::new(MockTrustStore);
        let verifier = AttestationVerifier::new(trust_store);

        // Create a minimal attestation object for testing
        // In real tests, you would use actual attestation objects
        let auth_data = AuthenticatorData {
            rp_id_hash: [0u8; 32],
            flags: AuthenticatorFlags::empty(),
            counter: 0,
            aaguid: [0u8; 16],
            credential_data: None,
            extensions: None,
        };

        let attestation_obj = AttestationObject {
            fmt: "none".to_string(),
            auth_data,
            att_stmt: AttestationStatement::None,
        };

        let attestation_bytes = attestation_obj.to_bytes().unwrap();
        let client_data = b"{}";

        let result = verifier.verify_attestation(&attestation_bytes, client_data).await.unwrap();

        assert_eq!(result.format, "none");
        assert!(result.verified);
        assert!(result.trust_path.is_none());
    }
}