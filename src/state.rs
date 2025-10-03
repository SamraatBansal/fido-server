//! Application state

use crate::config::Settings;
use crate::controllers::{AuthenticationController, MappingController, RegistrationController};
use crate::services::{MemoryStorage, Storage, WebAuthnService};
use std::sync::Arc;

/// Application state containing all services
#[derive(Clone)]
pub struct AppState {
    pub registration_controller: Arc<RegistrationController>,
    pub authentication_controller: Arc<AuthenticationController>,
    pub mapping_controller: Arc<MappingController>,
}

impl AppState {
    /// Create a new application state
    ///
    /// # Errors
    ///
    /// Returns an error if state initialization fails
    pub fn new(settings: &Settings) -> Result<Self, crate::error::AppError> {
        // Initialize WebAuthn service
        let webauthn_service = Arc::new(WebAuthnService::new(&settings.webauthn)?);

        // Initialize storage (using memory storage for now)
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());

        // Initialize controllers
        let registration_controller = Arc::new(RegistrationController::new(
            webauthn_service.clone(),
            storage.clone(),
        ));

        let authentication_controller = Arc::new(AuthenticationController::new(
            webauthn_service.clone(),
            storage.clone(),
        ));

        let mapping_controller = Arc::new(MappingController::new(storage));

        Ok(Self {
            registration_controller,
            authentication_controller,
            mapping_controller,
        })
    }
}
