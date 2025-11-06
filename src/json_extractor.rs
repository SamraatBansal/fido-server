use actix_web::{dev::Payload, web, FromRequest, HttpRequest, Result as ActixResult};
use crate::error::{AppError, Result};
use crate::api::*;
use futures::future::{Ready, ready};
use serde::de::DeserializeOwned;
use std::fmt;

// Custom JSON extractor that provides better error messages for FIDO conformance
pub struct FidoJson<T>(pub T);

impl<T> std::ops::Deref for FidoJson<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for FidoJson<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> fmt::Display for FidoJson<T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl<T> FromRequest for FidoJson<T>
where
    T: DeserializeOwned + 'static,
{
    type Error = AppError;
    type Future = Ready<Result<Self>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let json_result = web::Json::<T>::from_request(req, payload);
        
        ready(match json_result.into_inner() {
            Ok(json) => Ok(FidoJson(json.into_inner())),
            Err(e) => {
                // Convert JSON errors to appropriate FIDO errors
                let error_msg = e.to_string();
                
                if error_msg.contains("missing field") {
                    if let Some(start) = error_msg.find("missing field `") {
                        let field_start = start + 15; // length of "missing field `"
                        if let Some(end) = error_msg[field_start..].find('`') {
                            let field_name = &error_msg[field_start..field_start + end];
                            return ready(Err(AppError::MissingField(field_name.to_string())));
                        }
                    }
                    ready(Err(AppError::InvalidRequest("Missing required field".to_string())))
                } else if error_msg.contains("invalid type") {
                    ready(Err(AppError::InvalidField("Invalid field type".to_string())))
                } else {
                    ready(Err(AppError::InvalidRequest("Invalid JSON format".to_string())))
                }
            }
        })
    }
}

// Type aliases for the specific request types to make handler signatures cleaner
pub type FidoRegistrationRequest = FidoJson<ServerPublicKeyCredentialCreationOptionsRequest>;
pub type FidoRegistrationCredential = FidoJson<ServerPublicKeyCredential>;
pub type FidoAuthenticationRequest = FidoJson<ServerPublicKeyCredentialGetOptionsRequest>;
pub type FidoAuthenticationCredential = FidoJson<ServerPublicKeyCredential>;