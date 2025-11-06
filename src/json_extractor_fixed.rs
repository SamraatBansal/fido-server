use actix_web::{web, HttpRequest, HttpResponse, Result, FromRequest, dev::Payload, Error};
use futures::future::{Ready, ready, LocalBoxFuture};
use serde::de::DeserializeOwned;
use crate::api::ServerResponse;

/// Custom JSON extractor that returns FIDO-compliant error responses
pub struct JsonExtractor<T>(pub T);

impl<T> std::ops::Deref for JsonExtractor<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::DerefMut for JsonExtractor<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> FromRequest for JsonExtractor<T>
where
    T: DeserializeOwned + 'static,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let json_config = req
            .app_data::<web::JsonConfig>()
            .map(|c| c.clone())
            .unwrap_or_default();
        
        let req = req.clone();
        let mut payload = payload.take();
        
        Box::pin(async move {
            match web::Json::<T>::from_request(&req, &mut payload).await {
                Ok(json) => Ok(JsonExtractor(json.into_inner())),
                Err(err) => {
                    // Convert JSON parsing errors to FIDO-compliant error responses
                    let error_message = match err.as_response_error().status_code() {
                        actix_web::http::StatusCode::BAD_REQUEST => {
                            let err_str = format!("{}", err);
                            if err_str.contains("missing field") {
                                // Extract field name from error message
                                if let Some(start) = err_str.find("missing field `") {
                                    if let Some(end) = err_str[start + 15..].find("`") {
                                        let field_name = &err_str[start + 15..start + 15 + end];
                                        format!("Missing required field: {}", field_name)
                                    } else {
                                        "Missing required field".to_string()
                                    }
                                } else {
                                    "Missing required field".to_string()
                                }
                            } else if err_str.contains("invalid type") {
                                "Invalid field type".to_string()
                            } else {
                                "Invalid JSON format".to_string()
                            }
                        },
                        _ => "Invalid request format".to_string(),
                    };

                    let response = HttpResponse::BadRequest().json(ServerResponse::error(&error_message));
                    Err(actix_web::error::InternalError::from_response(err, response).into())
                }
            }
        })
    }
}