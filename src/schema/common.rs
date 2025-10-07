//! Common schema definitions

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Common API response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the request was successful
    pub success: bool,
    /// Response data (if successful)
    pub data: Option<T>,
    /// Error message (if unsuccessful)
    pub error: Option<String>,
    /// Timestamp of the response
    pub timestamp: DateTime<Utc>,
}

impl<T> ApiResponse<T> {
    /// Create a successful response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
        }
    }

    /// Create an error response
    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            timestamp: Utc::now(),
        }
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Service version
    pub version: String,
    /// Current timestamp
    pub timestamp: DateTime<Utc>,
    /// Optional service details
    pub details: Option<ServiceDetails>,
}

/// Service details for health check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDetails {
    /// Database connection status
    pub database: String,
    /// Cache connection status (if applicable)
    pub cache: Option<String>,
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

/// Error response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Additional details (optional)
    pub details: Option<serde_json::Value>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl ErrorResponse {
    /// Create a new error response
    pub fn new(code: String, message: String) -> Self {
        Self {
            code,
            message,
            details: None,
            timestamp: Utc::now(),
        }
    }

    /// Create an error response with details
    pub fn with_details(code: String, message: String, details: serde_json::Value) -> Self {
        Self {
            code,
            message,
            details: Some(details),
            timestamp: Utc::now(),
        }
    }
}

/// Validation error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Field that failed validation
    pub field: String,
    /// Validation error message
    pub message: String,
    /// Invalid value (optional)
    pub value: Option<serde_json::Value>,
}

impl ValidationError {
    /// Create a new validation error
    pub fn new(field: String, message: String) -> Self {
        Self {
            field,
            message,
            value: None,
        }
    }

    /// Create a validation error with value
    pub fn with_value(field: String, message: String, value: serde_json::Value) -> Self {
        Self {
            field,
            message,
            value: Some(value),
        }
    }
}

/// Pagination parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    /// Page number (1-based)
    #[serde(default = "default_page")]
    pub page: u32,
    /// Items per page
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

fn default_page() -> u32 {
    1
}

fn default_page_size() -> u32 {
    20
}

/// Paginated response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// Items in the current page
    pub items: Vec<T>,
    /// Current page number
    pub page: u32,
    /// Items per page
    pub page_size: u32,
    /// Total number of items
    pub total: u64,
    /// Total number of pages
    pub total_pages: u32,
    /// Whether there's a next page
    pub has_next: bool,
    /// Whether there's a previous page
    pub has_previous: bool,
}

impl<T> PaginatedResponse<T> {
    /// Create a new paginated response
    pub fn new(
        items: Vec<T>,
        page: u32,
        page_size: u32,
        total: u64,
    ) -> Self {
        let total_pages = ((total as f64) / (page_size as f64)).ceil() as u32;
        let total_pages = if total_pages == 0 { 1 } else { total_pages };

        Self {
            items,
            page,
            page_size,
            total,
            total_pages,
            has_next: page < total_pages,
            has_previous: page > 1,
        }
    }
}

impl PaginationParams {
    /// Validate pagination parameters
    pub fn validate(&self) -> Result<(), String> {
        if self.page == 0 {
            return Err("Page number must be greater than 0".to_string());
        }

        if self.page_size == 0 {
            return Err("Page size must be greater than 0".to_string());
        }

        if self.page_size > 1000 {
            return Err("Page size cannot exceed 1000".to_string());
        }

        Ok(())
    }

    /// Calculate offset for database queries
    pub fn offset(&self) -> u32 {
        (self.page - 1) * self.page_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_success() {
        let response = ApiResponse::success("test data");
        assert!(response.success);
        assert_eq!(response.data, Some("test data"));
        assert!(response.error.is_none());
    }

    #[test]
    fn test_api_response_error() {
        let response = ApiResponse::<String>::error("test error".to_string());
        assert!(!response.success);
        assert!(response.data.is_none());
        assert_eq!(response.error, Some("test error".to_string()));
    }

    #[test]
    fn test_error_response() {
        let error = ErrorResponse::new(
            "VALIDATION_ERROR".to_string(),
            "Invalid input".to_string(),
        );
        assert_eq!(error.code, "VALIDATION_ERROR");
        assert_eq!(error.message, "Invalid input");
        assert!(error.details.is_none());
    }

    #[test]
    fn test_validation_error() {
        let error = ValidationError::new(
            "username".to_string(),
            "Username is required".to_string(),
        );
        assert_eq!(error.field, "username");
        assert_eq!(error.message, "Username is required");
        assert!(error.value.is_none());
    }

    #[test]
    fn test_pagination_params_validation() {
        let valid_params = PaginationParams {
            page: 1,
            page_size: 20,
        };
        assert!(valid_params.validate().is_ok());

        let invalid_page = PaginationParams {
            page: 0,
            page_size: 20,
        };
        assert!(invalid_page.validate().is_err());

        let invalid_page_size = PaginationParams {
            page: 1,
            page_size: 0,
        };
        assert!(invalid_page_size.validate().is_err());

        let too_large_page_size = PaginationParams {
            page: 1,
            page_size: 1001,
        };
        assert!(too_large_page_size.validate().is_err());
    }

    #[test]
    fn test_pagination_offset() {
        let params = PaginationParams {
            page: 3,
            page_size: 10,
        };
        assert_eq!(params.offset(), 20);
    }

    #[test]
    fn test_paginated_response() {
        let items = vec!["item1", "item2", "item3"];
        let response = PaginatedResponse::new(items.clone(), 1, 10, 25);

        assert_eq!(response.items, items);
        assert_eq!(response.page, 1);
        assert_eq!(response.page_size, 10);
        assert_eq!(response.total, 25);
        assert_eq!(response.total_pages, 3);
        assert!(response.has_next);
        assert!(!response.has_previous);
    }

    #[test]
    fn test_health_response() {
        let health = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            details: None,
        };
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, "1.0.0");
        assert!(health.details.is_none());
    }
}