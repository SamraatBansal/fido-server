//! Time utilities

use chrono::{DateTime, Utc, Duration};

/// Get current timestamp
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Add duration to timestamp
pub fn add_duration(timestamp: DateTime<Utc>, duration: Duration) -> DateTime<Utc> {
    timestamp + duration
}

/// Check if timestamp is expired
pub fn is_expired(timestamp: DateTime<Utc>) -> bool {
    timestamp < Utc::now()
}

/// Format timestamp for display
pub fn format_timestamp(timestamp: DateTime<Utc>) -> String {
    timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Parse timestamp from string
pub fn parse_timestamp(timestamp_str: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(timestamp_str)
        .map(|dt| dt.with_timezone(&Utc))
}