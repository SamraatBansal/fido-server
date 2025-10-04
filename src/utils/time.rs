//! Time utilities

use chrono::{DateTime, Duration, Utc};

/// Get current timestamp as RFC3339 string
pub fn current_timestamp() -> String {
    Utc::now().to_rfc3339()
}

/// Parse RFC3339 timestamp
pub fn parse_timestamp(timestamp: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(timestamp).map(|dt| dt.with_timezone(&Utc))
}

/// Check if a timestamp is expired
pub fn is_expired(timestamp: &DateTime<Utc>, duration_seconds: i64) -> bool {
    let expiry = *timestamp + Duration::seconds(duration_seconds);
    Utc::now() > expiry
}

/// Get timestamp for duration in the future
pub fn future_timestamp(duration_seconds: i64) -> DateTime<Utc> {
    Utc::now() + Duration::seconds(duration_seconds)
}

/// Get timestamp for duration in the past
pub fn past_timestamp(duration_seconds: i64) -> DateTime<Utc> {
    Utc::now() - Duration::seconds(duration_seconds)
}

/// Format duration in human-readable format
pub fn format_duration(duration_seconds: i64) -> String {
    let duration = Duration::seconds(duration_seconds);
    
    let days = duration.num_days();
    let hours = duration.num_hours() % 24;
    let minutes = duration.num_minutes() % 60;
    let seconds = duration.num_seconds() % 60;
    
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp() {
        let timestamp = current_timestamp();
        assert!(timestamp.len() > 0);
        
        // Should be parseable
        assert!(parse_timestamp(&timestamp).is_ok());
    }

    #[test]
    fn test_is_expired() {
        let now = Utc::now();
        let past = now - Duration::seconds(60);
        let future = now + Duration::seconds(60);
        
        assert!(is_expired(&past, 30)); // 60 seconds ago, 30 second expiry
        assert!(!is_expired(&past, 120)); // 60 seconds ago, 120 second expiry
        assert!(!is_expired(&future, 120)); // Future timestamp
    }

    #[test]
    fn test_future_timestamp() {
        let future = future_timestamp(60);
        let now = Utc::now();
        let diff = future.signed_duration_since(now);
        
        // Should be approximately 60 seconds in the future
        assert!(diff.num_seconds() >= 59);
        assert!(diff.num_seconds() <= 61);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(3661), "1h 1m 1s");
        assert_eq!(format_duration(61), "1m 1s");
        assert_eq!(format_duration(1), "1s");
        assert_eq!(format_duration(86461), "1d 1h 1m 1s");
    }
}