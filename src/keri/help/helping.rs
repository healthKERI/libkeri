/// Returns time now in RFC-3339 profile of ISO 8601 format.
/// Format: YYYY-MM-DDTHH:MM:SS.ffffff+HH:MM
/// Equivalent to Python's datetime.now(timezone.utc).isoformat(timespec='microseconds')
pub fn nowiso8601() -> String {
    use chrono::{SecondsFormat, Utc};

    // Get current UTC time and format with microsecond precision
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}
