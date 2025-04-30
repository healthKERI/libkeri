use crate::cesr::Versionage;
use crate::keri::core::serdering::{SadValue, SerderKERI};
use crate::keri::{versify, Ilks, Kinds};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use std::error::Error;

/// Builder for creating KERI query events
pub struct QueryEventBuilder {
    route: String,
    reply_route: String,
    query: Option<IndexMap<String, SadValue>>,
    stamp: Option<String>,
    version: String,
    kind: String,
}

impl QueryEventBuilder {
    /// Create a new QueryEventBuilder
    pub fn new() -> Self {
        Self {
            route: String::new(),
            reply_route: String::new(),
            query: None,
            stamp: None,
            version: "KERI10JSON000000_".to_string(),
            kind: "JSON".to_string(),
        }
    }

    /// Set the route
    ///
    /// Parameters:
    ///   route - namespaced path, '/' delimited, that indicates data flow
    ///           handler (behavior) to process the query
    pub fn with_route(mut self, route: String) -> Self {
        self.route = route;
        self
    }

    /// Set the reply route
    ///
    /// Parameters:
    ///   reply_route - namespaced path, '/' delimited, that indicates data flow
    ///                 handler (behavior) to process reply message to query if any
    pub fn with_reply_route(mut self, reply_route: String) -> Self {
        self.reply_route = reply_route;
        self
    }

    /// Set the query data parameters
    pub fn with_query(mut self, query: IndexMap<String, SadValue>) -> Self {
        self.query = Some(query);
        self
    }

    /// Set the timestamp
    ///
    /// Parameters:
    ///   stamp - date-time-stamp RFC-3339 profile of ISO-8601 datetime of creation of message
    pub fn with_stamp(mut self, stamp: String) -> Self {
        self.stamp = Some(stamp);
        self
    }

    /// Set the version string
    pub fn with_version(mut self, version: String) -> Self {
        self.version = version;
        self
    }

    /// Set the serialization kind
    pub fn with_kind(mut self, kind: String) -> Self {
        self.kind = kind;
        self
    }

    /// Build the query event serder
    pub fn build(self) -> Result<SerderKERI, Box<dyn Error>> {
        if !Kinds::contains(&self.kind) {
            return Err(format!("Invalid kind = {} for qry.", self.kind).into());
        }

        // Create versified string
        let vs = versify("KERI", &Versionage::from(self.version), &self.kind, 0)?;

        // Generate timestamp if not provided
        let timestamp = match self.stamp {
            Some(ts) => ts,
            None => {
                let now: DateTime<Utc> = Utc::now();
                now.to_rfc3339()
            }
        };

        // Create the key event dict (ked)
        let mut ked = IndexMap::new();
        ked.insert("v".to_string(), SadValue::String(vs));
        ked.insert("t".to_string(), SadValue::String(Ilks::QRY.to_string()));
        ked.insert("d".to_string(), SadValue::String("".to_string()));
        ked.insert("dt".to_string(), SadValue::String(timestamp));
        ked.insert("r".to_string(), SadValue::String(self.route));
        ked.insert("rr".to_string(), SadValue::String(self.reply_route));

        if let Some(query_data) = self.query {
            ked.insert("q".to_string(), SadValue::Object(query_data));
        } else {
            // If no query data is provided, use an empty object
            ked.insert("q".to_string(), SadValue::Object(IndexMap::new()));
        }

        // Create the serder
        let serder = SerderKERI::from_sad_and_saids(&ked, None)?;
        Ok(serder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::core::serdering::Serder;
    use std::error::Error;

    #[test]
    fn test_query_event_builder_basic() -> Result<(), Box<dyn Error>> {
        // Create a basic query
        let serder = QueryEventBuilder::new()
            .with_route("logs".to_string())
            .with_reply_route("log/processor".to_string())
            .build()?;

        // Verify the key event data
        let ked = serder.ked();

        // Check it's a query event
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::QRY);

        // Check basic fields
        assert_eq!(ked["r"].as_str().unwrap(), "logs");
        assert_eq!(ked["rr"].as_str().unwrap(), "log/processor");

        // Check dt field exists (timestamp)
        assert!(ked.get("dt").is_some());

        // Check q field is an empty object
        match &ked["q"] {
            SadValue::Object(obj) => assert!(obj.is_empty()),
            _ => panic!("Expected q field to be an object"),
        }

        Ok(())
    }

    #[test]
    fn test_query_event_with_query_data() -> Result<(), Box<dyn Error>> {
        // Create query data
        let mut query_data = IndexMap::new();
        query_data.insert(
            "i".to_string(),
            SadValue::String("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string()),
        );
        query_data.insert("sn".to_string(), SadValue::String("5".to_string()));
        query_data.insert(
            "dt".to_string(),
            SadValue::String("2020-08-01T12:20:05.123456+00:00".to_string()),
        );

        // Set a specific timestamp
        let timestamp = "2020-08-22T17:50:12.988921+00:00".to_string();

        // Create a query with data
        let serder = QueryEventBuilder::new()
            .with_route("logs".to_string())
            .with_reply_route("log/processor".to_string())
            .with_query(query_data)
            .with_stamp(timestamp.clone())
            .build()?;

        // Verify the key event data
        let ked = serder.ked();

        // Check timestamp
        assert_eq!(ked["dt"].as_str().unwrap(), timestamp);

        // Check query data
        let q = match &ked["q"] {
            SadValue::Object(obj) => obj,
            _ => panic!("Expected q field to be an object"),
        };

        assert_eq!(
            q["i"].as_str().unwrap(),
            "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"
        );
        assert_eq!(q["sn"].as_str().unwrap(), "5");
        assert_eq!(
            q["dt"].as_str().unwrap(),
            "2020-08-01T12:20:05.123456+00:00"
        );

        Ok(())
    }

    #[test]
    fn test_query_event_custom_version_kind() -> Result<(), Box<dyn Error>> {
        // Create a query with custom version and kind
        let serder = QueryEventBuilder::new()
            .with_route("logs".to_string())
            .with_version("KERI10".to_string())
            .with_kind("CBOR".to_string())
            .build()?;

        // Verify the version string
        let ked = serder.ked();
        let version = ked["v"].as_str().unwrap();
        assert!(version.starts_with("KERI10CBOR"));

        Ok(())
    }

    #[test]
    fn test_query_event_invalid_kind() -> Result<(), Box<dyn Error>> {
        // Try to create a query with invalid kind
        let result = QueryEventBuilder::new()
            .with_kind("INVALID".to_string())
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid kind"));

        Ok(())
    }

    #[test]
    fn test_query_event_said_derivation() -> Result<(), Box<dyn Error>> {
        // Create a query
        let serder = QueryEventBuilder::new()
            .with_route("logs".to_string())
            .build()?;

        // Get the SAID (self-addressing identifier)
        let said = serder.said().expect("Failed to get SAID");

        // SAID should start with 'E' for BLAKE3_256 digest
        assert!(said.starts_with('E'));

        // Verify the SAID is in the 'd' field of the event
        assert_eq!(serder.ked()["d"].as_str().unwrap(), said);

        Ok(())
    }

    #[test]
    fn test_query_matches_python_example() -> Result<(), Box<dyn Error>> {
        // Recreate the Python example from the docstring
        let mut query_data = IndexMap::new();
        query_data.insert(
            "i".to_string(),
            SadValue::String("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string()),
        );
        query_data.insert("sn".to_string(), SadValue::String("5".to_string()));
        query_data.insert(
            "dt".to_string(),
            SadValue::String("2020-08-01T12:20:05.123456+00:00".to_string()),
        );

        let serder = QueryEventBuilder::new()
            .with_route("logs".to_string())
            .with_reply_route("log/processor".to_string())
            .with_query(query_data)
            .with_stamp("2020-08-22T17:50:12.988921+00:00".to_string())
            .build()?;

        let ked = serder.ked();

        // Check expected fields from Python example
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::QRY);
        assert_eq!(
            ked["dt"].as_str().unwrap(),
            "2020-08-22T17:50:12.988921+00:00"
        );
        assert_eq!(ked["r"].as_str().unwrap(), "logs");
        assert_eq!(ked["rr"].as_str().unwrap(), "log/processor");

        let q = match &ked["q"] {
            SadValue::Object(obj) => obj,
            _ => panic!("Expected q field to be an object"),
        };

        assert_eq!(
            q["i"].as_str().unwrap(),
            "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"
        );
        assert_eq!(q["sn"].as_str().unwrap(), "5");
        assert_eq!(
            q["dt"].as_str().unwrap(),
            "2020-08-01T12:20:05.123456+00:00"
        );

        Ok(())
    }

    #[test]
    fn test_query_event_builder_serialization() -> Result<(), Box<dyn Error>> {
        // Create query data
        let mut query_data = IndexMap::new();
        query_data.insert(
            "i".to_string(),
            SadValue::String("DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI".to_string()),
        );

        // Create a timestamp matching the Python test
        let timestamp = "2021-01-01T00:00:00.000000+00:00".to_string();

        // Create the query event
        let serder = QueryEventBuilder::new()
            .with_route("log".to_string())
            .with_query(query_data)
            .with_stamp(timestamp)
            .build()?;

        // Get raw serialized bytes
        let raw = serder.raw();

        // Expected bytes from Python test
        let expected = b"{\"v\":\"KERI10JSON0000c9_\",\"t\":\"qry\",\"d\":\"EGN68_seecuzXQO15FFGJLVwZCBCPYW-hy29fjWWPQbp\",\"dt\":\"2021-01-01T00:00:00.000000+00:00\",\"r\":\"log\",\"rr\":\"\",\"q\":{\"i\":\"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI\"}}";

        // Compare raw bytes with expected
        assert_eq!(raw, expected);

        Ok(())
    }
}
