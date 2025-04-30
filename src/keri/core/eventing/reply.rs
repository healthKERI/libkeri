use crate::cesr::Versionage;
use crate::keri::core::serdering::{SadValue, SerderKERI};
use crate::keri::{versify, Ilks, Kinds};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use std::error::Error;

/// Builder for creating KERI reply events
pub struct ReplyEventBuilder {
    route: String,
    data: Option<IndexMap<String, SadValue>>,
    stamp: Option<String>,
    version: String,
    kind: String,
}

impl ReplyEventBuilder {
    /// Create a new ReplyEventBuilder
    pub fn new() -> Self {
        Self {
            route: String::new(),
            data: None,
            stamp: None,
            version: "KERI10JSON000000_".to_string(),
            kind: "JSON".to_string(),
        }
    }

    /// Set the route
    ///
    /// Parameters:
    ///   route - namespaced path, '/' delimited, that indicates data flow
    ///           handler (behavior) to process the reply
    pub fn with_route(mut self, route: String) -> Self {
        self.route = route;
        self
    }

    /// Set the data attributes
    ///
    /// Parameters:
    ///   data - attribute section of reply
    pub fn with_data(mut self, data: IndexMap<String, SadValue>) -> Self {
        self.data = Some(data);
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

    /// Build the reply event serder
    pub fn build(self) -> Result<SerderKERI, Box<dyn Error>> {
        if !Kinds::contains(&self.kind) {
            return Err(format!("Invalid kind = {} for rpy.", self.kind).into());
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
        ked.insert("t".to_string(), SadValue::String(Ilks::RPY.to_string()));
        ked.insert("d".to_string(), SadValue::String("".to_string()));
        ked.insert("dt".to_string(), SadValue::String(timestamp));
        ked.insert("r".to_string(), SadValue::String(self.route));

        if let Some(data) = self.data {
            ked.insert("a".to_string(), SadValue::Object(data));
        } else {
            // If no data is provided, use an empty object
            ked.insert("a".to_string(), SadValue::Object(IndexMap::new()));
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
    fn test_reply_event_builder_basic() -> Result<(), Box<dyn Error>> {
        // Create a basic reply
        let serder = ReplyEventBuilder::new()
            .with_route("logs/processor".to_string())
            .build()?;

        // Verify the key event data
        let ked = serder.ked();

        // Check it's a reply event
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::RPY);

        // Check basic fields
        assert_eq!(ked["r"].as_str().unwrap(), "logs/processor");

        // Check dt field exists (timestamp)
        assert!(ked.get("dt").is_some());
        let a = ked["a"].clone();
        let raw_str = std::str::from_utf8(serder.raw())?;

        // Check a field is an empty object
        match &ked["a"] {
            SadValue::Object(obj) => assert!(obj.is_empty()),
            _ => panic!("Expected a field to be an object"),
        }

        Ok(())
    }

    #[test]
    fn test_reply_event_with_data() -> Result<(), Box<dyn Error>> {
        // Create data
        let mut data = IndexMap::new();
        data.insert(
            "d".to_string(),
            SadValue::String("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string()),
        );
        data.insert(
            "i".to_string(),
            SadValue::String("EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM".to_string()),
        );
        data.insert(
            "name".to_string(),
            SadValue::String("John Jones".to_string()),
        );
        data.insert("role".to_string(), SadValue::String("Founder".to_string()));

        // Set a specific timestamp
        let timestamp = "2020-08-22T17:50:12.988921+00:00".to_string();

        // Create a reply with data
        let serder = ReplyEventBuilder::new()
            .with_route("logs/processor".to_string())
            .with_data(data)
            .with_stamp(timestamp.clone())
            .build()?;

        // Verify the key event data
        let ked = serder.ked();

        // Check timestamp
        assert_eq!(ked["dt"].as_str().unwrap(), timestamp);

        // Check data attributes
        let a = match &ked["a"] {
            SadValue::Object(obj) => obj,
            _ => panic!("Expected a field to be an object"),
        };

        assert_eq!(
            a["d"].as_str().unwrap(),
            "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"
        );
        assert_eq!(
            a["i"].as_str().unwrap(),
            "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM"
        );
        assert_eq!(a["name"].as_str().unwrap(), "John Jones");
        assert_eq!(a["role"].as_str().unwrap(), "Founder");

        Ok(())
    }

    #[test]
    fn test_reply_event_custom_version_kind() -> Result<(), Box<dyn Error>> {
        // Create a reply with custom version and kind
        let serder = ReplyEventBuilder::new()
            .with_route("logs/processor".to_string())
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
    fn test_reply_event_invalid_kind() -> Result<(), Box<dyn Error>> {
        // Try to create a reply with invalid kind
        let result = ReplyEventBuilder::new()
            .with_kind("INVALID".to_string())
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid kind"));

        Ok(())
    }

    #[test]
    fn test_reply_event_said_derivation() -> Result<(), Box<dyn Error>> {
        // Create a reply
        let serder = ReplyEventBuilder::new()
            .with_route("logs/processor".to_string())
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
    fn test_reply_matches_python_example() -> Result<(), Box<dyn Error>> {
        // Recreate the Python example from the docstring
        let mut data = IndexMap::new();
        data.insert(
            "d".to_string(),
            SadValue::String("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string()),
        );
        data.insert(
            "i".to_string(),
            SadValue::String("EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM".to_string()),
        );
        data.insert(
            "name".to_string(),
            SadValue::String("John Jones".to_string()),
        );
        data.insert("role".to_string(), SadValue::String("Founder".to_string()));

        let serder = ReplyEventBuilder::new()
            .with_route("logs/processor".to_string())
            .with_data(data)
            .with_stamp("2020-08-22T17:50:12.988921+00:00".to_string())
            .build()?;

        let ked = serder.ked();

        // Check expected fields from Python example
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::RPY);
        assert_eq!(
            ked["dt"].as_str().unwrap(),
            "2020-08-22T17:50:12.988921+00:00"
        );
        assert_eq!(ked["r"].as_str().unwrap(), "logs/processor");

        let a = match &ked["a"] {
            SadValue::Object(obj) => obj,
            _ => panic!("Expected a field to be an object"),
        };

        assert_eq!(
            a["d"].as_str().unwrap(),
            "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"
        );
        assert_eq!(
            a["i"].as_str().unwrap(),
            "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM"
        );
        assert_eq!(a["name"].as_str().unwrap(), "John Jones");
        assert_eq!(a["role"].as_str().unwrap(), "Founder");

        Ok(())
    }

    #[test]
    fn test_reply_event_builder_serialization() -> Result<(), Box<dyn Error>> {
        // Create data
        let mut data = IndexMap::new();
        data.insert(
            "d".to_string(),
            SadValue::String("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string()),
        );
        data.insert(
            "i".to_string(),
            SadValue::String("EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM".to_string()),
        );
        data.insert(
            "name".to_string(),
            SadValue::String("John Jones".to_string()),
        );
        data.insert("role".to_string(), SadValue::String("Founder".to_string()));

        // Create a timestamp matching the Python example
        let timestamp = "2020-08-22T17:50:12.988921+00:00".to_string();

        // Create the reply event
        let serder = ReplyEventBuilder::new()
            .with_route("logs/processor".to_string())
            .with_data(data)
            .with_stamp(timestamp)
            .build()?;

        // Get raw serialized bytes
        let raw = serder.raw();

        // The SAID will be dynamically generated, so we can't check the exact raw bytes
        // but we can check that it starts and ends correctly
        let raw_str = std::str::from_utf8(&raw)?;

        // Check that it starts with the correct version and type
        assert!(raw_str.starts_with("{\"v\":\"KERI10JSON"));
        assert!(raw_str.contains("\"t\":\"rpy\""));

        // Check that it contains our data
        assert!(raw_str.contains("\"John Jones\""));
        assert!(raw_str.contains("\"Founder\""));

        // Should have a field for route
        assert!(raw_str.contains("\"r\":\"logs/processor\""));

        Ok(())
    }

    #[test]
    fn test_reply_with_empty_route() -> Result<(), Box<dyn Error>> {
        // Create a reply with empty route (should be valid)
        let serder = ReplyEventBuilder::new().build()?;

        let ked = serder.ked();

        // Check it's a reply event
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::RPY);

        // Check route is empty string
        assert_eq!(ked["r"].as_str().unwrap(), "");

        Ok(())
    }

    #[test]
    fn test_reply_event_for_role_add() -> Result<(), Box<dyn Error>> {
        // Define the route
        let route = "/end/role/add".to_string();

        // Create data
        let mut data = IndexMap::new();
        data.insert(
            "cid".to_string(),
            SadValue::String("BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y".to_string()),
        );
        data.insert("role".to_string(), SadValue::String("watcher".to_string()));
        data.insert(
            "eid".to_string(),
            SadValue::String("BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr".to_string()),
        );

        // Create a timestamp matching the Python test
        let timestamp = "2021-01-01T00:00:00.000000+00:00".to_string();

        // Create the reply event
        let serder = ReplyEventBuilder::new()
            .with_route(route)
            .with_data(data)
            .with_stamp(timestamp)
            .build()?;

        // Verify the timestamp
        let ked = serder.ked();
        assert_eq!(
            ked["dt"].as_str().unwrap(),
            "2021-01-01T00:00:00.000000+00:00"
        );

        // Get the raw serialized output
        let raw = serder.raw();

        // Expected raw output from Python test
        let expected = b"{\"v\":\"KERI10JSON000113_\",\"t\":\"rpy\",\"d\":\"EFlkeg-NociMRXHSGBSqARxV5y7zuT5z-ZpLZAkcoMkk\",\"dt\":\"2021-01-01T00:00:00.000000+00:00\",\"r\":\"/end/role/add\",\"a\":{\"cid\":\"BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y\",\"role\":\"watcher\",\"eid\":\"BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr\"}}";

        // Compare raw output with expected
        assert_eq!(raw, expected);

        // Get and check the SAID
        let said = serder.said().expect("Failed to get SAID");
        assert_eq!(said, "EFlkeg-NociMRXHSGBSqARxV5y7zuT5z-ZpLZAkcoMkk");

        // Verify the data field contains the expected values
        let a = match &ked["a"] {
            SadValue::Object(obj) => obj,
            _ => panic!("Expected a field to be an object"),
        };

        assert_eq!(
            a["cid"].as_str().unwrap(),
            "BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y"
        );
        assert_eq!(a["role"].as_str().unwrap(), "watcher");
        assert_eq!(
            a["eid"].as_str().unwrap(),
            "BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr"
        );

        Ok(())
    }
}
