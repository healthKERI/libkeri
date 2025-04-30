use crate::cesr::number::Number;
use crate::cesr::Versionage;
use crate::keri::core::serdering::{SadValue, SerderKERI};
use crate::keri::{versify, Ilks, Kinds};
use indexmap::IndexMap;
use num_bigint::BigUint;
use std::error::Error;

/// Builder for creating KERI receipt events
pub struct ReceiptEventBuilder {
    pre: String,
    sn: usize,
    said: String,
    version: String,
    kind: String,
}

impl ReceiptEventBuilder {
    /// Create a new ReceiptEventBuilder with required fields
    ///
    /// Parameters:
    ///   pre - qb64 string of prefix of event being receipted
    ///   sn - sequence number of event being receipted
    ///   said - qb64 of said of event being receipted
    pub fn new(pre: String, sn: usize, said: String) -> Self {
        Self {
            pre,
            sn,
            said,
            version: "KERI10JSON000000_".to_string(),
            kind: "JSON".to_string(),
        }
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

    /// Build the receipt event serder
    pub fn build(self) -> Result<SerderKERI, Box<dyn Error>> {
        // Validate sequence number
        let sner = Number::from_num(&BigUint::from(self.sn))?;

        if !Kinds::contains(&self.kind) {
            return Err(format!("Invalid kind = {} for rect.", self.kind).into());
        }

        // Create versified string
        let vs = versify("KERI", &Versionage::from(self.version), &self.kind, 0)?;

        // Create the key event dict (ked)
        let mut ked = IndexMap::new();
        ked.insert("v".to_string(), SadValue::String(vs));
        ked.insert("t".to_string(), SadValue::String(Ilks::RCT.to_string()));
        ked.insert("d".to_string(), SadValue::String(self.said));
        ked.insert("i".to_string(), SadValue::String(self.pre));
        ked.insert("s".to_string(), SadValue::String(sner.numh()));

        // Create the serder
        let serder = SerderKERI::from_sad_and_saids(&ked, None)?;
        Ok(serder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::core::serdering::{Rawifiable, Serder};
    use std::error::Error;

    #[test]
    fn test_receipt_event_builder_basic() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Sequence number
        let sn = 3;

        // SAID of event being receipted
        let said = "EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J".to_string();

        // Create a basic receipt
        let serder = ReceiptEventBuilder::new(pre.clone(), sn, said.clone()).build()?;

        // Verify the key event data
        let ked = serder.ked();

        // Check it's a receipt event
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::RCT);

        // Check basic fields
        assert_eq!(ked["i"].as_str().unwrap(), pre);
        assert_eq!(ked["s"].as_str().unwrap(), "3");
        assert_eq!(ked["d"].as_str().unwrap(), said);

        Ok(())
    }

    #[test]
    fn test_receipt_event_custom_version_kind() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Sequence number
        let sn = 5;

        // SAID of event being receipted
        let said = "EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J".to_string();

        // Create a receipt with custom version and kind
        let serder = ReceiptEventBuilder::new(pre.clone(), sn, said.clone())
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
    fn test_receipt_event_validation() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Invalid kind
        let sn = 1;
        let said = "EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J".to_string();

        let result = ReceiptEventBuilder::new(pre.clone(), sn, said.clone())
            .with_kind("INVALID".to_string())
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid kind"));

        Ok(())
    }

    #[test]
    fn test_receipt_event_serialization() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Sequence number
        let sn = 4;

        // SAID of event being receipted
        let said = "EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J".to_string();

        // Create a receipt
        let serder = ReceiptEventBuilder::new(pre.clone(), sn, said.clone()).build()?;

        // Check raw serialization
        let raw = serder.raw();

        // Verify we can deserialize it back
        let deserialized = SerderKERI::from_raw(&raw, None)?;

        // Check that fields match
        assert_eq!(deserialized.ked()["t"].as_str().unwrap(), Ilks::RCT);
        assert_eq!(deserialized.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(deserialized.ked()["s"].as_str().unwrap(), "4");
        assert_eq!(deserialized.ked()["d"].as_str().unwrap(), said);

        Ok(())
    }

    #[test]
    fn test_receipt_event_specific_structure() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Sequence number
        let sn = 2;

        // SAID of event being receipted
        let said = "EGr9qTLviRyuWnmLCXkMJGqUVGczfKpELk7aBfKuwMnK".to_string();

        // Create a receipt
        let serder = ReceiptEventBuilder::new(pre.clone(), sn, said.clone()).build()?;

        // Verify structure (especially compared to interaction events)
        let ked = serder.ked();

        // Receipt events have:
        // 1. No 'p' field (previous event digest)
        assert!(ked.get("p").is_none());

        // 2. No 'a' field (attachments)
        assert!(ked.get("a").is_none());

        // 3. The 'd' field contains the receipted event's SAID
        assert_eq!(ked["d"].as_str().unwrap(), said);

        // 4. The 't' field is "rct"
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::RCT);

        Ok(())
    }

    #[test]
    fn test_receipt() -> Result<(), Box<dyn Error>> {
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
        let said = "EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J";

        let serder = ReceiptEventBuilder::new(pre.to_string(), 0, said.to_string()).build()?;

        let ked = serder.ked();
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::RCT);
        assert_eq!(ked["i"].as_str().unwrap(), pre);
        assert_eq!(ked["s"].as_str().unwrap(), "0");

        let raw = b"{\"v\":\"KERI10JSON000091_\",\"t\":\"rct\",\"d\":\"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J\",\"i\":\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\",\"s\":\"0\"}";
        assert_eq!(raw, serder.raw());

        let serder = ReceiptEventBuilder::new(pre.to_string(), 2, said.to_string()).build()?;

        let ked = serder.ked();
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::RCT);
        assert_eq!(ked["i"].as_str().unwrap(), pre);
        assert_eq!(ked["s"].as_str().unwrap(), "2");

        let raw = b"{\"v\":\"KERI10JSON000091_\",\"t\":\"rct\",\"d\":\"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J\",\"i\":\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\",\"s\":\"2\"}";
        assert_eq!(raw, serder.raw());

        Ok(())
    }
}
