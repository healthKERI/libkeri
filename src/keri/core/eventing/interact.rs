use crate::cesr::number::Number;
use crate::cesr::Versionage;
use crate::keri::core::serdering::{SadValue, SerderKERI};
use crate::keri::{versify, Ilks, Kinds};
use indexmap::IndexMap;
use num_bigint::BigUint;
use std::error::Error;

/// Builder for creating KERI interaction events
pub struct InteractEventBuilder {
    pre: String,
    dig: String,
    sn: usize,
    data_list: Option<Vec<SadValue>>,
    data_map: Option<IndexMap<String, SadValue>>,
    version: String,
    kind: String,
}

impl InteractEventBuilder {
    /// Create a new InteractEventBuilder with required fields
    pub fn new(pre: String, dig: String) -> Self {
        Self {
            pre,
            dig,
            sn: 1,
            data_list: None,
            data_map: None,
            version: "KERI10JSON000000_".to_string(),
            kind: "JSON".to_string(),
        }
    }

    /// Set the sequence number
    pub fn with_sn(mut self, sn: usize) -> Self {
        self.sn = sn;
        self
    }

    /// Set the committed data (such as seals)
    pub fn with_data_list(mut self, data: Vec<SadValue>) -> Self {
        self.data_list = Some(data);
        self
    }

    /// Set the committed data (such as seals)
    pub fn with_data_map(mut self, data: IndexMap<String, SadValue>) -> Self {
        self.data_map = Some(data);
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

    /// Build the interaction event serder
    pub fn build(self) -> Result<SerderKERI, Box<dyn Error>> {
        // Validate sequence number
        let sner = Number::from_num(&BigUint::from(self.sn))?;
        if sner.num() < 1 {
            return Err(format!("Invalid sn = 0x{} for ixn.", sner.numh()).into());
        }

        if !Kinds::contains(&self.kind) {
            return Err(format!("Invalid kind = {} for ixn.", self.kind).into());
        }
        // Create versified string
        let vs = versify("KERI", &Versionage::from(self.version), &self.kind, 0)?;

        // Create the key event dict (ked)
        let mut ked = IndexMap::new();
        ked.insert("v".to_string(), SadValue::String(vs));
        ked.insert("t".to_string(), SadValue::String(Ilks::IXN.to_string()));
        ked.insert("d".to_string(), SadValue::String("".to_string()));
        ked.insert("i".to_string(), SadValue::String(self.pre));
        ked.insert("s".to_string(), SadValue::String(sner.numh()));
        ked.insert("p".to_string(), SadValue::String(self.dig));

        if self.data_list.is_some() {
            ked.insert("a".to_string(), SadValue::Array(self.data_list.unwrap()));
        } else if self.data_map.is_some() {
            ked.insert("a".to_string(), SadValue::Object(self.data_map.unwrap()));
        } else {
            ked.insert("a".to_string(), SadValue::Array(vec![]));
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
    fn test_interact_event_builder_basic() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Create previous event digest
        let dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-DpRXs".to_string();

        // Create a basic interaction
        let serder = InteractEventBuilder::new(pre.clone(), dig.clone()).build()?;

        // Verify the key event data
        let ked = serder.ked();

        // Check it's an interaction event
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::IXN);

        // Check basic fields
        assert_eq!(ked["i"].as_str().unwrap(), pre);
        assert_eq!(ked["p"].as_str().unwrap(), dig);
        assert_eq!(ked["s"].as_str().unwrap(), "1");

        // Check the attachments array is empty
        let attachments = ked["a"].as_array().unwrap();
        assert!(attachments.is_empty());

        Ok(())
    }

    #[test]
    fn test_interact_event_builder_with_data() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Create previous event digest
        let dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-DpRXs".to_string();

        // Create data attachments
        let mut data_map1 = IndexMap::new();
        data_map1.insert(
            "i".to_string(),
            SadValue::String("EbAwspDmOlHDUjGZ8m9JGQ4r7Knt5gu4KBNt0JSL2ZoI".to_string()),
        );
        data_map1.insert("s".to_string(), SadValue::String("3".to_string()));
        data_map1.insert(
            "d".to_string(),
            SadValue::String("EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-DpRXs".to_string()),
        );

        let mut data_map2 = IndexMap::new();
        data_map2.insert(
            "i".to_string(),
            SadValue::String("ELPNqidJsVsWPAPb5RkJKS7wEzOvE9ihzhTFcmF8vEHM".to_string()),
        );
        data_map2.insert("s".to_string(), SadValue::String("1".to_string()));
        data_map2.insert(
            "d".to_string(),
            SadValue::String("EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-DpRXs".to_string()),
        );

        let data = vec![
            SadValue::from(SadValue::Object(data_map1)),
            SadValue::from(SadValue::Object(data_map2)),
        ];

        // Create an interaction with data and sequence number 2
        let serder = InteractEventBuilder::new(pre.clone(), dig.clone())
            .with_sn(2)
            .with_data_list(data)
            .build()?;

        // Verify the key event data
        let ked = serder.ked();

        // Check it's an interaction event
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::IXN);

        // Check basic fields
        assert_eq!(ked["i"].as_str().unwrap(), pre);
        assert_eq!(ked["p"].as_str().unwrap(), dig);
        assert_eq!(ked["s"].as_str().unwrap(), "2");

        // Check the attachments
        let attachments = ked["a"].as_array().unwrap();
        assert_eq!(attachments.len(), 2);

        // Check first attachment
        let first_attachment = &attachments[0];
        match first_attachment {
            SadValue::Object(m) => {
                assert_eq!(
                    m["i"].as_str().unwrap(),
                    "EbAwspDmOlHDUjGZ8m9JGQ4r7Knt5gu4KBNt0JSL2ZoI"
                );
            }
            _ => {
                panic!("Expected attachment to be an object");
            }
        }

        // Check second attachment
        let second_attachment = &attachments[1];
        match second_attachment {
            SadValue::Object(m) => {
                assert_eq!(
                    m["i"].as_str().unwrap(),
                    "ELPNqidJsVsWPAPb5RkJKS7wEzOvE9ihzhTFcmF8vEHM"
                );
            }
            _ => {
                panic!("Expected attachment to be an object");
            }
        }

        Ok(())
    }

    #[test]
    fn test_interact_event_builder_invalid_sn() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Create previous event digest
        let dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-DpRXs".to_string();

        // Try to create an interaction with invalid sequence number
        let result = InteractEventBuilder::new(pre.clone(), dig.clone())
            .with_sn(0)
            .build();

        // Should fail with error about invalid sequence number
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid sn"));

        Ok(())
    }

    #[test]
    fn test_interact_event_builder_version_and_kind() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Create previous event digest
        let dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-DpRXs".to_string();

        // Create an interaction with custom version and kind
        let serder = InteractEventBuilder::new(pre.clone(), dig.clone())
            .with_version("KERI10".to_string())
            .with_kind("CBOR".to_string())
            .build()?;

        // Verify the key event data
        let ked = serder.ked();

        // Check version string starts with KERI10CBOR
        let kver = ked["v"].as_str().unwrap();
        assert!(ked["v"].as_str().unwrap().starts_with("KERI10CBOR"));

        Ok(())
    }

    #[test]
    fn test_interact_event_said_derivation() -> Result<(), Box<dyn Error>> {
        // Create identifier prefix
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH".to_string();

        // Create previous event digest
        let dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-DpRXs".to_string();

        // Create an interaction
        let serder = InteractEventBuilder::new(pre.clone(), dig.clone()).build()?;

        // Get the SAID (self-addressing identifier)
        let said = serder.said().expect("Failed to get SAID");

        // SAID should start with 'E' for BLAKE3_256 digest
        assert!(said.starts_with('E'));

        // Verify the SAID is in the 'd' field of the event
        assert_eq!(serder.ked()["d"].as_str().unwrap(), said);

        Ok(())
    }

    #[test]
    fn test_interactaction() -> Result<(), Box<dyn Error>> {
        let pre = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
        let pdig = "ECauhEzA4DJDXVDnNQiGQ0sKXa6sx_GgS8Ebdzm4E-kQ";

        let serder = InteractEventBuilder::new(pre.to_string(), pdig.to_string())
            .with_sn(2)
            .build()?;

        let ked = serder.ked();

        assert_eq!(ked["t"].as_str().unwrap(), Ilks::IXN.to_string());
        assert_eq!(ked["s"].as_str().unwrap(), "2");
        assert_eq!(ked["i"].as_str().unwrap(), pre);
        assert_eq!(ked["p"].as_str().unwrap(), pdig);

        let raw = b"{\"v\":\"KERI10JSON0000cb_\",\"t\":\"ixn\",\"d\":\"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J\",\"i\":\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\",\"s\":\"2\",\"p\":\"ECauhEzA4DJDXVDnNQiGQ0sKXa6sx_GgS8Ebdzm4E-kQ\",\"a\":[]}";
        assert_eq!(serder.raw(), raw);

        Ok(())
    }
}
