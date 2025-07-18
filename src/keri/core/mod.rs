pub mod errors;
pub mod eventing;
pub mod filing;
pub mod parsing;
pub mod routing;
pub mod serdering;

use regex::bytes::Regex;

use once_cell::sync::Lazy;

use crate::cesr::Versionage;
use crate::errors::MatterError;
use crate::keri::core::serdering::{SadValue, Sadder};
use crate::keri::{deversify, versify, KERIError, Kinds};

/// Regex to find version string in raw serialization
static REVER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?P<proto1>[A-Z]{4})(?P<major1>[0-9a-f])(?P<minor1>[0-9a-f])(?P<kind1>[A-Z]{4})(?P<size1>[0-9a-f]{6})_").expect("Invalid regex pattern")
});

/// Compute serialized size of ked and update version field
///
/// Returns tuple of (raw, proto, kind, ked, version) where:
///   * raw (Vec<u8>): serialized event as bytes of kind
///   * proto (String): protocol type as value of Protocolage
///   * kind (String): serialization kind as value of Serialage
///   * ked (Sadder): key event dict (with updated version string)
///   * version (Versionage): instance
///
/// # Parameters
///   * ked (Sadder): key event dict
///   * kind_opt (Option<Kinds>): value of Kinds is serialization type
///       if not provided use that given in ked.v
///   * version_opt (Option<Versionage>): supported protocol version for message
///
/// # Errors
///   * MatterError: if version string is missing, unsupported version,
///     invalid kind, or malformed version string
pub fn sizeify(
    ked: &Sadder,
    kind_opt: Option<&Kinds>,
    version_opt: Option<Versionage>,
) -> Result<(Vec<u8>, String, String, Sadder, Versionage), KERIError> {
    // Get the default version if not provided
    let version = version_opt.unwrap_or_else(|| Versionage { major: 1, minor: 0 });

    // Check if 'v' field exists in ked
    if !ked.contains_key("v") {
        return Err(MatterError::ValueError(
            "Missing version string in key event dict".to_string(),
        )
        .into());
    }

    // Extract protocol, version, kind, and size from version string
    let smellage = deversify(ked["v"].as_str().unwrap())?;
    let (proto, vrsn, knd) = (smellage.proto, smellage.vrsn, smellage.kind);

    // Verify version is supported
    if vrsn != version {
        return Err(KERIError::ValueError(format!(
            "Unsupported version = {}.{}",
            vrsn.major, vrsn.minor
        )));
    }

    // Use provided kind or extracted kind
    let kind = match kind_opt {
        Some(k) => k,
        None => &Kinds::from(&knd)?,
    };

    // Create a copy of ked to update the version string
    let mut ked_mut = ked.clone();

    // Serialize ked to get raw bytes
    let raw = SadValue::dumps(&ked_mut, &kind)?;
    let size = raw.len();

    let match_opt = REVER.find(&raw);

    let (fore, back) = match match_opt {
        Some(m) if m.start() <= 12 => (m.start(), m.end()),
        _ => {
            return Err(KERIError::ValueError(format!(
                "Invalid version string in raw = {:?}",
                raw
            )))
        }
    };

    // Update version string with latest kind and size
    let vs = versify("KERI", &vrsn, &kind.to_string(), size as u64)?;

    // Find version string in raw
    let fore = &raw[..fore];
    let back = &raw[back..];
    // Find version string in raw
    // Replace old version string in raw with new one
    let mut new_raw = Vec::with_capacity(fore.len() + vs.as_bytes().len() + back.len());
    new_raw.extend_from_slice(fore);
    new_raw.extend_from_slice(vs.as_bytes());
    new_raw.extend_from_slice(back);

    if size != new_raw.len() {
        return Err(KERIError::ValueError(format!(
            "Malformed version string size = {}",
            vs
        )));
    }

    // Update ked with new version string
    ked_mut.insert("v".to_string(), SadValue::String(vs));

    Ok((new_raw, proto, kind.to_string(), ked_mut, vrsn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::core::serdering::SadValue;
    use crate::keri::KERIError;
    use indexmap::IndexMap;

    #[test]
    fn test_sizeify() -> Result<(), KERIError> {
        // Create a test KED with version string using Sadd (IndexMap<String, SadValue>)
        let mut ked = IndexMap::new();

        // Add required fields
        ked.insert(
            "v".to_string(),
            SadValue::String("KERI10JSON000000_".to_string()),
        );
        ked.insert("t".to_string(), SadValue::String("icp".to_string()));
        ked.insert(
            "d".to_string(),
            SadValue::String("E_0C8xxRQ8I7R5URH_SLED_YQFVpzw9_XYGg7p5YENGM".to_string()),
        );
        ked.insert(
            "i".to_string(),
            SadValue::String("E_0C8xxRQ8I7R5URH_SLED_YQFVpzw9_XYGg7p5YENGM".to_string()),
        );
        ked.insert("s".to_string(), SadValue::String("0".to_string()));
        ked.insert("kt".to_string(), SadValue::String("1".to_string()));

        // Add key list
        ked.insert(
            "k".to_string(),
            SadValue::Array(vec![SadValue::String(
                "DKvWXaxQfN91JgPjrguoCTXPGtZWJoV9kFEu8MMuxVSZ".to_string(),
            )]),
        );

        // Add empty lists
        ked.insert("nt".to_string(), SadValue::String("0".to_string()));
        ked.insert("n".to_string(), SadValue::Array(vec![]));
        ked.insert("bt".to_string(), SadValue::String("0".to_string()));
        ked.insert("b".to_string(), SadValue::Array(vec![]));
        ked.insert("c".to_string(), SadValue::Array(vec![]));
        ked.insert("a".to_string(), SadValue::Array(vec![]));

        // Call sizeify
        let (raw, proto, kind, updated_ked, vrsn) = sizeify(&ked, None, None)?;

        // Check results
        assert_eq!(proto, "KERI");
        assert_eq!(kind, "JSON");
        assert_eq!(vrsn, Versionage { major: 1, minor: 0 });

        // Check if size was updated in version string
        if let SadValue::String(updated_v) = &updated_ked["v"] {
            assert!(updated_v.starts_with("KERI10JSON"));
            assert_ne!(updated_v, "KERI10JSON000000_"); // Should have actual size, not placeholder

            // Size in version string should reflect raw length
            let smellage = deversify(updated_v)?;
            let actual_size = smellage.size;
            assert_eq!(actual_size, raw.len());
        } else {
            panic!("Expected version to be a string value");
        }

        Ok(())
    }

    #[test]
    fn test_sizeify_with_custom_kind() -> Result<(), KERIError> {
        // Create a test KED with version string using Sadd
        let mut ked = IndexMap::new();

        // Add required fields
        ked.insert(
            "v".to_string(),
            SadValue::String("KERI10JSON000000_".to_string()),
        );
        ked.insert("t".to_string(), SadValue::String("icp".to_string()));
        ked.insert(
            "d".to_string(),
            SadValue::String("E_0C8xxRQ8I7R5URH_SLED_YQFVpzw9_XYGg7p5YENGM".to_string()),
        );
        ked.insert(
            "i".to_string(),
            SadValue::String("E_0C8xxRQ8I7R5URH_SLED_YQFVpzw9_XYGg7p5YENGM".to_string()),
        );

        // Call sizeify with CBOR kind
        let (_, _, kind, updated_ked, _) = sizeify(&ked, Some(&Kinds::Cbor), None)?;

        // Check if kind was set correctly
        assert_eq!(kind, "CBOR");

        // Version string should reflect CBOR kind
        if let SadValue::String(updated_v) = &updated_ked["v"] {
            assert!(updated_v.starts_with("KERI10CBOR"));
        } else {
            panic!("Expected version to be a string value");
        }

        Ok(())
    }

    #[test]
    fn test_sizeify_unsupported_version() {
        // Create a test KED with version string using Sadd
        let mut ked = IndexMap::new();

        // Add required fields
        ked.insert(
            "v".to_string(),
            SadValue::String("KERI10JSON000000_".to_string()),
        );
        ked.insert("t".to_string(), SadValue::String("icp".to_string()));

        // Call sizeify with unsupported version
        let result = sizeify(&ked, None, Some(Versionage { major: 2, minor: 0 }));

        // Should return an error
        assert!(result.is_err());
        if let Err(KERIError::ValueError(msg)) = result {
            assert!(msg.contains("Unsupported version"));
        } else {
            panic!("Expected ValueError");
        }
    }
}
