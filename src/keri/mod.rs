use crate::cesr::b64_to_int;
use crate::cesr::{int_to_b64, Versionage};
use crate::errors::MatterError;
use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use thiserror::Error;

mod app;
mod core;
mod db;

/// Format string for version
pub const VERFMT: &str = "{}{:x}{:x}{}{:0{}x}_";

/// Number of hex characters in raw serialization size in version string
pub const VERRAWSIZE: usize = 6;

/// Number of characters in full version string for version 1
pub const VER1FULLSPAN: usize = 17;

/// Terminator for version 1 string
pub const VER1TERM: &[u8] = b"_";

/// Regular expression pattern for version 1 format
pub const VEREX1: &[u8] = b"(?P<proto1>[A-Z]{4})(?P<major1>[0-9a-f])(?P<minor1>[0-9a-f])(?P<kind1>[A-Z]{4})(?P<size1>[0-9a-f]{6})_";

/// Number of characters in full version string for version 2
pub const VER2FULLSPAN: usize = 16;

/// Terminator for version 2 string
pub const VER2TERM: &[u8] = b".";

/// Regular expression pattern for version 2 format
pub const VEREX2: &[u8] = b"(?P<proto2>[A-Z]{4})(?P<major2>[0-9A-Za-z_-])(?P<minor2>[0-9A-Za-z_-]{2})(?P<kind2>[A-Z]{4})(?P<size2>[0-9A-Za-z_-]{4})\\.";

/// Combined regular expression pattern for both version formats
pub const VEREX: &[u8] = b"(?P<proto2>[A-Z]{4})(?P<major2>[0-9A-Za-z_-])(?P<minor2>[0-9A-Za-z_-]{2})(?P<kind2>[A-Z]{4})(?P<size2>[0-9A-Za-z_-]{4})\\.|(?P<proto1>[A-Z]{4})(?P<major1>[0-9a-f])(?P<minor1>[0-9a-f])(?P<kind1>[A-Z]{4})(?P<size1>[0-9a-f]{6})_";

/// Maximum number of characters in full version string
pub const MAXVERFULLSPAN: usize = VER1FULLSPAN;

/// Compiled regular expression for version detection
pub static REVER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(std::str::from_utf8(VEREX1).expect("Invalid regex pattern"))
        .expect("Failed to compile regex pattern")
});

/// Maximum version string offset
pub const MAXVSOFFSET: usize = 12;

/// Minimum buffer size to "smell" the version format
pub const SMELLSIZE: usize = MAXVSOFFSET + MAXVERFULLSPAN;

/// Errors related to protocol validation
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid protocol={0}.")]
    Invalid(String),
}

/// Errors related to version validation
#[derive(Error, Debug)]
pub enum KERIError {
    #[error("Value error={0}.")]
    ValueError(String),

    #[error("Incompatible vrsn={0:?} with version string.")]
    Incompatible(Versionage),

    #[error("Bad rematch.")]
    BadRematch(),

    #[error("Invalid version string = '{0}'.")]
    VersionError(String),

    #[error("Short version string = '{0}'.")]
    Shortage(String),

    #[error("Kind string error = '{0}'.")]
    KindError(String),

    #[error("Protocol error = '{0}'.")]
    ProtocolError(String),

    #[error("Field error: {0}")]
    FieldError(String),

    #[error("Deserialization error: {0}")]
    DeserializeError(String),

    #[error("Invalid version: {0}")]
    SerderVersionError(String),

    #[error("Invalid version: {0}")]
    ValidationError(String),

    #[error("Error deserializing JSON: {0}")]
    JsonError(String),

    #[error("Error deserializing MGPK: {0}")]
    MgpkError(String),

    #[error("Error deserializing CBOR: {0}")]
    CborError(String),

    #[error("Invalid deserialization kind: {0}")]
    InvalidKind(String),

    #[error("Missing required field '{0}' for ilk '{1}'")]
    MissingRequiredField(String, String),

    #[error("Unknown ilk: {0}")]
    UnknownIlk(String),

    #[error("Wrapped matter error: {0}")]
    MatterError(String),

    #[error("IO Error")]
    Io(#[from] std::io::Error),

    #[error("Parsing Error: {0}")]
    Parsing(String),

    #[error("Unsupported Message Version")]
    UnsupportedMessage,

    #[error("Invalid CESR Data")]
    InvalidCesrData,
}

impl From<MatterError> for KERIError {
    fn from(error: MatterError) -> Self {
        match error {
            MatterError::InvalidCode(code) => {
                KERIError::ValidationError(format!("Invalid Matter code: {}", code))
            }

            // Fallback for any other errors or future-added error types
            _ => KERIError::MatterError(format!("{:?}", error)),
        }
    }
}
/// Extracts and validates version information from a regex match
///
/// # Arguments
/// * `captures` - Regex captures from a version string match
///
/// # Returns
/// * `Result<Smellage, Error>` - A structured version information or an error
pub fn rematch(captures: &regex::Captures) -> Result<Smellage, KERIError> {
    let full = captures.get(0).unwrap().as_str().as_bytes();

    if full.len() == VER2FULLSPAN && full[full.len() - 1] == VER2TERM[0] {
        // Version 2 format
        let proto = captures.name("proto2").unwrap().as_str();
        let major = captures.name("major2").unwrap().as_str();
        let minor = captures.name("minor2").unwrap().as_str();
        let kind = captures.name("kind2").unwrap().as_str();
        let size = captures.name("size2").unwrap().as_str();

        if !Protocolage::contains(proto) {
            return Err(KERIError::VersionError(proto.to_string()));
        }

        let vrsn = Versionage {
            major: b64_to_int(major),
            minor: b64_to_int(minor),
        };

        let gvrsn = Versionage {
            major: b64_to_int(major),
            minor: b64_to_int(minor),
        };

        if vrsn.major < 2 {
            return Err(KERIError::VersionError(format!(
                "{}.{}",
                vrsn.major, vrsn.minor
            )));
        }

        if !Kinds::contains(kind) {
            return Err(KERIError::KindError(kind.to_string()));
        }

        let size_val = b64_to_int(size);

        Ok(Smellage {
            proto: proto.to_string(),
            vrsn: vrsn.into(),
            gvrsn: gvrsn.into(),
            kind: kind.to_string(),
            size: size_val as usize,
        })
    } else if full.len() == VER1FULLSPAN && full[full.len() - 1] == VER1TERM[0] {
        // Version 1 format
        let proto = captures.name("proto1").unwrap().as_str();
        let major = captures.name("major1").unwrap().as_str();
        let minor = captures.name("minor1").unwrap().as_str();
        let kind = captures.name("kind1").unwrap().as_str();
        let size = captures.name("size1").unwrap().as_str();

        if !Protocolage::contains(proto) {
            return Err(KERIError::ProtocolError(proto.to_string()));
        }

        let vrsn = Versionage {
            major: u32::from_str_radix(major, 16).expect("Failed to parse hex"),
            minor: u32::from_str_radix(minor, 16).expect("Failed to parse hex"),
        };

        let gvrsn = Versionage {
            major: u32::from_str_radix(major, 16).expect("Failed to parse hex"),
            minor: u32::from_str_radix(minor, 16).expect("Failed to parse hex"),
        };

        if vrsn.major > 1 {
            return Err(KERIError::Incompatible(vrsn));
        }

        if !Kinds::contains(kind) {
            return Err(KERIError::KindError(kind.to_string()));
        }

        let size_val = u32::from_str_radix(size, 16).expect("Failed to parse hex");

        Ok(Smellage {
            proto: proto.to_string(),
            vrsn: vrsn.into(),
            gvrsn: gvrsn.into(),
            kind: kind.to_string(),
            size: size_val as usize,
        })
    } else {
        Err(KERIError::VersionError(format!("{:?}", full)))
    }
}

/// Creates a version string based on protocol, version, kind, and size
///
/// # Arguments
///
/// * `protocol` - Protocol identifier, one of the valid Protocols values
/// * `version` - Version information consisting of major and minor parts
/// * `kind` - Serialization kind, one of the valid Kinds values
/// * `size` - Length of serialized map that embeds version string field
///
/// # Returns
///
/// A formatted version string according to the version format
///
/// # Errors
///
/// Returns an error if the protocol or kind is invalid
pub fn versify(
    protocol: &str,
    version: &Versionage,
    kind: &str,
    size: u64,
) -> Result<String, KERIError> {
    if !Protocolage::contains(protocol) {
        return Err(KERIError::ProtocolError(protocol.to_string()));
    }
    if !Kinds::contains(kind) {
        return Err(KERIError::KindError(kind.to_string()));
    }

    if version.major < 2 {
        // Version 1 format
        Ok(format!(
            "{}{:x}{:x}{}{:0width$x}_",
            protocol,
            version.major,
            version.minor,
            kind,
            size,
            width = VERRAWSIZE
        ))
    } else {
        // Version 2+ format
        Ok(format!(
            "{}{}{}{}{}{}",
            protocol,
            int_to_b64(version.major, 1),
            int_to_b64(version.minor, 2),
            kind,
            int_to_b64(size as u32, 4),
            std::str::from_utf8(VER2TERM).unwrap()
        ))
    }
}

/// Extracts protocol type, version, serialization kind, and size from a version string
///
/// # Arguments
///
/// * `vs` - A version string, either as a string slice or byte slice
///
/// # Returns
///
/// A Result containing a Smellage struct with extracted information or an error
///
/// # Errors
///
/// Returns an error if the version string format is invalid
pub fn deversify<T: AsRef<[u8]>>(vs: T) -> Result<Smellage, KERIError> {
    // Convert input to bytes if it's not already
    let vs_bytes = vs.as_ref();

    let vs_str = std::str::from_utf8(vs_bytes)
        .map_err(|e| KERIError::VersionError(format!("Invalid UTF-8: {}", e)))?;
    // Match the version string against the regex pattern
    match REVER.captures(vs_str) {
        Some(captures) => rematch(&captures),
        None => Err(KERIError::VersionError(
            String::from_utf8_lossy(vs_bytes).to_string(),
        )),
    }
}

/// Extract and return an instance of Smellage from a version string inside raw serialization.
///
/// # Arguments
///
/// * `raw` - A byte slice containing serialized incoming message stream.
///   Assumes start of stream is JSON, CBOR, or MGPK field map with first field
///   is labeled 'v' and value is version string.
///
/// # Returns
///
/// A Result containing a Smellage struct with extracted information or an error
///
/// # Errors
///
/// Returns a ShortageError if the raw bytes are too short to contain a full version string.
/// Returns a VersionError if the version string is invalid or not found within MAXVSOFFSET.
pub fn smell(raw: &[u8]) -> Result<Smellage, KERIError> {
    if raw.len() < SMELLSIZE {
        return Err(KERIError::VersionError(
            "Need more raw bytes to smell full version string.".to_string(),
        ));
    }

    let raw_str = std::str::from_utf8(raw)
        .map_err(|e| KERIError::VersionError(format!("Invalid UTF-8: {}", e)))?;
    // Search for version string pattern in raw bytes
    match REVER.find(raw_str) {
        Some(mat) if mat.start() <= MAXVSOFFSET => {
            // If found and within max offset, extract captures and get Smellage
            let caps = REVER
                .captures(raw_str)
                .expect("Match should contain captures");
            rematch(&caps)
        }
        _ => {
            // Either not found or found outside max offset
            Err(KERIError::VersionError(format!(
                "Invalid version string from smelled raw = {:?}",
                &raw[..SMELLSIZE.min(raw.len())]
            )))
        }
    }
}

/// KERI/ACDC protocol packet (message) types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ilks;

impl Ilks {
    pub const ICP: &'static str = "icp";
    pub const ROT: &'static str = "rot";
    pub const IXN: &'static str = "ixn";
    pub const DIP: &'static str = "dip";
    pub const DRT: &'static str = "drt";
    pub const RCT: &'static str = "rct";
    pub const QRY: &'static str = "qry";
    pub const RPY: &'static str = "rpy";
    pub const XIP: &'static str = "xip";
    pub const EXN: &'static str = "exn";
    pub const PRO: &'static str = "pro";
    pub const BAR: &'static str = "bar";
    pub const VCP: &'static str = "vcp";
    pub const VRT: &'static str = "vrt";
    pub const ISS: &'static str = "iss";
    pub const REV: &'static str = "rev";
    pub const BIS: &'static str = "bis";
    pub const BRV: &'static str = "brv";
    pub const RIP: &'static str = "rip";
    pub const UPD: &'static str = "upd";
    pub const ACD: &'static str = "acd";
    pub const ACE: &'static str = "ace";
    pub const SCH: &'static str = "sch";
    pub const ATT: &'static str = "att";
    pub const AGG: &'static str = "agg";
    pub const EDG: &'static str = "edg";
    pub const RUL: &'static str = "rul";

    /// Returns all Ilk values as a vector of strings
    pub fn all() -> Vec<&'static str> {
        vec![
            Self::ICP,
            Self::ROT,
            Self::IXN,
            Self::DIP,
            Self::DRT,
            Self::RCT,
            Self::QRY,
            Self::RPY,
            Self::XIP,
            Self::EXN,
            Self::PRO,
            Self::BAR,
            Self::VCP,
            Self::VRT,
            Self::ISS,
            Self::REV,
            Self::BIS,
            Self::BRV,
            Self::RIP,
            Self::UPD,
            Self::ACD,
            Self::ACE,
            Self::SCH,
            Self::ATT,
            Self::AGG,
            Self::EDG,
            Self::RUL,
        ]
    }

    /// Checks if a given string is a valid Ilk
    pub fn is_valid(ilk: &str) -> bool {
        Self::all().contains(&ilk)
    }
}

impl std::hash::Hash for Ilk {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}
/// Alternative representation of Ilks using an enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ilk {
    Icp,
    Rot,
    Ixn,
    Dip,
    Drt,
    Rct,
    Qry,
    Rpy,
    Xip,
    Exn,
    Pro,
    Bar,
    Vcp,
    Vrt,
    Iss,
    Rev,
    Bis,
    Brv,
    Rip,
    Upd,
    Acd,
    Ace,
    Sch,
    Att,
    Agg,
    Edg,
    Rul,
}

impl Ilk {
    /// Convert enum variant to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Ilk::Icp => Ilks::ICP,
            Ilk::Rot => Ilks::ROT,
            Ilk::Ixn => Ilks::IXN,
            Ilk::Dip => Ilks::DIP,
            Ilk::Drt => Ilks::DRT,
            Ilk::Rct => Ilks::RCT,
            Ilk::Qry => Ilks::QRY,
            Ilk::Rpy => Ilks::RPY,
            Ilk::Xip => Ilks::XIP,
            Ilk::Exn => Ilks::EXN,
            Ilk::Pro => Ilks::PRO,
            Ilk::Bar => Ilks::BAR,
            Ilk::Vcp => Ilks::VCP,
            Ilk::Vrt => Ilks::VRT,
            Ilk::Iss => Ilks::ISS,
            Ilk::Rev => Ilks::REV,
            Ilk::Bis => Ilks::BIS,
            Ilk::Brv => Ilks::BRV,
            Ilk::Rip => Ilks::RIP,
            Ilk::Upd => Ilks::UPD,
            Ilk::Acd => Ilks::ACD,
            Ilk::Ace => Ilks::ACE,
            Ilk::Sch => Ilks::SCH,
            Ilk::Att => Ilks::ATT,
            Ilk::Agg => Ilks::AGG,
            Ilk::Edg => Ilks::EDG,
            Ilk::Rul => Ilks::RUL,
        }
    }

    /// Try to create an Ilk from a string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            Ilks::ICP => Some(Ilk::Icp),
            Ilks::ROT => Some(Ilk::Rot),
            Ilks::IXN => Some(Ilk::Ixn),
            Ilks::DIP => Some(Ilk::Dip),
            Ilks::DRT => Some(Ilk::Drt),
            Ilks::RCT => Some(Ilk::Rct),
            Ilks::QRY => Some(Ilk::Qry),
            Ilks::RPY => Some(Ilk::Rpy),
            Ilks::XIP => Some(Ilk::Xip),
            Ilks::EXN => Some(Ilk::Exn),
            Ilks::PRO => Some(Ilk::Pro),
            Ilks::BAR => Some(Ilk::Bar),
            Ilks::VCP => Some(Ilk::Vcp),
            Ilks::VRT => Some(Ilk::Vrt),
            Ilks::ISS => Some(Ilk::Iss),
            Ilks::REV => Some(Ilk::Rev),
            Ilks::BIS => Some(Ilk::Bis),
            Ilks::BRV => Some(Ilk::Brv),
            Ilks::RIP => Some(Ilk::Rip),
            Ilks::UPD => Some(Ilk::Upd),
            Ilks::ACD => Some(Ilk::Acd),
            Ilks::ACE => Some(Ilk::Ace),
            Ilks::SCH => Some(Ilk::Sch),
            Ilks::ATT => Some(Ilk::Att),
            Ilks::AGG => Some(Ilk::Agg),
            Ilks::EDG => Some(Ilk::Edg),
            Ilks::RUL => Some(Ilk::Rul),
            _ => None,
        }
    }
}

// This allows: let ilk: Ilk = "icp".try_into().unwrap();
impl TryFrom<&str> for Ilk {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s).ok_or_else(|| format!("Invalid ilk: {}", s))
    }
}

// This allows: format!("{}", ilk)
impl fmt::Display for Ilk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// SAID field labels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Saids;

impl Saids {
    pub const DOLLAR: &'static str = "$id";
    pub const AT: &'static str = "@id";
    pub const ID: &'static str = "id";
    pub const I: &'static str = "i";
    pub const D: &'static str = "d";

    /// Returns all SAID field labels as a vector of strings
    pub fn all() -> Vec<&'static str> {
        vec![Self::DOLLAR, Self::AT, Self::ID, Self::I, Self::D]
    }

    /// Checks if a given string is a valid SAID field label
    pub fn is_valid(label: &str) -> bool {
        Self::all().contains(&label)
    }
}

/// Alternative representation of SAID field labels using an enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    Dollar,
    At,
    Id,
    I,
    D,
}

impl Said {
    /// Convert enum variant to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Said::Dollar => Saids::DOLLAR,
            Said::At => Saids::AT,
            Said::Id => Saids::ID,
            Said::I => Saids::I,
            Said::D => Saids::D,
        }
    }

    /// Try to create a Said from a string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            Saids::DOLLAR => Some(Said::Dollar),
            Saids::AT => Some(Said::At),
            Saids::ID => Some(Said::Id),
            Saids::I => Some(Said::I),
            Saids::D => Some(Said::D),
            _ => None,
        }
    }
}

// This allows: let said: Said = "$id".try_into().unwrap();
impl TryFrom<&str> for Said {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s).ok_or_else(|| format!("Invalid SAID field label: {}", s))
    }
}

// This allows: format!("{}", said)
impl fmt::Display for Said {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents message envelope properties
#[derive(Debug, Clone, PartialEq)]
pub struct Smellage {
    /// Protocol identifier
    pub proto: String,
    /// Version Versionage
    pub vrsn: Versionage,
    /// Message kind
    pub kind: String,
    /// Size of the message
    pub size: usize,
    /// KERI global version, optional with default None
    pub gvrsn: Option<Versionage>,
}

impl Smellage {
    /// Create a new Smellage instance
    pub fn new(
        proto: impl Into<String>,
        vrsn: Versionage,
        kind: impl Into<String>,
        size: usize,
    ) -> Self {
        Self {
            proto: proto.into(),
            vrsn,
            kind: kind.into(),
            size,
            gvrsn: None,
        }
    }

    /// Create a new Smellage instance with all fields including gvrsn
    pub fn with_gvrsn(
        proto: impl Into<String>,
        vrsn: Versionage,
        kind: impl Into<String>,
        size: usize,
        gvrsn: Versionage,
    ) -> Self {
        Self {
            proto: proto.into(),
            vrsn,
            kind: kind.into(),
            size,
            gvrsn: Some(gvrsn),
        }
    }
}

/// Builder pattern for more flexible construction
pub struct SmellageBuilder {
    proto: Option<String>,
    vrsn: Option<Versionage>,
    kind: Option<String>,
    size: Option<usize>,
    gvrsn: Option<Versionage>,
}

impl SmellageBuilder {
    /// Create a new empty builder
    pub fn new() -> Self {
        Self {
            proto: None,
            vrsn: None,
            kind: None,
            size: None,
            gvrsn: None,
        }
    }

    /// Set the protocol identifier
    pub fn proto(mut self, proto: impl Into<String>) -> Self {
        self.proto = Some(proto.into());
        self
    }

    /// Set the version string
    pub fn vrsn(mut self, vrsn: Versionage) -> Self {
        self.vrsn = Some(vrsn);
        self
    }

    /// Set the message kind
    pub fn kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = Some(kind.into());
        self
    }

    /// Set the size of the message
    pub fn size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    /// Set the KERI global version
    pub fn gvrsn(mut self, gvrsn: Versionage) -> Self {
        self.gvrsn = Some(gvrsn);
        self
    }

    /// Build the Smellage instance
    pub fn build(self) -> Result<Smellage, String> {
        let proto = self.proto.ok_or_else(|| "proto is required".to_string())?;
        let vrsn = self.vrsn.ok_or_else(|| "vrsn is required".to_string())?;
        let kind = self.kind.ok_or_else(|| "kind is required".to_string())?;
        let size = self.size.ok_or_else(|| "size is required".to_string())?;

        Ok(Smellage {
            proto,
            vrsn,
            kind,
            size,
            gvrsn: self.gvrsn,
        })
    }
}

impl Default for SmellageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Enum representing serialization kinds
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Kinds {
    Json,
    Mgpk,
    Cbor,
    Cesr,
}

impl Kinds {
    pub fn contains(other: &str) -> bool {
        "JSON" == other || "MGPK" == other || "CBOR" == other || "CESR" == other
    }

    pub fn from(kind: &str) -> Result<Self, KERIError> {
        match kind {
            "JSON" => Ok(Self::Json),
            "MGPK" => Ok(Self::Mgpk),
            "CBOR" => Ok(Self::Cbor),
            "CESR" => Ok(Self::Cesr),
            _ => Err(KERIError::VersionError(format!(
                "Invalid serialization kind: {}",
                kind
            ))),
        }
    }
}

impl fmt::Display for Kinds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Kinds::Json => write!(f, "JSON"),
            Kinds::Mgpk => write!(f, "MGPK"),
            Kinds::Cbor => write!(f, "CBOR"),
            Kinds::Cesr => write!(f, "CESR"),
        }
    }
}

/// Represents supported protocol types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Protocolage {
    /// KERI protocol identifier
    pub keri: String,

    /// ACDC protocol identifier
    pub acdc: String,
}

impl Protocolage {
    /// Create a new Protocolage instance
    pub fn new(keri: impl Into<String>, acdc: impl Into<String>) -> Self {
        Self {
            keri: keri.into(),
            acdc: acdc.into(),
        }
    }

    pub fn contains(other: &str) -> bool {
        "KERI" == other || "ACDC" == other
    }
}

impl Default for Protocolage {
    fn default() -> Self {
        Self {
            keri: "KERI".to_string(),
            acdc: "ACDC".to_string(),
        }
    }
}

/// Add conversion from tuple for convenience
impl From<(String, String)> for Protocolage {
    fn from(tuple: (String, String)) -> Self {
        Self {
            keri: tuple.0,
            acdc: tuple.1,
        }
    }
}

/// Allow conversion from &str tuple
impl From<(&str, &str)> for Protocolage {
    fn from(tuple: (&str, &str)) -> Self {
        Self {
            keri: tuple.0.to_string(),
            acdc: tuple.1.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ilk_constants() {
        assert_eq!(Ilks::ICP, "icp");
        assert_eq!(Ilks::ROT, "rot");
        assert_eq!(Ilks::IXN, "ixn");
        // ... and so on
    }

    #[test]
    fn test_all_ilks() {
        let all = Ilks::all();
        assert_eq!(all.len(), 27); // Total number of Ilks
        assert!(all.contains(&"icp"));
        assert!(all.contains(&"rot"));
        // ... and so on
    }

    #[test]
    fn test_is_valid_ilk() {
        assert!(Ilks::is_valid("icp"));
        assert!(Ilks::is_valid("rot"));
        assert!(!Ilks::is_valid("invalid"));
    }

    #[test]
    fn test_ilk_enum() {
        assert_eq!(Ilk::Icp.as_str(), "icp");
        assert_eq!(Ilk::Rot.as_str(), "rot");
        // ... and so on
    }

    #[test]
    fn test_ilk_from_str() {
        assert_eq!(Ilk::from_str("icp"), Some(Ilk::Icp));
        assert_eq!(Ilk::from_str("rot"), Some(Ilk::Rot));
        assert_eq!(Ilk::from_str("invalid"), None);
    }

    #[test]
    fn test_ilk_try_from() {
        let ilk: Result<Ilk, _> = "icp".try_into();
        assert!(ilk.is_ok());
        assert_eq!(ilk.unwrap(), Ilk::Icp);

        let invalid: Result<Ilk, _> = "invalid".try_into();
        assert!(invalid.is_err());
    }

    #[test]
    fn test_ilk_display() {
        assert_eq!(format!("{}", Ilk::Icp), "icp");
        assert_eq!(format!("{}", Ilk::Rot), "rot");
    }

    #[test]
    fn test_said_constants() {
        assert_eq!(Saids::DOLLAR, "$id");
        assert_eq!(Saids::AT, "@id");
        assert_eq!(Saids::ID, "id");
        assert_eq!(Saids::I, "i");
        assert_eq!(Saids::D, "d");
    }

    #[test]
    fn test_all_saids() {
        let all = Saids::all();
        assert_eq!(all.len(), 5); // Total number of SAID field labels
        assert!(all.contains(&"$id"));
        assert!(all.contains(&"@id"));
        assert!(all.contains(&"id"));
        assert!(all.contains(&"i"));
        assert!(all.contains(&"d"));
    }

    #[test]
    fn test_is_valid_said() {
        assert!(Saids::is_valid("$id"));
        assert!(Saids::is_valid("@id"));
        assert!(Saids::is_valid("id"));
        assert!(Saids::is_valid("i"));
        assert!(Saids::is_valid("d"));
        assert!(!Saids::is_valid("invalid"));
    }

    #[test]
    fn test_said_enum() {
        assert_eq!(Said::Dollar.as_str(), "$id");
        assert_eq!(Said::At.as_str(), "@id");
        assert_eq!(Said::Id.as_str(), "id");
        assert_eq!(Said::I.as_str(), "i");
        assert_eq!(Said::D.as_str(), "d");
    }

    #[test]
    fn test_said_from_str() {
        assert_eq!(Said::from_str("$id"), Some(Said::Dollar));
        assert_eq!(Said::from_str("@id"), Some(Said::At));
        assert_eq!(Said::from_str("id"), Some(Said::Id));
        assert_eq!(Said::from_str("i"), Some(Said::I));
        assert_eq!(Said::from_str("d"), Some(Said::D));
        assert_eq!(Said::from_str("invalid"), None);
    }

    #[test]
    fn test_said_try_from() {
        let dollar: Result<Said, _> = "$id".try_into();
        assert!(dollar.is_ok());
        assert_eq!(dollar.unwrap(), Said::Dollar);

        let at: Result<Said, _> = "@id".try_into();
        assert!(at.is_ok());
        assert_eq!(at.unwrap(), Said::At);

        let invalid: Result<Said, _> = "invalid".try_into();
        assert!(invalid.is_err());
    }

    #[test]
    fn test_said_display() {
        assert_eq!(format!("{}", Said::Dollar), "$id");
        assert_eq!(format!("{}", Said::At), "@id");
        assert_eq!(format!("{}", Said::Id), "id");
        assert_eq!(format!("{}", Said::I), "i");
        assert_eq!(format!("{}", Said::D), "d");
    }
    #[test]
    fn test_smellage_new() {
        let smell = Smellage::new("KERI", Versionage { major: 1, minor: 0 }, "icp", 123);
        assert_eq!(smell.proto, "KERI");
        assert_eq!(smell.vrsn, Versionage { major: 1, minor: 0 });
        assert_eq!(smell.kind, "icp");
        assert_eq!(smell.size, 123);
        assert_eq!(smell.gvrsn, None);
    }

    #[test]
    fn test_smellage_with_gvrsn() {
        let smell = Smellage::with_gvrsn(
            "KERI",
            Versionage { major: 1, minor: 0 },
            "icp",
            123,
            Versionage { major: 1, minor: 0 },
        );
        assert_eq!(smell.proto, "KERI");
        assert_eq!(smell.vrsn, Versionage { major: 1, minor: 0 });
        assert_eq!(smell.kind, "icp");
        assert_eq!(smell.size, 123);
        assert_eq!(smell.gvrsn, Some(Versionage { major: 1, minor: 0 }));
    }

    #[test]
    fn test_smellage_builder() {
        let smell = SmellageBuilder::new()
            .proto("KERI")
            .vrsn(Versionage { major: 1, minor: 0 })
            .kind("rot")
            .size(256)
            .gvrsn(Versionage { major: 1, minor: 0 })
            .build()
            .unwrap();

        assert_eq!(smell.proto, "KERI");
        assert_eq!(smell.vrsn, Versionage { major: 1, minor: 0 });
        assert_eq!(smell.kind, "rot");
        assert_eq!(smell.size, 256);
        assert_eq!(smell.gvrsn, Some(Versionage { major: 1, minor: 0 }));
    }

    #[test]
    fn test_builder_error() {
        let result = SmellageBuilder::new()
            .proto("KERI")
            .vrsn(Versionage { major: 1, minor: 0 })
            .size(256)
            .build();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "kind is required");
    }

    #[test]
    fn test_protocolage_new() {
        let proto = Protocolage::new("KERI", "ACDC");
        assert_eq!(proto.keri, "KERI");
        assert_eq!(proto.acdc, "ACDC");
    }

    #[test]
    fn test_protocolage_default() {
        let proto = Protocolage::default();
        assert_eq!(proto.keri, "KERI");
        assert_eq!(proto.acdc, "ACDC");
    }

    #[test]
    fn test_protocolage_from_tuple() {
        let proto: Protocolage = ("KERI".to_string(), "ACDC".to_string()).into();
        assert_eq!(proto.keri, "KERI");
        assert_eq!(proto.acdc, "ACDC");

        let proto: Protocolage = ("KERI", "ACDC").into();
        assert_eq!(proto.keri, "KERI");
        assert_eq!(proto.acdc, "ACDC");
    }
}
