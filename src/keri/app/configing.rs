//! Configuration management for KERI applications
//!
//! This module provides the `Configer` trait and implementations for managing
//! configuration data with support for multiple serialization formats including
//! JSON, MessagePack, and CBOR.

use crate::errors::MatterError;
use crate::keri::core::filing::BaseFiler;
use serde_json;
use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Configuration file format
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigFormat {
    /// JSON format (default)
    Json,
    /// MessagePack binary format
    MessagePack,
    /// CBOR binary format
    Cbor,
}

impl ConfigFormat {
    /// Get format from file extension
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "json" => ConfigFormat::Json,
            "mgpk" => ConfigFormat::MessagePack,
            "cbor" => ConfigFormat::Cbor,
            _ => ConfigFormat::Json, // Default to JSON
        }
    }

    /// Get default file extension for this format
    pub fn extension(&self) -> &'static str {
        match self {
            ConfigFormat::Json => "json",
            ConfigFormat::MessagePack => "mgpk",
            ConfigFormat::Cbor => "cbor",
        }
    }
}

/// Configuration management trait
pub trait Configer {
    /// Store configuration data to file
    ///
    /// # Arguments
    /// * `data` - The configuration data to store
    ///
    /// # Returns
    /// * `Result<(), MatterError>` - Success or error
    fn put(&mut self, data: &HashMap<String, serde_json::Value>) -> Result<(), MatterError>;

    /// Retrieve configuration data from file
    ///
    /// # Returns
    /// * `Result<HashMap<String, serde_json::Value>, MatterError>` - Configuration data or error
    fn get(&mut self) -> Result<HashMap<String, serde_json::Value>, MatterError>;

    /// Get the file path for this configer
    fn path(&self) -> &Path;

    /// Get the configuration format
    fn format(&self) -> &ConfigFormat;

    /// Check if a configuration file exists
    fn exists(&self) -> bool {
        self.path().exists()
    }

    /// Get file size in bytes
    fn size(&self) -> Result<u64, MatterError> {
        std::fs::metadata(self.path())
            .map(|m| m.len())
            .map_err(|e| MatterError::IOError(format!("Failed to get file size: {}", e)))
    }
}

/// Default configuration base directory
pub const CONFIG_BASE: &str = "cf";

/// File-based configuration manager using libkeri's Filer system
pub struct FileConfiger {
    /// Internal filer for managing file operations
    filer: BaseFiler,
    /// Configuration format
    format: ConfigFormat,
    /// Whether to use human-readable JSON format
    human: bool,
}

impl std::fmt::Debug for FileConfiger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileConfiger")
            .field("format", &self.format)
            .field("human", &self.human)
            .field("path", &self.path())
            .finish()
    }
}

impl FileConfiger {
    /// Create a new FileConfiger
    ///
    /// # Arguments
    /// * `name` - Configuration file name (default: "conf")
    /// * `base` - Base directory segment (default: "main")
    /// * `format` - Configuration file format (default: JSON)
    /// * `human` - Use human-readable JSON format (default: true)
    /// * `temp` - Use temporary directory (default: false)
    /// * `clean` - Use clean directory variant (default: false)
    ///
    /// # Returns
    /// * `Result<FileConfiger, MatterError>` - New configer or error
    pub fn new(
        name: Option<&str>,
        base: Option<&str>,
        format: Option<ConfigFormat>,
        human: Option<bool>,
        temp: Option<bool>,
        clean: Option<bool>,
    ) -> Result<Self, MatterError> {
        let name = name.unwrap_or("conf");
        let base = base.unwrap_or(CONFIG_BASE);
        let format = format.unwrap_or(ConfigFormat::Json);
        let human = human.unwrap_or(true);
        let temp = temp.unwrap_or(false);
        let clean = clean.unwrap_or(false);

        // Create the filer with appropriate settings
        let filer = BaseFiler::new(
            name,
            base,
            temp,
            None,                                 // Use default head directory path
            None,                                 // Use default permissions
            true,                                 // Reopen immediately
            false,                                // Don't clear on reopen
            true,                                 // Reuse existing path
            clean,                                // Use clean variant if requested
            true,                                 // This is a file, not directory
            false,                                // Don't add extension to directory
            Some("w+".to_string()),               // Read/write mode
            Some(format.extension().to_string()), // Use format extension
            None,                                 // Use default settings
        )
        .map_err(|e| MatterError::IOError(format!("Failed to create filer: {}", e)))?;

        Ok(FileConfiger {
            filer,
            format,
            human,
        })
    }

    /// Create a new FileConfiger with default settings
    pub fn default() -> Result<Self, MatterError> {
        Self::new(None, None, None, None, None, None)
    }

    /// Create a new FileConfiger with specified name
    pub fn with_name(name: &str) -> Result<Self, MatterError> {
        Self::new(Some(name), None, None, None, None, None)
    }

    /// Create a new FileConfiger with specified base directory
    pub fn with_base(base: &str) -> Result<Self, MatterError> {
        Self::new(None, Some(base), None, None, None, None)
    }

    /// Create a new FileConfiger with specified format
    pub fn with_format(format: ConfigFormat) -> Result<Self, MatterError> {
        Self::new(None, None, Some(format), None, None, None)
    }

    /// Create a new temporary FileConfiger
    pub fn with_temp() -> Result<Self, MatterError> {
        Self::new(None, None, None, None, Some(true), None)
    }

    /// Create a new clean FileConfiger
    pub fn with_clean() -> Result<Self, MatterError> {
        Self::new(None, None, None, None, None, Some(true))
    }

    /// Import configuration from an external file into the config directory
    ///
    /// This method reads a configuration file from an external path and recreates it
    /// in the appropriate libkeri config directory structure under the `cf` directory.
    /// The format is auto-detected from the source file extension.
    ///
    /// # Arguments
    /// * `source_path` - Path to the external configuration file to import
    /// * `name` - Optional name for the config in the cf directory (default: source filename)
    /// * `base` - Optional base directory segment (default: "cf")
    /// * `temp` - Use temporary directory (default: false)
    /// * `clean` - Use clean directory variant (default: false)
    ///
    /// # Returns
    /// * `Result<FileConfiger, MatterError>` - New configer with imported data
    pub fn import_from_file(
        source_path: &Path,
        name: Option<&str>,
        base: Option<&str>,
        temp: Option<bool>,
        clean: Option<bool>,
    ) -> Result<Self, MatterError> {
        // Check if source file exists
        if !source_path.exists() {
            return Err(MatterError::IOError(format!(
                "Source file does not exist: {}",
                source_path.display()
            )));
        }

        // Auto-detect format from source file extension
        let format = if let Some(ext) = source_path.extension() {
            ConfigFormat::from_extension(&ext.to_string_lossy())
        } else {
            ConfigFormat::Json // Default to JSON if no extension
        };

        // Use source filename as default name if not provided
        let config_name = name.unwrap_or_else(|| {
            source_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("imported_config")
        });

        // Read the source file
        let source_data = std::fs::read(source_path).map_err(|e| {
            MatterError::IOError(format!(
                "Failed to read source file {}: {}",
                source_path.display(),
                e
            ))
        })?;

        // Create new configer
        let mut configer = Self::new(
            Some(config_name),
            base,
            Some(format.clone()),
            Some(true), // Use human-readable format
            temp,
            clean,
        )?;

        // Parse the source data based on format
        let parsed_data: HashMap<String, serde_json::Value> = match format {
            ConfigFormat::Json => serde_json::from_slice(&source_data).map_err(|e| {
                MatterError::DeserializationError(format!(
                    "Failed to parse JSON from source file: {}",
                    e
                ))
            })?,
            ConfigFormat::MessagePack => {
                #[cfg(feature = "msgpack")]
                {
                    rmp_serde::from_slice(&source_data).map_err(|e| {
                        MatterError::DeserializationError(format!(
                            "Failed to parse MessagePack from source file: {}",
                            e
                        ))
                    })?
                }
                #[cfg(not(feature = "msgpack"))]
                {
                    return Err(MatterError::DeserializationError(
                        "MessagePack support not enabled".to_string(),
                    ));
                }
            }
            ConfigFormat::Cbor => {
                #[cfg(feature = "cbor")]
                {
                    serde_cbor::from_slice(&source_data).map_err(|e| {
                        MatterError::DeserializationError(format!(
                            "Failed to parse CBOR from source file: {}",
                            e
                        ))
                    })?
                }
                #[cfg(not(feature = "cbor"))]
                {
                    return Err(MatterError::DeserializationError(
                        "CBOR support not enabled".to_string(),
                    ));
                }
            }
        };

        // Store the parsed data in the new configer
        configer.put(&parsed_data)?;

        Ok(configer)
    }

    /// Serialize data according to the format
    fn serialize(&self, data: &HashMap<String, serde_json::Value>) -> Result<Vec<u8>, MatterError> {
        match self.format {
            ConfigFormat::Json => {
                if self.human {
                    // Use pretty-printed JSON for human readability
                    serde_json::to_vec_pretty(data).map_err(|e| {
                        MatterError::SerializationError(format!("JSON serialization failed: {}", e))
                    })
                } else {
                    serde_json::to_vec(data).map_err(|e| {
                        MatterError::SerializationError(format!("JSON serialization failed: {}", e))
                    })
                }
            }
            ConfigFormat::MessagePack => {
                #[cfg(feature = "msgpack")]
                {
                    rmp_serde::to_vec(data).map_err(|e| {
                        MatterError::SerializationError(format!(
                            "MessagePack serialization failed: {}",
                            e
                        ))
                    })
                }
                #[cfg(not(feature = "msgpack"))]
                {
                    Err(MatterError::SerializationError(
                        "MessagePack support not enabled".to_string(),
                    ))
                }
            }
            ConfigFormat::Cbor => {
                #[cfg(feature = "cbor")]
                {
                    serde_cbor::to_vec(data).map_err(|e| {
                        MatterError::SerializationError(format!("CBOR serialization failed: {}", e))
                    })
                }
                #[cfg(not(feature = "cbor"))]
                {
                    Err(MatterError::SerializationError(
                        "CBOR support not enabled".to_string(),
                    ))
                }
            }
        }
    }

    /// Deserialize data according to the format
    fn deserialize(&self, data: &[u8]) -> Result<HashMap<String, serde_json::Value>, MatterError> {
        if data.is_empty() {
            return Ok(HashMap::new());
        }

        match self.format {
            ConfigFormat::Json => serde_json::from_slice(data).map_err(|e| {
                MatterError::DeserializationError(format!("JSON deserialization failed: {}", e))
            }),
            ConfigFormat::MessagePack => {
                #[cfg(feature = "msgpack")]
                {
                    rmp_serde::from_slice(data).map_err(|e| {
                        MatterError::DeserializationError(format!(
                            "MessagePack deserialization failed: {}",
                            e
                        ))
                    })
                }
                #[cfg(not(feature = "msgpack"))]
                {
                    Err(MatterError::DeserializationError(
                        "MessagePack support not enabled".to_string(),
                    ))
                }
            }
            ConfigFormat::Cbor => {
                #[cfg(feature = "cbor")]
                {
                    serde_cbor::from_slice(data).map_err(|e| {
                        MatterError::DeserializationError(format!(
                            "CBOR deserialization failed: {}",
                            e
                        ))
                    })
                }
                #[cfg(not(feature = "cbor"))]
                {
                    Err(MatterError::DeserializationError(
                        "CBOR support not enabled".to_string(),
                    ))
                }
            }
        }
    }
}

impl Configer for FileConfiger {
    fn put(&mut self, data: &HashMap<String, serde_json::Value>) -> Result<(), MatterError> {
        let serialized = self.serialize(data)?;

        // Get the file handle from the filer
        let file = self
            .filer
            .get_file_mut()
            .ok_or_else(|| MatterError::IOError("File not opened".to_string()))?;

        // Truncate the file to clear existing content
        file.set_len(0)
            .map_err(|e| MatterError::IOError(format!("Failed to truncate config file: {}", e)))?;

        // Seek to the beginning
        file.seek(SeekFrom::Start(0))
            .map_err(|e| MatterError::IOError(format!("Failed to seek to start: {}", e)))?;

        // Write data
        file.write_all(&serialized)
            .map_err(|e| MatterError::IOError(format!("Failed to write config file: {}", e)))?;

        // Ensure data is written to disk
        file.sync_all()
            .map_err(|e| MatterError::IOError(format!("Failed to sync config file: {}", e)))?;

        Ok(())
    }

    fn get(&mut self) -> Result<HashMap<String, serde_json::Value>, MatterError> {
        // Check if file exists using filer
        let path = self
            .filer
            .get_path()
            .ok_or_else(|| MatterError::IOError("No path available".to_string()))?;

        if !path.exists() {
            return Ok(HashMap::new());
        }

        // Read the file directly using std::fs since filer file handle might not be in read mode
        let buffer = std::fs::read(path)
            .map_err(|e| MatterError::IOError(format!("Failed to read config file: {}", e)))?;

        self.deserialize(&buffer)
    }

    fn path(&self) -> &Path {
        self.filer.get_path().unwrap_or(Path::new(""))
    }

    fn format(&self) -> &ConfigFormat {
        &self.format
    }
}

/// Create a new FileConfiger with default settings
pub fn configer() -> Result<FileConfiger, MatterError> {
    FileConfiger::default()
}

/// Create a new FileConfiger with specified name
pub fn configer_with_name(name: &str) -> Result<FileConfiger, MatterError> {
    FileConfiger::with_name(name)
}

/// Create a new FileConfiger with specified base directory
pub fn configer_with_base(base: &str) -> Result<FileConfiger, MatterError> {
    FileConfiger::with_base(base)
}

/// Create a new FileConfiger with specified format
pub fn configer_with_format(format: ConfigFormat) -> Result<FileConfiger, MatterError> {
    FileConfiger::with_format(format)
}

/// Import configuration from an external file into the config directory
///
/// This convenience function reads a configuration file from an external path and
/// recreates it in the libkeri config directory structure under the `cf` directory.
///
/// # Arguments
/// * `source_path` - Path to the external configuration file to import
/// * `name` - Optional name for the config in the cf directory (default: source filename)
///
/// # Returns
/// * `Result<FileConfiger, MatterError>` - New configer with imported data
///
/// # Example
/// ```rust
/// use std::path::Path;
/// use libkeri::configer_import_file;
///
/// // Import a JSON config file
/// let configer = configer_import_file(Path::new("/path/to/my_config.json"), None)?;
/// ```
pub fn configer_import_file(
    source_path: &Path,
    name: Option<&str>,
) -> Result<FileConfiger, MatterError> {
    FileConfiger::import_from_file(source_path, name, None, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_format_from_extension() {
        assert_eq!(ConfigFormat::from_extension("json"), ConfigFormat::Json);
        assert_eq!(
            ConfigFormat::from_extension("mgpk"),
            ConfigFormat::MessagePack
        );
        assert_eq!(ConfigFormat::from_extension("cbor"), ConfigFormat::Cbor);
        assert_eq!(ConfigFormat::from_extension("unknown"), ConfigFormat::Json);
    }

    #[test]
    fn test_config_format_extension() {
        assert_eq!(ConfigFormat::Json.extension(), "json");
        assert_eq!(ConfigFormat::MessagePack.extension(), "mgpk");
        assert_eq!(ConfigFormat::Cbor.extension(), "cbor");
    }

    #[test]
    fn test_file_configer_new() {
        let configer = FileConfiger::new(
            Some("test"),
            Some("base"),
            Some(ConfigFormat::Json),
            Some(true),
            Some(true),  // Use temp directory
            Some(false), // Don't use clean variant
        )
        .unwrap();

        assert_eq!(configer.format, ConfigFormat::Json);
        assert_eq!(configer.human, true);
        // Check that the path contains the expected components
        let path_str = configer.path().to_string_lossy();
        assert!(path_str.contains("test.json"));
    }

    #[test]
    fn test_put_and_get_json() {
        let mut configer = FileConfiger::new(
            Some("test"),
            Some("base"),
            Some(ConfigFormat::Json),
            Some(true),
            Some(true),  // Use temp directory
            Some(false), // Don't use clean variant
        )
        .unwrap();

        let mut data = HashMap::new();
        data.insert(
            "key1".to_string(),
            serde_json::Value::String("value1".to_string()),
        );
        data.insert(
            "key2".to_string(),
            serde_json::Value::Number(serde_json::Number::from(42)),
        );

        // Put data
        configer.put(&data).unwrap();

        // Check file exists
        assert!(configer.exists());

        // Get data back
        let retrieved = configer.get().unwrap();
        assert_eq!(retrieved.len(), 2);
        assert_eq!(
            retrieved.get("key1").unwrap(),
            &serde_json::Value::String("value1".to_string())
        );
        assert_eq!(
            retrieved.get("key2").unwrap(),
            &serde_json::Value::Number(serde_json::Number::from(42))
        );
    }

    #[test]
    fn test_get_empty_file() {
        let mut configer = FileConfiger::new(
            Some("empty"),
            Some("base"),
            Some(ConfigFormat::Json),
            Some(true),
            Some(true),  // Use temp directory
            Some(false), // Don't use clean variant
        )
        .unwrap();

        // Get from newly created file should return empty map
        let data = configer.get().unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn test_convenience_functions() {
        // These should not panic
        let _configer1 = configer().unwrap();
        let _configer2 = configer_with_name("test").unwrap();
        let _configer3 = configer_with_base("testbase").unwrap();
        let _configer4 = configer_with_format(ConfigFormat::Json).unwrap();
    }

    #[test]
    fn test_import_from_file() {
        use std::fs;
        use std::path::PathBuf;
        use tempfile::TempDir;

        // Create a temporary directory for test files
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create a test JSON config file
        let source_config = r#"{
            "database": {
                "host": "localhost",
                "port": 5432,
                "name": "test_db"
            },
            "logging": {
                "level": "info",
                "file": "/var/log/app.log"
            }
        }"#;

        let source_file_path = temp_path.join("test_config.json");
        fs::write(&source_file_path, source_config).unwrap();

        // Import the configuration file
        let mut configer = FileConfiger::import_from_file(
            &source_file_path,
            Some("imported_test"),
            Some("test_base"),
            Some(true),  // Use temp directory
            Some(false), // Don't use clean variant
        )
        .unwrap();

        // Verify the data was imported correctly
        let retrieved_data = configer.get().unwrap();
        assert!(!retrieved_data.is_empty());

        // Check specific values
        assert!(retrieved_data.contains_key("database"));
        assert!(retrieved_data.contains_key("logging"));

        if let Some(database) = retrieved_data.get("database") {
            let db_obj = database.as_object().unwrap();
            assert_eq!(db_obj.get("host").unwrap().as_str().unwrap(), "localhost");
            assert_eq!(db_obj.get("port").unwrap().as_u64().unwrap(), 5432);
            assert_eq!(db_obj.get("name").unwrap().as_str().unwrap(), "test_db");
        }

        // Test the convenience function as well
        let mut configer2 =
            configer_import_file(&source_file_path, Some("convenience_test")).unwrap();
        let retrieved_data2 = configer2.get().unwrap();
        assert_eq!(retrieved_data, retrieved_data2);

        // Verify the config was created in the appropriate cf directory structure
        let config_path = configer.path();
        let path_str = config_path.to_string_lossy();
        assert!(path_str.contains("test_base"));
        assert!(path_str.contains("imported_test.json"));
    }

    #[test]
    fn test_import_from_file_format_detection() {
        use std::fs;
        use tempfile::TempDir;

        // Create a temporary directory for test files
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Test with JSON format (always available)
        let json_cases = vec![
            ("config.json", ConfigFormat::Json),
            ("config", ConfigFormat::Json), // No extension defaults to JSON
        ];

        let source_config = r#"{"test": "value"}"#;

        for (filename, expected_format) in json_cases {
            let source_file_path = temp_path.join(filename);
            fs::write(&source_file_path, source_config).unwrap();

            let configer = FileConfiger::import_from_file(
                &source_file_path,
                None,
                None,
                Some(true), // Use temp directory
                None,
            )
            .unwrap();

            assert_eq!(configer.format(), &expected_format);
        }

        // Test MessagePack format detection (but only attempt import if feature is enabled)
        let mgpk_file_path = temp_path.join("config.mgpk");
        fs::write(&mgpk_file_path, source_config).unwrap();

        let mgpk_result =
            FileConfiger::import_from_file(&mgpk_file_path, None, None, Some(true), None);

        #[cfg(feature = "msgpack")]
        {
            let configer = mgpk_result.unwrap();
            assert_eq!(configer.format(), &ConfigFormat::MessagePack);
        }

        #[cfg(not(feature = "msgpack"))]
        {
            // Should fail with MessagePack not enabled error
            assert!(mgpk_result.is_err());
            assert!(mgpk_result
                .unwrap_err()
                .to_string()
                .contains("MessagePack support not enabled"));
        }

        // Test CBOR format detection (but only attempt import if feature is enabled)
        let cbor_file_path = temp_path.join("config.cbor");
        fs::write(&cbor_file_path, source_config).unwrap();

        let cbor_result =
            FileConfiger::import_from_file(&cbor_file_path, None, None, Some(true), None);

        #[cfg(feature = "cbor")]
        {
            let configer = cbor_result.unwrap();
            assert_eq!(configer.format(), &ConfigFormat::Cbor);
        }

        #[cfg(not(feature = "cbor"))]
        {
            // Should fail with CBOR not enabled error
            assert!(cbor_result.is_err());
            assert!(cbor_result
                .unwrap_err()
                .to_string()
                .contains("CBOR support not enabled"));
        }
    }

    #[test]
    fn test_import_from_file_errors() {
        use std::path::PathBuf;

        // Test with non-existent file
        let non_existent_path = PathBuf::from("/path/that/does/not/exist.json");
        let result =
            FileConfiger::import_from_file(&non_existent_path, None, None, Some(true), None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Source file does not exist"));
    }
}
