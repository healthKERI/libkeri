//! HIO filing module
//!
//! File and directory management for KERI installations

use std::fs::{self, DirBuilder, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use crate::hio::errors::HioError;
use crate::hio::helping::ocfn;

/// Filer instances manage file directories and files to hold KERI installation
/// specific resources like databases and configuration files.
///
/// # File/Directory Creation Mode Notes
/// `.perm` provides default restricted access permissions to directory and/or files
/// `0o1700` == 960
///
/// - Sticky bit: When this bit is set on a directory it means that a file in that
///   directory can be renamed or deleted only by the owner of the file, by the owner
///   of the directory, or by a privileged process.
/// - Owner has read permission
/// - Owner has write permission  
/// - Owner has execute permission
#[derive(Debug)]
pub struct Filer {
    /// Class constants - using associated constants instead of class variables
    head_dir_path: PathBuf,
    pub(crate) tail_dir_path: PathBuf,
    pub(crate) clean_tail_dir_path: PathBuf,
    alt_head_dir_path: PathBuf,
    pub(crate) alt_tail_dir_path: PathBuf,
    pub(crate) alt_clean_tail_dir_path: PathBuf,
    pub(crate) temp_prefix: String,
    temp_suffix: String,

    /// Instance attributes
    pub name: String,
    pub base: String,
    pub temp: bool,
    pub path: Option<PathBuf>,
    pub perm: u32,
    pub filed: bool,
    pub extensioned: bool,
    pub mode: String,
    pub fext: String,
    pub file: Option<File>,
    pub opened: bool,

    /// Hold temp directory to keep it alive
    _temp_dir: Option<TempDir>,
}

impl Filer {
    // Class constants
    const DEFAULT_HEAD_DIR_PATH: &'static str = "/usr/local/var";
    const DEFAULT_TAIL_DIR_PATH: &'static str = "hio";
    const DEFAULT_CLEAN_TAIL_DIR_PATH: &'static str = "hio/clean";
    const DEFAULT_ALT_TAIL_DIR_PATH: &'static str = ".hio";
    const DEFAULT_ALT_CLEAN_TAIL_DIR_PATH: &'static str = ".hio/clean";
    const DEFAULT_TEMP_PREFIX: &'static str = "hio_";
    const DEFAULT_TEMP_SUFFIX: &'static str = "_test";
    const DEFAULT_PERM: u32 = 0o1700; // S_ISVTX | S_IRUSR | S_IWUSR | S_IXUSR
    const DEFAULT_MODE: &'static str = "r+";
    const DEFAULT_FEXT: &'static str = "text";

    /// Create a new Filer instance
    ///
    /// # Arguments
    /// * `name` - Unique identifier of file/directory
    /// * `base` - Optional directory path segment inserted before name
    /// * `temp` - True means use temporary directory, clear on close
    /// * `head_dir_path` - Optional head directory pathname
    /// * `perm` - Optional numeric OS dir permissions
    /// * `reopen` - True means (re)open with this init
    /// * `clear` - True means remove directory upon close when reopening
    /// * `reuse` - True means reuse self.path if already exists  
    /// * `clean` - True means path uses clean tail variant
    /// * `filed` - True means .path is file path not directory path
    /// * `extensioned` - When not filed: True means ensure .path ends with fext
    /// * `mode` - File open mode when filed
    /// * `fext` - File extension when filed or extensioned
    pub fn new(
        name: Option<String>,
        base: Option<String>,
        temp: Option<bool>,
        head_dir_path: Option<PathBuf>,
        perm: Option<u32>,
        reopen: Option<bool>,
        clear: Option<bool>,
        reuse: Option<bool>,
        clean: Option<bool>,
        filed: Option<bool>,
        extensioned: Option<bool>,
        mode: Option<String>,
        fext: Option<String>,
    ) -> Result<Self, HioError> {
        let name = name.unwrap_or_else(|| "main".to_string());
        let base = base.unwrap_or_default();

        // Validate relative paths
        if Path::new(&name).is_absolute() {
            return Err(HioError::FilerError(format!(
                "Not relative name path: {}",
                name
            )));
        }
        if !base.is_empty() && Path::new(&base).is_absolute() {
            return Err(HioError::FilerError(format!(
                "Not relative base path: {}",
                base
            )));
        }

        let alt_head_dir_path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));

        let mut filer = Filer {
            head_dir_path: head_dir_path
                .unwrap_or_else(|| PathBuf::from(Self::DEFAULT_HEAD_DIR_PATH)),
            tail_dir_path: PathBuf::from(Self::DEFAULT_TAIL_DIR_PATH),
            clean_tail_dir_path: PathBuf::from(Self::DEFAULT_CLEAN_TAIL_DIR_PATH),
            alt_head_dir_path,
            alt_tail_dir_path: PathBuf::from(Self::DEFAULT_ALT_TAIL_DIR_PATH),
            alt_clean_tail_dir_path: PathBuf::from(Self::DEFAULT_ALT_CLEAN_TAIL_DIR_PATH),
            temp_prefix: Self::DEFAULT_TEMP_PREFIX.to_string(),
            temp_suffix: Self::DEFAULT_TEMP_SUFFIX.to_string(),

            name,
            base,
            temp: temp.unwrap_or(false),
            path: None,
            perm: perm.unwrap_or(Self::DEFAULT_PERM),
            filed: filed.unwrap_or(false),
            extensioned: extensioned.unwrap_or(false),
            mode: mode.unwrap_or_else(|| Self::DEFAULT_MODE.to_string()),
            fext: fext.unwrap_or_else(|| Self::DEFAULT_FEXT.to_string()),
            file: None,
            opened: false,
            _temp_dir: None,
        };

        if reopen.unwrap_or(true) {
            filer.reopen(
                None,
                None,
                None,
                clear.unwrap_or(false),
                reuse.unwrap_or(false),
                clean.unwrap_or(false),
                None,
                None,
            )?;
        }

        Ok(filer)
    }

    /// Open if closed or close and reopen if opened or create and open if not
    ///
    /// # Arguments
    /// * `temp` - Optional temp mode override
    /// * `head_dir_path` - Optional head directory pathname override
    /// * `perm` - Optional permissions override
    /// * `clear` - True means remove directory upon close
    /// * `reuse` - True means reuse self.path if already exists
    /// * `clean` - True means path uses clean tail variant
    /// * `mode` - Optional file open mode override
    /// * `fext` - Optional file extension override
    pub fn reopen(
        &mut self,
        temp: Option<bool>,
        head_dir_path: Option<PathBuf>,
        perm: Option<u32>,
        clear: bool,
        reuse: bool,
        clean: bool,
        mode: Option<String>,
        fext: Option<String>,
    ) -> Result<bool, HioError> {
        self.close(clear)?;

        // Update parameters if provided
        if let Some(temp) = temp {
            self.temp = temp;
        }
        if let Some(head_dir_path) = head_dir_path {
            self.head_dir_path = head_dir_path;
        }
        if let Some(perm) = perm {
            self.perm = perm;
        }
        if let Some(mode) = mode {
            self.mode = mode;
        }
        if let Some(fext) = fext {
            self.fext = fext;
        }

        let should_remake = self.path.is_none() || !self.path.as_ref().unwrap().exists() || !reuse;

        if should_remake {
            let (path, file, temp_dir) = self.remake(
                &self.name.clone(),
                &self.base.clone(),
                Some(self.temp),
                Some(self.head_dir_path.clone()),
                Some(self.perm),
                clean,
                self.filed,
                self.extensioned,
                Some(self.mode.clone()),
                Some(self.fext.clone()),
            )?;

            self.path = Some(path);
            self.file = file;
            self._temp_dir = temp_dir;
        } else if self.filed && self.path.is_some() {
            // File exists, just open it
            let path = self.path.as_ref().unwrap();
            let file = ocfn(
                path,
                self.mode.contains('r'),
                self.mode.contains('w') || self.mode.contains('+'),
                self.mode.contains('a'),
                self.mode.contains('w') && !self.mode.contains('+'),
                true,
                false,
                self.perm,
            )?;
            self.file = Some(file);
        }

        self.opened = if !self.filed {
            true
        } else {
            self.file.is_some()
        };

        Ok(self.opened)
    }

    /// Make and return (path, file, temp_dir) by opening or creating directory or file at path
    #[allow(clippy::too_many_arguments)]
    pub fn remake(
        &self,
        name: &str,
        base: &str,
        temp: Option<bool>,
        head_dir_path: Option<PathBuf>,
        perm: Option<u32>,
        clean: bool,
        filed: bool,
        extensioned: bool,
        mode: Option<String>,
        fext: Option<String>,
    ) -> Result<(PathBuf, Option<File>, Option<TempDir>), HioError> {
        // Validate relative paths
        if Path::new(name).is_absolute() {
            return Err(HioError::FilerError(format!(
                "Not relative name path: {}",
                name
            )));
        }
        if !base.is_empty() && Path::new(base).is_absolute() {
            return Err(HioError::FilerError(format!(
                "Not relative base path: {}",
                base
            )));
        }

        let temp = temp.unwrap_or(false);
        let head_dir_path = head_dir_path.unwrap_or_else(|| self.head_dir_path.clone());
        let perm = perm.unwrap_or(self.perm);
        let mode = mode.unwrap_or_else(|| self.mode.clone());
        let fext = fext.unwrap_or_else(|| self.fext.clone());

        let tail_dir_path = if clean {
            &self.clean_tail_dir_path
        } else {
            &self.tail_dir_path
        };

        let alt_tail_dir_path = if clean {
            &self.alt_clean_tail_dir_path
        } else {
            &self.alt_tail_dir_path
        };

        // Add extension if needed
        let final_name = if filed || extensioned {
            let path = Path::new(name);
            if path.extension().is_none() {
                format!("{}.{}", name, fext)
            } else {
                name.to_string()
            }
        } else {
            name.to_string()
        };

        let mut temp_dir_holder = None;
        let mut file = None;

        let path = if temp {
            // Create temporary directory
            let temp_dir = tempfile::Builder::new()
                .prefix(&self.temp_prefix)
                .suffix(&self.temp_suffix)
                .tempdir()
                .map_err(HioError::IoError)?;

            let temp_path = temp_dir
                .path()
                .join(tail_dir_path)
                .join(base)
                .join(&final_name);

            // Handle clean option for temp
            if clean && temp_path.exists() {
                if temp_path.is_file() {
                    if filed || extensioned {
                        fs::remove_file(&temp_path).map_err(HioError::IoError)?;
                    } else if let Some(parent) = temp_path.parent() {
                        fs::remove_dir_all(parent).map_err(HioError::IoError)?;
                    }
                } else {
                    fs::remove_dir_all(&temp_path).map_err(HioError::IoError)?;
                }
            }

            // Create directory structure and file if needed
            if filed || extensioned {
                if let Some(parent) = temp_path.parent() {
                    DirBuilder::new()
                        .mode(perm)
                        .recursive(true)
                        .create(parent)
                        .map_err(HioError::IoError)?;
                }
                if filed {
                    file = Some(ocfn(
                        &temp_path,
                        mode.contains('r'),
                        mode.contains('w') || mode.contains('+'),
                        mode.contains('a'),
                        mode.contains('w') && !mode.contains('+'),
                        true,
                        false,
                        perm,
                    )?);
                }
            } else {
                DirBuilder::new()
                    .mode(perm)
                    .recursive(true)
                    .create(&temp_path)
                    .map_err(HioError::IoError)?;
            }

            temp_dir_holder = Some(temp_dir);
            temp_path
        } else {
            // Persistent directory
            let mut persistent_path = head_dir_path
                .join(tail_dir_path)
                .join(base)
                .join(&final_name);

            // Handle clean option
            if clean && persistent_path.exists() {
                if persistent_path.is_file() {
                    if filed {
                        fs::remove_file(&persistent_path).map_err(HioError::IoError)?;
                    } else if let Some(parent) = persistent_path.parent() {
                        fs::remove_dir_all(parent).map_err(HioError::IoError)?;
                    }
                } else {
                    fs::remove_dir_all(&persistent_path).map_err(HioError::IoError)?;
                }
            }

            // Try to create at primary path, fall back to alt if needed
            let result = self.try_create_path(&persistent_path, filed, extensioned, &mode, perm);

            match result {
                Ok(f) => {
                    file = f;
                }
                Err(_) => {
                    // Fall back to alternative path
                    persistent_path = self
                        .alt_head_dir_path
                        .join(alt_tail_dir_path)
                        .join(base)
                        .join(&final_name);

                    file =
                        self.try_create_path(&persistent_path, filed, extensioned, &mode, perm)?;
                }
            }

            // Set permissions on the final path
            if !extensioned {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(perm);
                    fs::set_permissions(&persistent_path, perms).map_err(HioError::IoError)?;
                }
            }

            persistent_path
        };

        Ok((path, file, temp_dir_holder))
    }

    /// Helper method to try creating path with fallback logic
    fn try_create_path(
        &self,
        path: &Path,
        filed: bool,
        extensioned: bool,
        mode: &str,
        perm: u32,
    ) -> Result<Option<File>, HioError> {
        if !path.exists() {
            // Path doesn't exist, create it
            if filed || extensioned {
                if let Some(parent) = path.parent() {
                    DirBuilder::new()
                        .mode(perm)
                        .recursive(true)
                        .create(parent)
                        .map_err(HioError::IoError)?;
                }
                if filed {
                    let file = ocfn(
                        path,
                        mode.contains('r'),
                        mode.contains('w') || mode.contains('+'),
                        mode.contains('a'),
                        mode.contains('w') && !mode.contains('+'),
                        true,
                        false,
                        perm,
                    )?;
                    Ok(Some(file))
                } else {
                    Ok(None)
                }
            } else {
                DirBuilder::new()
                    .mode(perm)
                    .recursive(true)
                    .create(path)
                    .map_err(HioError::IoError)?;
                Ok(None)
            }
        } else {
            // Path exists, check access and open file if needed
            if filed {
                let file = ocfn(
                    path,
                    mode.contains('r'),
                    mode.contains('w') || mode.contains('+'),
                    mode.contains('a'),
                    mode.contains('w') && !mode.contains('+'),
                    true,
                    false,
                    perm,
                )?;
                Ok(Some(file))
            } else {
                Ok(None)
            }
        }
    }

    /// Check if path exists for a given set of parameters
    pub fn exists(
        &self,
        name: &str,
        base: &str,
        head_dir_path: Option<&Path>,
        clean: bool,
        filed: bool,
        extensioned: bool,
        fext: Option<&str>,
    ) -> Result<bool, HioError> {
        // Validate relative paths
        if Path::new(name).is_absolute() {
            return Err(HioError::FilerError(format!(
                "Not relative name path: {}",
                name
            )));
        }
        if !base.is_empty() && Path::new(base).is_absolute() {
            return Err(HioError::FilerError(format!(
                "Not relative base path: {}",
                base
            )));
        }

        let head_dir_path = head_dir_path.unwrap_or(&self.head_dir_path);
        let fext = fext.unwrap_or(&self.fext);

        let tail_dir_path = if clean {
            &self.clean_tail_dir_path
        } else {
            &self.tail_dir_path
        };

        let alt_tail_dir_path = if clean {
            &self.alt_clean_tail_dir_path
        } else {
            &self.alt_tail_dir_path
        };

        // Add extension if needed
        let final_name = if filed || extensioned {
            let path = Path::new(name);
            if path.extension().is_none() {
                format!("{}.{}", name, fext)
            } else {
                name.to_string()
            }
        } else {
            name.to_string()
        };

        // Check primary path
        let primary_path = head_dir_path
            .join(tail_dir_path)
            .join(base)
            .join(&final_name);

        if primary_path.exists() {
            return Ok(true);
        }

        // Check alternative path
        let alt_path = self
            .alt_head_dir_path
            .join(alt_tail_dir_path)
            .join(base)
            .join(&final_name);

        Ok(alt_path.exists())
    }

    /// Close file if any and optionally remove directory or file at path
    pub fn close(&mut self, clear: bool) -> Result<bool, HioError> {
        // Close file if open
        if self.file.is_some() {
            self.file = None; // File is automatically closed when dropped
        }
        self.opened = false;

        if clear {
            self.clear_path()?;
        }

        Ok(!self.opened) // True means closed
    }

    /// Remove directory/file at end of path
    fn clear_path(&mut self) -> Result<(), HioError> {
        if let Some(path) = &self.path {
            if path.exists() {
                if path.is_file() {
                    // Remove file
                    fs::remove_file(path).map_err(HioError::IoError)?;
                    self.file = None;

                    // If temp, also remove parent directory
                    if self.temp {
                        if let Some(parent) = path.parent() {
                            fs::remove_dir_all(parent).map_err(HioError::IoError)?;
                        }
                    }
                } else if self.extensioned {
                    // Path end has file extension, remove as file
                    fs::remove_file(path).map_err(HioError::IoError)?;

                    // If temp, also remove parent directory
                    if self.temp {
                        if let Some(parent) = path.parent() {
                            fs::remove_dir_all(parent).map_err(HioError::IoError)?;
                        }
                    }
                } else {
                    // Remove directory and all contents
                    fs::remove_dir_all(path).map_err(HioError::IoError)?;
                }
            }
        }

        // Clear temp directory holder to allow cleanup
        self._temp_dir = None;
        Ok(())
    }
}

impl Drop for Filer {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        let _ = self.close(self.temp);
    }
}

// Simple context manager - no builder needed
pub struct FilerContext {
    pub filer: Filer,
    clear_on_drop: bool,
}

impl FilerContext {
    pub fn new(filer: Filer, clear: bool) -> Self {
        let clear_on_drop = filer.temp || clear;
        Self {
            filer,
            clear_on_drop,
        }
    }
}

impl Drop for FilerContext {
    fn drop(&mut self) {
        let _ = self.filer.close(self.clear_on_drop);
    }
}

impl std::ops::Deref for FilerContext {
    type Target = Filer;
    fn deref(&self) -> &Self::Target {
        &self.filer
    }
}

impl std::ops::DerefMut for FilerContext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.filer
    }
}

pub fn open_filer(
    name: Option<String>,
    temp: Option<bool>,
    reopen: Option<bool>,
    clear: Option<bool>,
) -> Result<FilerContext, HioError> {
    let name = name.unwrap_or_else(|| "test".to_string());
    let temp = temp.unwrap_or(true);
    let reopen = reopen.unwrap_or(true);
    let clear = clear.unwrap_or(false);

    let filer = Filer::new(
        Some(name),   // name
        None,         // base
        Some(temp),   // temp - this is the key fix
        None,         // head_dir_path
        None,         // perm
        Some(reopen), // reopen
        Some(clear),  // clear
        None,         // reuse
        None,         // clean
        None,         // filed
        None,         // extensioned
        None,         // mode
        None,         // fext
    )?;

    Ok(FilerContext::new(filer, clear))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::sync::Mutex;

    // Force tests to run sequentially to avoid race conditions
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn cleanup_all_test_dirs() {
        // Clean up ALL possible test directories more thoroughly
        let dirs_to_clean = vec![
            "/usr/local/var/hio", // Clean entire hio directory
            "/usr/local/var/hio/test",
            "/usr/local/var/hio/clean",
            "/usr/local/var/hio/clean/test",
            "/usr/local/var/hio/conf",
            "/usr/local/var/hio/conf/test.text",
        ];

        for dir in dirs_to_clean {
            let path = PathBuf::from(dir);
            if path.exists() {
                if path.is_file() {
                    let _ = fs::remove_file(&path);
                } else {
                    let _ = fs::remove_dir_all(&path);
                }
            }
        }

        if let Some(home) = dirs::home_dir() {
            let alt_dirs = vec![
                home.join(".hio"), // Clean entire .hio directory
                home.join(".hio/test"),
                home.join(".hio/clean"),
                home.join(".hio/clean/test"),
                home.join(".hio/conf"),
                home.join(".hio/conf/test.text"),
            ];

            for dir in alt_dirs {
                if dir.exists() {
                    if dir.is_file() {
                        let _ = fs::remove_file(&dir);
                    } else {
                        let _ = fs::remove_dir_all(&dir);
                    }
                }
            }
        }

        // Small delay to ensure filesystem operations complete
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    #[test]
    fn test_filing() -> Result<(), HioError> {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup_all_test_dirs();

        // Test basic directory creation
        let exists_before = {
            let filer = Filer::new(
                Some("test".to_string()),
                None,
                None,
                None,
                None,
                Some(false), // reopen=false
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )?;
            filer.exists("test", "", None, false, false, false, None)?
        };
        assert!(!exists_before);

        // Test with reopen=true (default)
        let mut filer = Filer::new(
            Some("test".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        assert!(filer.exists("test", "", None, false, false, false, None)?);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/test"));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_none());

        filer.close(false)?;
        assert!(!filer.opened);

        // Verify path exists after close
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen without reuse (remake)
        filer.reopen(None, None, None, false, false, false, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen with reuse=true
        filer.reopen(None, None, None, false, true, false, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen with reuse=true, clear=true (should remake even with reuse)
        filer.reopen(None, None, None, true, true, false, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen with clear=true (should remake)
        filer.reopen(None, None, None, true, false, false, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test close with clear=true
        let path_before_clear = filer.path.clone();
        filer.close(true)?;
        assert!(!path_before_clear.unwrap().exists());

        cleanup_all_test_dirs();
        Ok(())
    }

    #[test]
    fn test_filing_clean() -> Result<(), HioError> {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup_all_test_dirs();

        // Test clean path variant
        let exists_before = {
            let filer = Filer::new(
                Some("test".to_string()),
                None,
                None,
                None,
                None,
                Some(false), // reopen=false
                None,
                None,
                Some(true), // clean=true
                None,
                None,
                None,
                None,
            )?;
            filer.exists("test", "", None, true, false, false, None)?
        };
        assert!(!exists_before);

        let mut filer = Filer::new(
            Some("test".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true), // clean=true
            None,
            None,
            None,
            None,
        )?;

        assert!(filer.exists("test", "", None, true, false, false, None)?);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/clean/test"));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_none());

        filer.close(false)?;
        assert!(!filer.opened);

        // Test various reopen scenarios with clean=true
        filer.reopen(None, None, None, false, false, true, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/clean/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, false, true, true, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/clean/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, true, true, true, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/clean/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, true, false, true, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/clean/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.close(true)?;
        assert!(!filer.path.as_ref().unwrap().exists());

        cleanup_all_test_dirs();
        Ok(())
    }

    #[test]
    fn test_filing_alt_path() -> Result<(), HioError> {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup_all_test_dirs();

        // Test with alt path by using a restricted head directory
        let restricted_head = PathBuf::from("/root/hio/hio");

        let exists_before = {
            let filer = Filer::new(
                Some("test".to_string()),
                None,
                None,
                Some(restricted_head.clone()),
                None,
                Some(false), // reopen=false
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )?;
            filer.exists(
                "test",
                "",
                Some(&restricted_head),
                false,
                false,
                false,
                None,
            )?
        };
        assert!(!exists_before);

        let mut filer = Filer::new(
            Some("test".to_string()),
            None,
            None,
            Some(restricted_head.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        assert!(filer.exists(
            "test",
            "",
            Some(&restricted_head),
            false,
            false,
            false,
            None
        )?);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/test"));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_none());

        filer.close(false)?;
        assert!(!filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test various reopen scenarios with alt path
        filer.reopen(None, None, None, false, false, false, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, false, true, false, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, true, true, false, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, true, false, false, None, None)?;
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/test"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.close(true)?;
        assert!(!filer.path.as_ref().unwrap().exists());

        cleanup_all_test_dirs();
        Ok(())
    }

    #[test]
    fn test_filing_with_file() -> Result<(), HioError> {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup_all_test_dirs();

        // Test Filer with file not dir
        let exists_before = {
            let filer = Filer::new(
                Some("test".to_string()),
                Some("conf".to_string()),
                None,
                None,
                None,
                Some(false), // reopen=false
                None,
                None,
                None,
                Some(true), // filed=true
                None,
                None,
                None,
            )?;
            filer.exists("test", "conf", None, false, true, false, None)?
        };
        assert!(!exists_before);

        let mut filer = Filer::new(
            Some("test".to_string()),
            Some("conf".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true), // filed=true
            None,
            None,
            None,
        )?;

        assert!(filer.exists("test", "conf", None, false, true, false, None)?);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/conf/test.text"));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_some());

        // Test file operations
        if let Some(ref mut file) = filer.file {
            let msg = "Hello Jim\n";
            let bytes_written = file.write(msg.as_bytes())?;
            assert_eq!(bytes_written, msg.len());

            file.seek(SeekFrom::Start(0))?;
            let mut buffer = String::new();
            file.read_to_string(&mut buffer)?;
            assert_eq!(buffer, msg);
        }

        filer.close(false)?;
        assert!(!filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen scenarios with file
        filer.reopen(None, None, None, false, false, false, None, None)?;
        assert!(filer.opened);
        assert!(filer.file.is_some());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, false, true, false, None, None)?;
        assert!(filer.opened);
        assert!(filer.file.is_some());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, true, true, false, None, None)?;
        assert!(filer.opened);
        assert!(filer.file.is_some());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, true, false, false, None, None)?;
        assert!(filer.opened);
        assert!(filer.file.is_some());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.close(true)?;
        assert!(!filer.path.as_ref().unwrap().exists());

        cleanup_all_test_dirs();
        Ok(())
    }

    #[test]
    fn test_filing_with_file_alt_path() -> Result<(), HioError> {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup_all_test_dirs();

        // Test Filer with file not dir and with Alt path
        let restricted_head = PathBuf::from("/root/hio");

        let exists_before = {
            let filer = Filer::new(
                Some("test".to_string()),
                Some("conf".to_string()),
                None,
                Some(restricted_head.clone()),
                None,
                Some(false), // reopen=false
                None,
                None,
                None,
                Some(true), // filed=true
                None,
                None,
                None,
            )?;
            filer.exists(
                "test",
                "conf",
                Some(&restricted_head),
                false,
                true,
                false,
                None,
            )?
        };
        assert!(!exists_before);

        let mut filer = Filer::new(
            Some("test".to_string()),
            Some("conf".to_string()),
            None,
            Some(restricted_head.clone()),
            None,
            None,
            None,
            None,
            None,
            Some(true), // filed=true
            None,
            None,
            None,
        )?;

        assert!(filer.exists(
            "test",
            "conf",
            Some(&restricted_head),
            false,
            true,
            false,
            None
        )?);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/conf/test.text"));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_some());

        // Test file operations
        if let Some(ref mut file) = filer.file {
            let msg = "Hello Jim\n";
            let bytes_written = file.write(msg.as_bytes())?;
            assert_eq!(bytes_written, msg.len());

            file.seek(SeekFrom::Start(0))?;
            let mut buffer = String::new();
            file.read_to_string(&mut buffer)?;
            assert_eq!(buffer, msg);
        }

        filer.close(false)?;
        assert!(!filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen scenarios
        filer.reopen(None, None, None, false, false, false, None, None)?;
        assert!(filer.opened);
        assert!(filer.file.is_some());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, false, true, false, None, None)?;
        assert!(filer.opened);
        assert!(filer.file.is_some());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, true, true, false, None, None)?;
        assert!(filer.opened);
        assert!(filer.file.is_some());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.reopen(None, None, None, true, false, false, None, None)?;
        assert!(filer.opened);
        assert!(filer.file.is_some());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".hio/conf/test.text"));
        assert!(filer.path.as_ref().unwrap().exists());

        filer.close(true)?;
        assert!(!filer.path.as_ref().unwrap().exists());

        cleanup_all_test_dirs();
        Ok(())
    }

    #[test]
    fn test_open_filer_context() -> Result<(), HioError> {
        let _guard = TEST_MUTEX.lock().unwrap();

        // Test open_filer with defaults (temp=true)
        let temp_path = {
            let filer_ctx = open_filer(None, None, None, None)?;

            // Check temp directory structure
            let path_str = filer_ctx.path.as_ref().unwrap().to_string_lossy();
            assert!(path_str.contains("hio_"));
            assert!(path_str.contains("_test/hio/test"));
            assert!(filer_ctx.opened);
            assert!(filer_ctx.path.as_ref().unwrap().exists());
            assert!(filer_ctx.file.is_none());

            filer_ctx.path.clone()
        }; // filer_ctx is dropped here, should clear temp files

        Ok(())
    }

    #[test]
    fn test_open_filer_context_filed() -> Result<(), HioError> {
        let _guard = TEST_MUTEX.lock().unwrap();

        // Test open_filer with filed=true but temp=true
        let filer = Filer::new(
            Some("test".to_string()),
            None,       // base
            Some(true), // temp=true
            None,       // head_dir_path
            None,       // perm
            None,       // reopen (default true)
            None,       // clear
            None,       // reuse
            None,       // clean
            Some(true), // filed=true
            None,       // extensioned
            None,       // mode
            None,       // fext
        )?;

        let filer_ctx = FilerContext::new(filer, false);

        let path_str = filer_ctx.path.as_ref().unwrap().to_string_lossy();

        // More flexible assertions for temp directories
        assert!(filer_ctx.temp, "Should be using temp directory");
        assert!(path_str.contains("test.text"), "Should end with test.text");
        assert!(filer_ctx.opened);
        assert!(filer_ctx.path.as_ref().unwrap().exists());
        assert!(filer_ctx.file.is_some());

        Ok(())
    }

    #[test]
    fn test_bad_file_paths() {
        let _guard = TEST_MUTEX.lock().unwrap();

        // Test absolute name path (should fail)
        let result = Filer::new(
            Some("/test".to_string()),
            Some("conf".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true), // filed=true
            None,
            None,
            None,
        );
        assert!(matches!(result, Err(HioError::FilerError(_))));

        // Test absolute base path (should fail)
        let result = Filer::new(
            Some("test".to_string()),
            Some("/conf".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true), // filed=true
            None,
            None,
            None,
        );
        assert!(matches!(result, Err(HioError::FilerError(_))));
    }

    #[test]
    fn test_filer_extension_handling() -> Result<(), HioError> {
        let _guard = TEST_MUTEX.lock().unwrap();

        // Test that extension is added when filed=true and no extension provided
        let filer = Filer::new(
            Some("testfile".to_string()), // no extension
            None,
            Some(true), // temp=true
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true), // filed=true
            None,
            None,
            Some("dat".to_string()), // custom extension
        )?;

        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .ends_with("testfile.dat"));
        assert!(filer.opened);
        assert!(filer.file.is_some());

        Ok(())
    }

    #[test]
    fn test_filer_with_existing_extension() -> Result<(), HioError> {
        let _guard = TEST_MUTEX.lock().unwrap();

        // Test that existing extension is preserved
        let filer = Filer::new(
            Some("testfile.json".to_string()), // has extension
            None,
            Some(true), // temp=true
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true), // filed=true
            None,
            None,
            Some("dat".to_string()), // different extension - should be ignored
        )?;

        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .ends_with("testfile.json"));
        assert!(filer.opened);
        assert!(filer.file.is_some());

        Ok(())
    }
}
