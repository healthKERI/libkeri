use crate::keri::core::errors::CoreError;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::Builder;

/// Manages file directories and files for KERI installation resources like databases and configuration files.
///
/// Filer instances handle the creation and management of directories and files using configurable
/// paths and permissions to store KERI-specific resources.
pub struct BaseFiler {
    /// Unique path component used in directory or file path name
    name: String,

    /// Another unique path component inserted before name
    base: String,

    /// True means use temporary directory in /tmp
    temp: bool,

    /// Head directory path
    head_dir_path: PathBuf,

    /// Full directory or file path once created else None
    path: Option<PathBuf>,

    /// Octal OS permissions for path directory and/or file
    perm: u32,

    /// True means path ends in file, False means path ends in directory
    filed: bool,

    /// When not filed: True means ensure path ends with extension, False otherwise
    extensioned: bool,

    /// File open mode if filed
    mode: String,

    /// File extension if filed
    fext: String,

    /// File instance when filed and created
    file: Option<File>,

    /// True means directory created and if filed then file is opened
    opened: bool,

    defaults: FilerDefaults,
}

#[allow(dead_code)]
impl BaseFiler {
    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn base(&self) -> String {
        self.base.clone()
    }

    pub fn path(&self) -> Option<PathBuf> {
        self.path.clone()
    }

    pub fn temp(&self) -> bool {
        self.temp
    }

    pub fn filed(&self) -> bool {
        self.filed
    }

    pub fn opened(&self) -> bool {
        self.opened
    }

    pub(crate) fn set_opened(&mut self, opened: bool) {
        self.opened = opened;
    }

    pub fn extensioned(&self) -> bool {
        self.extensioned
    }

    pub fn perm(&self) -> u32 {
        self.perm
    }
}

impl Default for BaseFiler {
    fn default() -> Self {
        Self {
            name: String::from("main"),
            base: String::from(""),
            temp: false,
            head_dir_path: PathBuf::from(Self::HEAD_DIR_PATH),
            path: None,
            perm: Self::PERM,
            filed: false,
            extensioned: false,
            mode: Self::MODE.to_string(),
            fext: Self::FEXT.to_string(),
            file: None,
            opened: false,
            defaults: FilerDefaults::default(),
        }
    }
}

pub struct FilerDefaults {
    pub head_dir_path: &'static str,
    pub tail_dir_path: &'static str,
    pub clean_tail_dir_path: &'static str,
    pub alt_head_dir_path: &'static str,
    pub alt_tail_dir_path: &'static str,
    pub alt_clean_tail_dir_path: &'static str,
    pub temp_head_dir: &'static str,
    pub temp_prefix: &'static str,
    pub temp_suffix: &'static str,
    pub perm: u32,
    pub mode: &'static str,
    pub fext: &'static str,
}

impl Default for FilerDefaults {
    fn default() -> Self {
        Self {
            head_dir_path: <BaseFiler as Filer>::HEAD_DIR_PATH,
            tail_dir_path: <BaseFiler as Filer>::TAIL_DIR_PATH,
            clean_tail_dir_path: <BaseFiler as Filer>::CLEAN_TAIL_DIR_PATH,
            alt_head_dir_path: "~",
            alt_tail_dir_path: <BaseFiler as Filer>::ALT_TAIL_DIR_PATH,
            alt_clean_tail_dir_path: <BaseFiler as Filer>::ALT_CLEAN_TAIL_DIR_PATH,
            temp_head_dir: <BaseFiler as Filer>::TEMP_HEAD_DIR,
            temp_prefix: <BaseFiler as Filer>::TEMP_PREFIX,
            temp_suffix: "_test",
            perm: <BaseFiler as Filer>::PERM,
            mode: <BaseFiler as Filer>::MODE,
            fext: <BaseFiler as Filer>::FEXT,
        }
    }
}

#[allow(dead_code)]
pub trait Filer {
    fn defaults() -> FilerDefaults {
        FilerDefaults::default()
    }

    // Class constants (static members in Rust)
    /// Default absolute directory path head such as "/usr/local/var"
    const HEAD_DIR_PATH: &'static str = "/usr/local/var";

    /// Default relative directory path tail when using head
    const TAIL_DIR_PATH: &'static str = "keri";

    /// Default relative directory path tail when creating clean
    const CLEAN_TAIL_DIR_PATH: &'static str = "keri/clean";

    /// Default alternative relative directory path tail as fallback
    const ALT_TAIL_DIR_PATH: &'static str = ".keri";

    /// Default alternative relative path tail when creating clean
    const ALT_CLEAN_TAIL_DIR_PATH: &'static str = ".keri/clean";

    /// Default relative directory path prefix when using temp head
    const TEMP_PREFIX: &'static str = "keri_";

    /// Default relative directory path prefix when using temp head
    const TEMP_HEAD_DIR: &'static str = "/tmp";

    /// Explicit default octal permissions such as 0o1700
    const PERM: u32 = 0o1700;

    /// Open mode such as "r+"
    const MODE: &'static str = "r+";

    /// Default file extension such as "text" for "fname.text"
    const FEXT: &'static str = "text";
}

impl Filer for BaseFiler {}

#[allow(dead_code)]
impl BaseFiler {
    /// Create a new Filer instance.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique identifier of file or directory
    /// * `base` - Optional directory path segment inserted before name
    /// * `temp` - If true, open in temporary directory, clear on close
    /// * `head_dir_path` - Optional head directory pathname for main database
    /// * `perm` - Optional numeric os dir permissions for database
    /// * `reopen` - If true, (re)open with this init
    /// * `clear` - If true, remove directory upon close when reopening
    /// * `reuse` - If true, reuse path if already exists
    /// * `clean` - If true, path uses clean tail variant
    /// * `filed` - If true, path is file path not directory path
    /// * `extensioned` - When not filed, if true, ensure path ends with fext
    /// * `mode` - File open mode when filed
    /// * `fext` - File extension when filed or extensioned
    ///
    /// # Returns
    ///
    /// * Result containing a new Filer instance or an error
    pub fn new<S1, S2>(
        name: S1,
        base: S2,
        temp: bool,
        head_dir_path: Option<PathBuf>,
        perm: Option<u32>,
        reopen: bool,
        clear: bool,
        reuse: bool,
        clean: bool,
        filed: bool,
        extensioned: bool,
        mode: Option<String>,
        fext: Option<String>,
        defaults: Option<FilerDefaults>,
    ) -> Result<Self, CoreError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        let name = name.into();
        let base = base.into();

        // Ensure relative path parts are relative
        if Path::new(&name).is_absolute() {
            return Err(CoreError::FilerError(format!(
                "Not relative name={} path.",
                name
            )));
        }

        if Path::new(&base).is_absolute() {
            return Err(CoreError::FilerError(format!(
                "Not relative base={} path.",
                base
            )));
        }

        let defaults = defaults.unwrap_or_default();

        let head_dir_path = head_dir_path.unwrap_or_else(|| PathBuf::from(defaults.head_dir_path));
        let perm = perm.unwrap_or(defaults.perm);
        let mode = mode.unwrap_or_else(|| defaults.mode.to_string());
        let fext = fext.unwrap_or_else(|| defaults.fext.to_string());

        let mut filer = Self {
            name,
            base,
            temp,
            head_dir_path,
            path: None,
            perm,
            filed,
            extensioned,
            mode,
            fext,
            file: None,
            opened: false,
            defaults,
        };

        if reopen {
            filer.reopen(
                Some(temp),
                None,
                Some(perm),
                clear,
                reuse,
                clean,
                None,
                None,
            )?;
        }

        Ok(filer)
    }

    /// Open if closed or close and reopen if opened or create and open if not
    ///
    /// # Arguments
    ///
    /// * `temp` - If provided, set the temp flag
    /// * `head_dir_path` - If provided, set the head directory path
    /// * `perm` - If provided, set the permissions
    /// * `clear` - If true, remove directory upon close
    /// * `reuse` - If true, reuse self.path if already exists
    /// * `clean` - If true, path uses clean tail variant
    /// * `mode` - If provided, set the file open mode when filed
    /// * `fext` - If provided, set the file extension when filed
    ///
    /// # Returns
    ///
    /// * Result<bool> where true means opened, false means closed
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
    ) -> Result<bool, CoreError> {
        // Close first (with clearing if requested)
        self.close(clear)?;

        // Update Filer properties if values are provided
        if let Some(t) = temp {
            self.temp = t;
        }

        if let Some(path) = head_dir_path {
            self.head_dir_path = path;
        }

        if let Some(p) = perm {
            self.perm = p;
        }

        if let Some(m) = mode {
            self.mode = m;
        }

        if let Some(ext) = fext {
            self.fext = ext;
        }

        // Check if we need to create or remake the path
        let path_needs_remake =
            self.path.is_none() || !self.path.as_ref().map_or(false, |p| p.exists()) || !reuse;

        if path_needs_remake {
            // Remake the path and potentially file
            let result = self.remake(
                &self.name,
                &self.base,
                Some(self.temp),
                Some(&self.head_dir_path),
                Some(self.perm),
                clean,
                self.filed,
                self.extensioned,
                Some(&self.mode),
                Some(&self.fext),
            )?;

            self.path = Some(result.0);
            self.file = result.1;
        } else if self.filed {
            // Assumes directory in self.path exists
            // Open the file with the specified mode
            if let Some(path) = &self.path {
                self.file = Some(self.open_file_with_perms(path, &self.mode, self.perm)?);
            }
        }

        // Update opened state based on filed status
        if !self.filed {
            self.opened = true;
        } else {
            self.opened = self.file.is_some();
        }

        Ok(self.opened)
    }

    /// Makes and returns (path, file) by opening or creating and opening if not
    /// preexistent, directory or file at path
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name alias portion of path
    /// * `base` - Optional base inserted before name in path
    /// * `temp` - Optional temp flag:
    ///     - None means ignore
    ///     - Some(true) means open temporary directory, may clear on close
    ///     - Some(false) means open persistent directory, may not clear on close
    /// * `head_dir_path` - Optional head directory pathname of main database
    /// * `perm` - Directory or file permissions
    /// * `clean` - True means make path for cleaned version and remove
    ///             old directory or file at clean path if any.
    /// * `filed` - True means path is file path not directory path
    /// * `extensioned` - When not filed:
    ///                  True means ensure path ends with fext
    ///                  False means do not ensure path ends with fext
    /// * `mode` - File open mode when filed, such as "w+"
    /// * `fext` - File extension when filed
    ///
    /// # Returns
    ///
    /// * Result containing a tuple with (PathBuf, Option<File>)
    pub fn remake(
        &self,
        name: &str,
        base: &str,
        temp: Option<bool>,
        head_dir_path: Option<&Path>,
        perm: Option<u32>,
        clean: bool,
        filed: bool,
        extensioned: bool,
        mode: Option<&str>,
        fext: Option<&str>,
    ) -> Result<(PathBuf, Option<File>), CoreError> {
        // Validate relative paths
        if Path::new(name).is_absolute() {
            return Err(CoreError::NotRelativePath(format!("name={}", name)));
        }

        if Path::new(base).is_absolute() {
            return Err(CoreError::NotRelativePath(format!("base={}", base)));
        }

        // Initialize with default values if not provided
        let temp = temp.unwrap_or(false);
        let head_dir_path = head_dir_path.unwrap_or_else(|| Path::new(self.defaults.head_dir_path));
        let perm = perm.unwrap_or(self.defaults.perm);
        let mode = mode.unwrap_or(self.defaults.mode);
        let fext = fext.unwrap_or(self.defaults.fext);

        // Determine the tail directory path based on clean flag
        let tail_dir_path = if clean {
            self.defaults.clean_tail_dir_path
        } else {
            self.defaults.tail_dir_path
        };

        let alt_tail_dir_path = if clean {
            self.defaults.alt_clean_tail_dir_path
        } else {
            self.defaults.alt_tail_dir_path
        };

        // Prepare the name with extension if needed
        let mut name_with_ext = name.to_string();
        if filed || extensioned {
            if !name.contains(&format!(".{}", fext)) {
                name_with_ext = format!("{}.{}", name, fext);
            }
        }

        if Path::new(&name_with_ext).is_absolute() {
            return Err(CoreError::NotRelativePath(format!(
                "name={}",
                name_with_ext
            )));
        }

        let mut file = None;
        let path: PathBuf;

        if temp {
            // Create temporary directory
            let temp_head_dir = Path::new(self.defaults.temp_head_dir);
            let temp_dir = create_temp_dir(
                self.defaults.temp_prefix,
                self.defaults.temp_suffix,
                Some(temp_head_dir),
            )
            .map_err(|e| CoreError::IoError(format!("Unable to create temp dir: {}", e)))?;

            let temp_path = temp_dir.path();

            path = temp_path
                .join(tail_dir_path)
                .join(base)
                .join(&name_with_ext);

            // Clean if requested
            if clean && path.exists() {
                if path.is_file() {
                    if filed || extensioned {
                        fs::remove_file(&path).map_err(|e| {
                            CoreError::IoError(format!("Unable to remove file: {}", e))
                        })?;
                    } else {
                        if let Some(parent) = path.parent() {
                            fs::remove_dir_all(parent).map_err(|e| {
                                CoreError::IoError(format!("Unable to remove all: {}", e))
                            })?;
                        }
                    }
                } else {
                    fs::remove_dir_all(&path).map_err(|e| {
                        CoreError::IoError(format!("Unable to remove all dir: {}", e))
                    })?;
                }
            }

            if filed || extensioned {
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        fs::create_dir_all(parent).map_err(|e| {
                            CoreError::IoError(format!("Unable to create all dir: {}", e))
                        })?;
                    }
                }

                if filed {
                    file = Some(self.open_file_with_perms(&path, mode, perm)?);
                }
            } else {
                fs::create_dir_all(&path)
                    .map_err(|e| CoreError::IoError(format!("Unable to create all dir: {}", e)))?;
            }
        } else {
            // Use regular directories
            let primary_path = PathBuf::from(head_dir_path)
                .join(tail_dir_path)
                .join(base)
                .join(&name_with_ext);

            // Expand user home directory if needed (e.g., "~")
            let primary_path = expand_user_path(&primary_path)?;

            // Clean if requested
            if clean && primary_path.exists() {
                if primary_path.is_file() {
                    if filed {
                        fs::remove_file(&primary_path).map_err(|e| {
                            CoreError::IoError(format!("Unable to remove file: {}", e))
                        })?;
                    } else {
                        if let Some(parent) = primary_path.parent() {
                            fs::remove_dir_all(parent).map_err(|e| {
                                CoreError::IoError(format!("Unable toremove all dir: {}", e))
                            })?;
                        }
                    }
                } else {
                    fs::remove_dir_all(&primary_path).map_err(|e| {
                        CoreError::IoError(format!("Unable to remove all dir: {}", e))
                    })?;
                }
            }

            // Try creating primary path
            let result = if !primary_path.exists() {
                if filed || extensioned {
                    if let Some(parent) = primary_path.parent() {
                        if !parent.exists() {
                            match fs::create_dir_all(parent) {
                                Ok(_) => Ok(primary_path),
                                Err(_) => {
                                    Err(CoreError::IoError("Unable to create dir".to_string()))
                                }
                            }
                        } else {
                            Ok(primary_path)
                        }
                    } else {
                        Ok(primary_path)
                    }
                } else {
                    match fs::create_dir_all(&primary_path) {
                        Ok(_) => Ok(primary_path),
                        Err(_) => Err(CoreError::IoError("Unable to create dir".to_string())),
                    }
                }
            } else {
                // Path exists, just check permissions
                if !has_full_access(&primary_path)? {
                    Err(CoreError::PermissionError(
                        "Full access denied to primary path".to_string(),
                    ))
                } else {
                    Ok(primary_path)
                }
            };

            // If primary path creation failed or doesn't have correct permissions, use alternative
            if result.is_err() {
                let alt_path = PathBuf::from(self.defaults.alt_head_dir_path)
                    .join(alt_tail_dir_path)
                    .join(base)
                    .join(&name_with_ext);

                // Expand user home directory if needed
                let alt_path = expand_user_path(&alt_path)?;

                if !alt_path.exists() {
                    if filed || extensioned {
                        if let Some(parent) = alt_path.parent() {
                            if !parent.exists() {
                                fs::create_dir_all(parent).map_err(|e| {
                                    CoreError::IoError(format!(
                                        "Unable to create parent dir: {}",
                                        e
                                    ))
                                })?;
                            }
                        }
                    } else {
                        fs::create_dir_all(&alt_path).map_err(|e| {
                            CoreError::IoError(format!("Unable to create all dir: {}", e))
                        })?;
                    }
                }

                if filed {
                    file = Some(self.open_file_with_perms(&alt_path, mode, perm)?);
                }

                path = alt_path;
            } else {
                // Primary path is good
                let result_path = result?;
                path = result_path;

                if filed {
                    file = Some(self.open_file_with_perms(&path, mode, perm)?);
                }
            }

            // Set permissions
            if !extensioned {
                fs::set_permissions(&path, fs::Permissions::from_mode(perm)).map_err(|e| {
                    CoreError::IoError(format!("Unable to set file permissions {}", e))
                })?;
            }
        }

        Ok((path, file))
    }

    /// Check if (path. file) exists for a given set of parameters for remake.
    /// Temp is not allowed.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name alias portion of path
    /// * `base` - Optional base inserted before name in path
    /// * `head_dir_path` - Optional head directory pathname of main database
    /// * `clean` - True means make path for cleaned version
    ///             False means make path normally (not clean)
    /// * `filed` - True means path is file path not directory path
    ///             False means path is directory path not file path
    /// * `extensioned` - When not filed:
    ///                   True means ensure path ends with fext
    ///                   False means do not ensure path ends with fext
    /// * `fext` - File extension when filed
    ///
    /// # Returns
    ///
    /// * Result containing a boolean:
    ///   - true means path or alt path exists
    ///   - false means neither exists
    pub fn exists(
        &self,
        name: &str,
        base: &str,
        head_dir_path: Option<&Path>,
        clean: bool,
        filed: bool,
        extensioned: bool,
        fext: Option<&str>,
    ) -> Result<bool, CoreError> {
        // Validate relative paths
        if Path::new(name).is_absolute() {
            return Err(CoreError::NotRelativePath(format!("name={}", name)));
        }

        if Path::new(base).is_absolute() {
            return Err(CoreError::NotRelativePath(format!("base={}", base)));
        }

        // Initialize with default values if not provided
        let head_dir_path = head_dir_path.unwrap_or_else(|| Path::new(self.defaults.head_dir_path));
        let fext = fext.unwrap_or(self.defaults.fext);

        // Determine the tail directory path based on clean flag
        let tail_dir_path = if clean {
            self.defaults.clean_tail_dir_path
        } else {
            self.defaults.tail_dir_path
        };

        let alt_tail_dir_path = if clean {
            self.defaults.alt_clean_tail_dir_path
        } else {
            self.defaults.alt_tail_dir_path
        };

        // Prepare the name with extension if needed
        let mut name_with_ext = name.to_string();
        if filed || extensioned {
            if !name.contains(&format!(".{}", fext)) {
                name_with_ext = format!("{}.{}", name, fext);
            }
        }

        if Path::new(&name_with_ext).is_absolute() {
            return Err(CoreError::NotRelativePath(format!(
                "name={}",
                name_with_ext
            )));
        }

        // Try the primary path first
        let primary_path = PathBuf::from(head_dir_path)
            .join(tail_dir_path)
            .join(base)
            .join(&name_with_ext);

        // Expand user home directory if needed (e.g., "~")
        let primary_path = expand_user_path(&primary_path)?;

        // Check if primary path exists
        if primary_path.exists() {
            return Ok(true);
        }

        // Check the alternative path
        let alt_path = PathBuf::from(self.defaults.alt_head_dir_path)
            .join(alt_tail_dir_path)
            .join(base)
            .join(&name_with_ext);

        // Expand user home directory if needed
        let alt_path = expand_user_path(&alt_path)?;

        // Return whether alt path exists
        Ok(alt_path.exists())
    }

    /// Close file if any and optionally remove directory or file at path
    ///
    /// # Arguments
    ///
    /// * `clear` - If true, remove the directory or file at path
    ///
    /// # Returns
    ///
    /// * Result<bool> where true means closed, false means still opened
    pub fn close(&mut self, clear: bool) -> Result<bool, CoreError> {
        // Close the file if it exists
        if let Some(file) = self.file.take() {
            drop(file); // Explicitly drop the file to close it
        }

        self.opened = false;

        // If clear is requested, remove the directory or file at path
        if clear {
            self.remove()?;
        }

        // Return not self.opened (true means closed, false means still opened)
        Ok(!self.opened)
    }

    // Helper method to remove the directory or file at path
    fn remove(&mut self) -> Result<(), CoreError> {
        if let Some(path) = &self.path {
            if path.exists() {
                if path.is_file() {
                    fs::remove_file(path)
                        .map_err(|e| CoreError::IoError(format!("Unable to remove file {}", e)))?;
                } else {
                    fs::remove_dir_all(path).map_err(|e| {
                        CoreError::IoError(format!("Unable to remove dir all {}", e))
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Remove directory/file at end of path
    ///
    /// This is an internal method that handles removing files or directories
    /// based on the Filer's configuration.
    fn clear_path(&mut self) -> Result<(), CoreError> {
        if let Some(path) = &self.path {
            if path.exists() {
                if path.is_file() {
                    // Remove only the file at the end of path
                    fs::remove_file(path)
                        .map_err(|e| CoreError::IoError(format!("Unable to remove file {}", e)))?;

                    // Clear the file reference
                    self.file = None;

                    // If temporary, remove the parent directory as well
                    if self.temp {
                        if let Some(parent) = path.parent() {
                            fs::remove_dir_all(parent).map_err(|e| {
                                CoreError::IoError(format!("Unable to remove all dir {}", e))
                            })?;
                        }
                    }
                } else if self.extensioned {
                    // Path end has file extension, so treat it as a file
                    fs::remove_file(path)
                        .map_err(|e| CoreError::IoError(format!("Unable to remove file {}", e)))?;

                    // If temporary, remove the parent directory as well
                    if self.temp {
                        if let Some(parent) = path.parent() {
                            fs::remove_dir_all(parent).map_err(|e| {
                                CoreError::IoError(format!("Unable to remove all dir parent {}", e))
                            })?;
                        }
                    }
                } else {
                    // Remove the directory and all contents
                    fs::remove_dir_all(path).map_err(|e| {
                        CoreError::IoError(format!("Unable to remove all dir path {}", e))
                    })?;
                }
            }
        }

        Ok(())
    }

    // Helper method to open a file with proper permissions
    fn open_file_with_perms(&self, path: &Path, mode: &str, perm: u32) -> Result<File, CoreError> {
        let file = OpenOptions::new()
            .read(mode.contains('r'))
            .write(mode.contains('w') || mode.contains('+'))
            .create(true)
            .open(path)
            .map_err(|e| CoreError::IoError(format!("Invalid permissiotns options {}", e)))?;

        fs::set_permissions(path, fs::Permissions::from_mode(perm))
            .map_err(|e| CoreError::IoError(format!("Unable to set permissions{}", e)))?;

        Ok(file)
    }

    /// Opens or creates the directory and/or file specified by this Filer
    pub fn open(&mut self) -> io::Result<()> {
        // Build the path based on the configuration
        self.build_path();

        if let Some(path) = &self.path {
            // Create parent directories with appropriate permissions
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, fs::Permissions::from_mode(self.perm))?;
            }

            if self.filed {
                // If this is a file, create/open it
                let file = OpenOptions::new()
                    .read(self.mode.contains("r"))
                    .write(self.mode.contains("w") || self.mode.contains("+"))
                    .create(true)
                    .open(path)?;

                // Set file permissions
                fs::set_permissions(path, fs::Permissions::from_mode(self.perm))?;

                self.file = Some(file);
            } else {
                // If this is a directory, ensure it exists
                fs::create_dir_all(path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(self.perm))?;
            }

            self.opened = true;
        }

        Ok(())
    }

    /// Builds the full path based on the current configuration
    fn build_path(&mut self) {
        let mut path = if self.temp {
            let mut p = PathBuf::from(self.defaults.temp_head_dir);
            p.push(format!(
                "{}{}{}",
                self.defaults.temp_prefix, self.name, self.defaults.temp_suffix
            ));
            p
        } else {
            let mut p = self.head_dir_path.clone();
            p.push(self.defaults.tail_dir_path);
            if !self.base.is_empty() {
                p.push(&self.base);
            }
            p.push(&self.name);
            p
        };

        // Add extension if needed
        if self.filed || self.extensioned {
            let mut file_name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            if !file_name.ends_with(&format!(".{}", self.fext)) {
                file_name = format!("{}.{}", file_name, self.fext);
                path.set_file_name(file_name);
            }
        }

        self.path = Some(path);
    }

    /// Returns the current path if set
    pub fn get_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns a reference to the file if opened
    pub fn get_file(&self) -> Option<&File> {
        self.file.as_ref()
    }

    /// Returns a mutable reference to the file if opened
    pub fn get_file_mut(&mut self) -> Option<&mut File> {
        self.file.as_mut()
    }
}

// Helper function to expand user's home directory (e.g., "~")
fn expand_user_path(path: &Path) -> Result<PathBuf, CoreError> {
    let path_str = path.to_string_lossy();

    if path_str.starts_with("~") {
        let home = dirs::home_dir()
            .ok_or_else(|| CoreError::OtherError("Could not find home directory".to_string()))?;

        let remainder = path_str.strip_prefix("~").unwrap();
        let remainder = if remainder.starts_with('/') {
            &remainder[1..]
        } else {
            remainder
        };

        Ok(home.join(remainder))
    } else {
        Ok(path.to_path_buf())
    }
}

// Helper function to check if we have full access to a path
fn has_full_access(path: &Path) -> Result<bool, CoreError> {
    let metadata = fs::metadata(path).map_err(|e| CoreError::IoError(e.to_string()))?;

    // Check if we have read/write access
    // This is a simplification; on Unix systems you'd use more specific permission checks
    Ok(metadata.permissions().mode() & 0o600 == 0o600)
}

fn create_temp_dir(
    prefix: &str,
    suffix: &str,
    temp_dir: Option<&Path>,
) -> io::Result<tempfile::TempDir> {
    let temp_path = temp_dir.unwrap_or_else(|| Path::new("/tmp"));
    Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .keep(true)
        .tempdir_in(temp_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};

    fn cleanup_test_dirs() {
        // Clean up standard test directory
        let dir_path = Path::new("/usr/local/var/hio/test");
        if dir_path.exists() {
            let _ = fs::remove_dir_all(dir_path);
        }

        // Clean up alt directory
        let home_dir = dirs::home_dir().unwrap();
        let alt_dir_path = home_dir.join(".hio").join("test");
        if alt_dir_path.exists() {
            let _ = fs::remove_dir_all(alt_dir_path);
        }
    }

    #[test]
    fn test_filing_basic() {
        cleanup_test_dirs();

        // Test with default reopen=false
        let filer = BaseFiler::new(
            "test", "", false, None, None, false, false, false, false, false, false, None, None,
            None,
        )
        .unwrap();
        assert!(!filer
            .exists("test", "", None, false, false, false, None)
            .unwrap());

        // Test with default reopen=true
        let mut filer = BaseFiler::new(
            "test", "", false, None, None, true, false, false, false, false, false, None, None,
            None,
        )
        .unwrap();
        assert!(filer
            .exists("test", "", None, false, false, false, None)
            .unwrap());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!("keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_none());

        let _ = filer.close(false);
        assert!(!filer.opened);

        // Check path normalization
        let norm_path_filer = filer.path.as_ref().unwrap().to_str().unwrap();
        // For Windows, we need to compare without drive letters
        let norm_path_filer = norm_path_filer.split(':').last().unwrap_or(norm_path_filer);
        assert!(norm_path_filer.ends_with(&format!("keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen with reuse=false (default)
        let mut filer = filer;
        let _ = filer.reopen(None, None, None, false, false, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!("keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen with reuse=true and clear=false
        let _ = filer.reopen(None, None, None, false, true, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!("keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen with reuse=true and clear=true
        let _ = filer.reopen(None, None, None, true, true, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!("keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test reopen with clear=true
        let _ = filer.reopen(None, None, None, true, false, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!("keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test close with clear=true
        let _ = filer.close(true);
        assert!(!filer.path.as_ref().unwrap().exists());
    }

    #[test]
    fn test_filing_clean() {
        cleanup_test_dirs();

        // Clean up clean directories
        let dir_path = Path::new("/usr/local/var/keri/clean/test");
        if dir_path.exists() {
            let _ = fs::remove_dir_all(dir_path);
        }

        let home_dir = dirs::home_dir().unwrap();
        let alt_dir_path = home_dir.join(".keri").join("clean").join("test");
        if alt_dir_path.exists() {
            let _ = fs::remove_dir_all(alt_dir_path);
        }

        // Test with clean=true and reopen=false
        let filer = BaseFiler::new(
            "test", "", false, None, None, false, false, false, true, false, false, None, None,
            None,
        )
        .unwrap();
        assert!(!filer
            .exists("test", "", None, true, false, false, None)
            .unwrap());

        // Test with clean=true and reopen=true
        let mut filer = BaseFiler::new(
            "test", "", false, None, None, true, false, false, true, false, false, None, None, None,
        )
        .unwrap();
        assert!(filer
            .exists("test", "", None, true, false, false, None)
            .unwrap());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}clean{}test",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_none());

        let _ = filer.close(false);
        assert!(!filer.opened);

        // Check path normalization
        let norm_path_filer = filer.path.as_ref().unwrap().to_str().unwrap();

        // For Windows, we need to compare without drive letters
        let norm_path_filer = norm_path_filer.split(':').last().unwrap_or(norm_path_filer);
        assert!(norm_path_filer.ends_with(&format!(
            "keri{}clean{}test",
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR
        )));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test various reopen combinations with clean=true
        let mut filer = filer;

        let _ = filer.reopen(None, None, None, false, false, true, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}clean{}test",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, false, true, true, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}clean{}test",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, true, true, true, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}clean{}test",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, true, false, true, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}clean{}test",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.close(true);
        assert!(!filer.path.as_ref().unwrap().exists());
    }

    #[test]
    fn test_filing_with_alt_path() {
        cleanup_test_dirs();

        let home_dir = dirs::home_dir().unwrap();
        let alt_dir_path = home_dir.join(".keri").join("test");
        if alt_dir_path.exists() {
            let _ = fs::remove_dir_all(&alt_dir_path);
        }

        // Use a head_dir_path that will not be writable to force using alt path
        let head_dir_path = if cfg!(windows) {
            PathBuf::from("C:\\Windows\\System32\\keri")
        } else {
            PathBuf::from("/root/keri")
        };

        // Test with reopen=false
        let filer = BaseFiler::new(
            "test",
            "",
            false,
            Some(head_dir_path.clone()),
            None,
            false,
            false,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!filer
            .exists("test", "", Some(&head_dir_path), false, false, false, None)
            .unwrap());

        // Test with reopen=true
        let mut filer = BaseFiler::new(
            "test",
            "",
            false,
            Some(head_dir_path.clone()),
            None,
            true,
            false,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(filer
            .exists("test", "", Some(&head_dir_path), false, false, false, None)
            .unwrap());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(".keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_none());

        let _ = filer.close(false);
        assert!(!filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(".keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test various reopen combinations with alt path
        let mut filer = filer;

        let _ = filer.reopen(None, None, None, false, false, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(".keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, false, true, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(".keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, true, true, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(".keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, true, false, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(".keri{}test", std::path::MAIN_SEPARATOR)));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.close(true);
        assert!(!filer.path.as_ref().unwrap().exists());
    }

    #[test]
    fn test_filing_with_file() {
        cleanup_test_dirs();

        // Clean up file paths
        let file_path = Path::new("/usr/local/var/keri/conf/test.text");
        if file_path.exists() {
            let _ = fs::remove_file(file_path);
        }

        let home_dir = dirs::home_dir().unwrap();
        let alt_file_path = home_dir.join(".keri").join("conf").join("test.text");
        if alt_file_path.exists() {
            let _ = fs::remove_file(alt_file_path);
        }

        assert!(!file_path.exists());

        // Test with filed=true and reopen=false
        let filer = BaseFiler::new(
            "test", "conf", false, None, None, false, false, false, false, true, false, None, None,
            None,
        )
        .unwrap();
        assert!(!filer
            .exists("test", "", None, false, true, false, None)
            .unwrap());

        // Test with filed=true and reopen=true
        let mut filer = BaseFiler::new(
            "test", "conf", false, None, None, true, false, false, false, true, false, None, None,
            None,
        )
        .unwrap();

        assert!(filer
            .exists("test", "conf", None, false, true, false, None)
            .unwrap());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_some());

        // Test file operations
        {
            let mut file = filer.file.as_ref().unwrap();
            let mut contents = String::new();
            let _ = file.read_to_string(&mut contents);
            assert!(contents.is_empty());

            let msg = "Hello Jim\n";
            assert_eq!(file.write(msg.as_bytes()).unwrap(), msg.len());
            let _ = file.seek(SeekFrom::Start(0));
            let mut contents = String::new();
            let _ = file.read_to_string(&mut contents);
            assert_eq!(contents, msg);
        }

        let _ = filer.close(false);
        assert!(!filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test various reopen combinations with filed=true
        let mut filer = filer;

        let _ = filer.reopen(None, None, None, false, false, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, false, true, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, true, true, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, true, false, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                "keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.close(true);
        assert!(!filer.path.as_ref().unwrap().exists());
    }

    #[test]
    fn test_filing_with_file_and_alt_path() {
        cleanup_test_dirs();

        let home_dir = dirs::home_dir().unwrap();
        let alt_file_path = home_dir.join(".keri").join("conf").join("test.text");
        if alt_file_path.exists() {
            let _ = fs::remove_file(&alt_file_path);
        }

        // Use a head_dir_path that will not be writable to force using alt path
        let head_dir_path = if cfg!(windows) {
            PathBuf::from("C:\\Windows\\System32")
        } else {
            PathBuf::from("/root/keri")
        };

        // Test with filed=true, alt path and reopen=false
        let filer = BaseFiler::new(
            "test",
            "conf",
            false,
            Some(head_dir_path.clone()),
            None,
            false,
            false,
            false,
            false,
            true,
            false,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!filer
            .exists(
                "test",
                "conf",
                Some(&head_dir_path),
                false,
                true,
                false,
                None
            )
            .unwrap());

        // Test with filed=true, alt path and reopen=true
        let mut filer = BaseFiler::new(
            "test",
            "conf",
            false,
            Some(head_dir_path.clone()),
            None,
            true,
            false,
            false,
            false,
            true,
            false,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(filer
            .exists(
                "test",
                "conf",
                Some(&head_dir_path),
                false,
                true,
                false,
                None
            )
            .unwrap());
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                ".keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.opened);
        assert!(filer.path.as_ref().unwrap().exists());
        assert!(filer.file.is_some());

        // Test file operations with alt path
        {
            let mut file = filer.file.as_ref().unwrap();
            let mut contents = String::new();
            let _ = file.read_to_string(&mut contents);
            assert!(contents.is_empty());

            let msg = "Hello Jim\n";
            assert_eq!(file.write(msg.as_bytes()).unwrap(), msg.len());
            let _ = file.seek(SeekFrom::Start(0));
            let mut contents = String::new();
            let _ = file.read_to_string(&mut contents);
            assert_eq!(contents, msg);
        }

        let _ = filer.close(false);
        assert!(!filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                ".keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        // Test various reopen combinations with filed=true and alt path
        let mut filer = filer;

        let _ = filer.reopen(None, None, None, false, false, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                ".keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, false, true, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                ".keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, true, true, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                ".keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.reopen(None, None, None, true, false, false, None, None);
        assert!(filer.opened);
        assert!(filer
            .path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(&format!(
                ".keri{}conf{}test.text",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )));
        assert!(filer.path.as_ref().unwrap().exists());

        let _ = filer.close(true);
        assert!(!filer.path.as_ref().unwrap().exists());
    }

    #[test]
    fn test_filing_with_temp() {
        // Test open_filer with temp=true (default)
        {
            let mut filer = BaseFiler::new(
                "test", "", true, None, None, true, false, false, false, false, false, None, None,
                None,
            )
            .unwrap();
            assert!(filer
                .path
                .as_ref()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("/tmp/keri_"));
            assert!(filer
                .path
                .as_ref()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(&format!(
                    "_test{}keri{}test",
                    std::path::MAIN_SEPARATOR,
                    std::path::MAIN_SEPARATOR
                )));
            assert!(filer.opened);
            assert!(filer.path.as_ref().unwrap().exists());
            assert!(filer.file.is_none());

            let path = filer.path.clone();
            let _ = filer.close(true);

            assert!(!path.unwrap().exists()); // Temp directories should be cleaned up
        }
        //
        //     // Test open_filer with filed=true and temp=true
        //     {
        //         let filer = open_filer(None, None, None, None, false, false, false, true, None, None).unwrap();
        //         assert!(filer.path.as_ref().unwrap().to_str().unwrap().starts_with("/tmp/keri_"));
        //         assert!(filer.path.as_ref().unwrap().to_str().unwrap().ends_with(&format!("_test{}keri{}test.text", std::path::MAIN_SEPARATOR, std::path::MAIN_SEPARATOR)));
        //         assert!(filer.opened);
        //         assert!(filer.path.as_ref().unwrap().exists());
        //         assert!(filer.file.is_some());
        //
        //         let path = filer.path.clone();
        //         drop(filer); // Close the filer
        //         assert!(!path.unwrap().exists()); // Temp files should be cleaned up
        //     }
        //
        //     // Test open_filer with alt path
        //     {
        //         // Use a head_dir_path that will not be writable to force using alt path
        //         let head_dir_path = if cfg!(windows) {
        //             PathBuf::from("C:\\Windows\\System32")
        //         } else {
        //             PathBuf::from("/root/keri")
        //         };
        //
        //         let filer = open_filer(
        //             None, None,
        //             Some(head_dir_path),
        //             None, true, false, false, true, None, None
        //         ).unwrap();
        //
        //         assert!(filer.path.as_ref().unwrap().to_str().unwrap().ends_with(&format!(".keri{}test.text", std::path::MAIN_SEPARATOR)));
        //         assert!(filer.opened);
        //         assert!(filer.path.as_ref().unwrap().exists());
        //         assert!(filer.file.is_some());
        //
        //         let path = filer.path.clone();
        //         drop(filer); // Close the filer with clear=true
        //         assert!(!path.unwrap().exists()); // Should be cleaned up even though not temp, because clear=true
        //     }
    }

    #[test]
    fn test_filing_invalid_paths() {
        // Test invalid name (absolute path)
        let name = if cfg!(windows) { "C:\\test" } else { "/test" };

        let result = BaseFiler::new(
            name, "conf", false, None, None, true, false, false, false, true, false, None, None,
            None,
        );

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, CoreError::FilerError(_)));
        }

        // Test invalid base (absolute path)
        let base = if cfg!(windows) { "C:\\conf" } else { "/conf" };

        let result = BaseFiler::new(
            "test", base, false, None, None, true, false, false, false, true, false, None, None,
            None,
        );

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, CoreError::FilerError(_)));
        }
    }
}
