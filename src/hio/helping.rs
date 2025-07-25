//! HIO helping utilities module

use crate::hio::errors::HioError;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Atomically open or create file from filepath.
///
/// If file already exists, then open file using the specified mode.
/// Else create file using write-update mode.
///
/// This is equivalent to Python's `ocfn` function, providing atomic
/// file creation with proper permissions.
///
/// # Arguments
/// * `path` - File path to open/create
/// * `read` - Whether file should be readable (default: true)  
/// * `write` - Whether file should be writable (default: true)
/// * `append` - Whether to append to existing file (default: false)
/// * `truncate` - Whether to truncate existing file (default: false)
/// * `create` - Whether to create file if it doesn't exist (default: true)
/// * `create_new` - Whether to fail if file already exists (default: false)
/// * `perm` - Unix file permissions (default: 0o600 - owner read/write only)
///
/// # Returns
/// * `Result<File, HioError>` - Opened file handle or error
#[cfg(unix)]
pub fn ocfn<P: AsRef<Path>>(
    path: P,
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    perm: u32,
) -> Result<File, HioError> {
    let path = path.as_ref();

    // First try to create the file exclusively (atomic creation)
    if create {
        let create_result = OpenOptions::new()
            .read(read)
            .write(write)
            .append(append)
            .truncate(false) // Don't truncate on creation
            .create_new(true) // Fail if file exists
            .mode(perm)
            .open(path);

        match create_result {
            Ok(file) => return Ok(file),
            Err(ref e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // File exists, fall through to normal open
                if create_new {
                    return Err(HioError::FilerError(format!(
                        "File already exists: {}",
                        path.display()
                    )));
                }
            }
            Err(e) => return Err(HioError::IoError(e)),
        }
    }

    // File exists or we're not creating, open normally
    let file = OpenOptions::new()
        .read(read)
        .write(write)
        .append(append)
        .truncate(truncate)
        .create(create && !create_new)
        .mode(perm)
        .open(path)
        .map_err(HioError::IoError)?;

    Ok(file)
}
