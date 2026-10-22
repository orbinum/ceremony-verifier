//! Input files: opened without following symlinks and without blocking (a FIFO swapped in
//! cannot hang the open), then checked on the open descriptor: regular file, bounded size.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

/// The largest input we accept (the power-16 ptau is ~76 MB, the transfer zkey ~17 MB).
pub const MAX_INPUT_BYTES: u64 = 128 * 1024 * 1024;

pub fn read(path: &str) -> Result<Vec<u8>, String> {
    let fail = |e: std::io::Error| format!("{path}: {e}");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(fail)?;
    let meta = file.metadata().map_err(fail)?;
    if !meta.is_file() || meta.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{path}: not a regular file within {MAX_INPUT_BYTES} bytes"
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(fail)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("{path}: grew past {MAX_INPUT_BYTES} bytes"));
    }
    Ok(bytes)
}
