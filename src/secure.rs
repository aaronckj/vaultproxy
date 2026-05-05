use std::fmt;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// A buffer that keeps its contents locked in RAM (preventing swap) and
/// zeroes memory on drop.
///
/// The `Debug` impl never prints the actual contents — it always shows
/// `[REDACTED SecureBuffer]`.
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a `SecureBuffer` from an existing byte vector.
    ///
    /// Attempts to `mlock` the allocation.  If `mlock` fails (e.g. inside a
    /// Docker container without the `IPC_LOCK` capability) a warning is logged
    /// but execution continues — the buffer is still zeroed on drop.
    pub fn new(data: Vec<u8>) -> Self {
        let mut buf = Self { data };
        buf.lock();
        buf
    }

    /// Allocate a zeroed buffer of `len` bytes.
    pub fn zeroed(len: usize) -> Self {
        Self::new(vec![0u8; len])
    }

    /// View the buffer as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Interpret the buffer contents as a UTF-8 string slice.
    ///
    /// Returns `Err` if the bytes are not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }

    /// Number of bytes in the buffer.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` when the buffer contains no bytes.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    // ------------------------------------------------------------------ //
    // private helpers                                                      //
    // ------------------------------------------------------------------ //

    fn lock(&mut self) {
        if self.data.is_empty() {
            return;
        }
        let ok = unsafe { memsec::mlock(self.data.as_mut_ptr(), self.data.len()) };
        if !ok {
            tracing::warn!(
                len = self.data.len(),
                "memsec::mlock failed — buffer will not be prevented from swapping"
            );
        }
    }

    fn unlock_and_zero(&mut self) {
        if self.data.is_empty() {
            return;
        }
        // memsec::munlock already calls memzero internally before unlocking,
        // but we call zeroize first so the Zeroize trait logic runs in case
        // the allocator makes a copy.
        self.data.zeroize();
        unsafe {
            memsec::munlock(self.data.as_mut_ptr(), self.data.len());
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.unlock_and_zero();
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED SecureBuffer]")
    }
}

// -------------------------------------------------------------------------- //
// Secure random                                                               //
// -------------------------------------------------------------------------- //

/// Fill a fresh `SecureBuffer` of `len` bytes with cryptographically secure
/// random data.
pub fn secure_random(len: usize) -> SecureBuffer {
    use rand::RngCore;
    let mut buf = SecureBuffer::zeroed(len);
    rand::thread_rng().fill_bytes(&mut buf.data);
    buf
}

use anyhow::Context;

// -------------------------------------------------------------------------- //
// Safe config file writes                                                     //
// -------------------------------------------------------------------------- //

/// Write data to a config file atomically, rejecting symlinks.
///
/// Writes to `<path>.tmp.<pid>`, fsyncs, then `rename(2)`s into place so a
/// mid-write crash, OOM kill, or container stop can never leave a truncated
/// keystore blob. Permissions on the temp file are set to `0600` before the
/// rename so the final file is already correctly locked down.
pub fn safe_write_config(path: &str, data: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    let p = std::path::Path::new(path);
    // If file exists, verify it's not a symlink
    if p.exists() && p.symlink_metadata()?.file_type().is_symlink() {
        anyhow::bail!("refusing to write to symlink: {}", path);
    }

    let tmp_path = format!("{}.tmp.{}", path, std::process::id());

    let write_result: anyhow::Result<()> = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let mut f = opts
            .open(&tmp_path)
            .with_context(|| format!("open tmp file {}", tmp_path))?;
        f.write_all(data)
            .with_context(|| format!("write tmp file {}", tmp_path))?;
        f.sync_all()
            .with_context(|| format!("fsync tmp file {}", tmp_path))?;
        drop(f);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&tmp_path, path)
            .with_context(|| format!("atomic rename {} -> {}", tmp_path, path))?;
        Ok(())
    })();

    if write_result.is_err() {
        // Best-effort cleanup — the rename never happened, so the target file
        // is still intact (old contents or absent).
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

// -------------------------------------------------------------------------- //
// Tests                                                                       //
// -------------------------------------------------------------------------- //

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a buffer reports the correct length and can be dropped
    /// without panicking (the Drop impl calls munlock / zeroize).
    #[test]
    fn test_secure_buffer_zeroes_on_drop() {
        let data = b"super secret data".to_vec();
        let expected_len = data.len();
        let buf = SecureBuffer::new(data);
        assert_eq!(buf.len(), expected_len);
        assert!(!buf.is_empty());
        // Dropping here exercises the zeroize + munlock path.
        drop(buf);
    }

    /// Verify that `secure_random` returns a non-empty buffer and (with very
    /// high probability) at least one byte is non-zero.
    #[test]
    fn test_secure_random() {
        let buf = secure_random(32);
        assert_eq!(buf.len(), 32);
        // The probability that 32 random bytes are all zero is 1/2^256 — we
        // treat that as impossible for the purposes of this test.
        let all_zero = buf.iter().all(|&b| b == 0);
        assert!(!all_zero, "secure_random produced all-zero output");
    }

    /// Verify that the Debug implementation never exposes the buffer contents.
    #[test]
    fn test_debug_redacted() {
        let secret = b"password123".to_vec();
        let buf = SecureBuffer::new(secret);
        let debug_output = format!("{:?}", buf);
        assert_eq!(debug_output, "[REDACTED SecureBuffer]");
        assert!(!debug_output.contains("password"));
        assert!(!debug_output.contains("123"));
    }
}
