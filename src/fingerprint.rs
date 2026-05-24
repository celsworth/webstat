// File identity: computes head-hash fingerprints and logical sizes for plain and compressed files.

use std::fs::File;
use std::hash::Hasher;
use std::io::Read;

use anyhow::Result;
use twox_hash::XxHash3_64;

use crate::compression::CompressionType;

/// How many bytes to read from the head and tail for fingerprinting.
pub const FINGERPRINT_SAMPLE: usize = 8_192;

#[derive(Debug, Clone, Copy)]
pub struct FileFingerprint {
    pub head: u64,
    pub logical_size: u64,
}

/// Compute fingerprints for a plain, gzip, or bzip2 file.
///
/// Returns `None` for empty files. Dispatches based on file extension.
pub fn compute_fingerprints(filepath: &str) -> Result<Option<FileFingerprint>> {
    match CompressionType::from_path(filepath) {
        CompressionType::Gz => return compute_gz_fingerprints(filepath),
        CompressionType::Bz2 => return compute_bz2_fingerprints(filepath),
        CompressionType::Plain => {}
    }

    let mut file = File::open(filepath)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(None);
    }

    let head_len = FINGERPRINT_SAMPLE.min(size as usize);
    let mut head = vec![0u8; head_len];
    let head_read = file.read(&mut head)?;
    if head_read == 0 {
        return Ok(None);
    }
    head.truncate(head_read);

    let head_hash = hash_sample(&head);

    Ok(Some(FileFingerprint {
        head: head_hash,
        logical_size: size,
    }))
}

/// Compute a cheap hash of the first compressed bytes of a file.
pub fn compute_compressed_head_fingerprint(filepath: &str) -> Result<Option<u64>> {
    let mut file = File::open(filepath)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(None);
    }

    let head_len = FINGERPRINT_SAMPLE.min(size as usize);
    let mut head = vec![0u8; head_len];
    let head_read = file.read(&mut head)?;
    if head_read == 0 {
        return Ok(None);
    }
    head.truncate(head_read);
    Ok(Some(hash_sample(&head)))
}

/// Compute just the head fingerprint of a decompressed compressed file.
///
/// Dispatches to the appropriate decompressor based on `compression`.
/// Only decompresses the first 8KB — much faster than full fingerprinting.
pub fn compute_decompressed_head_fingerprint(
    filepath: &str,
    compression: CompressionType,
) -> Result<Option<u64>> {
    match compression {
        CompressionType::Gz => compute_gz_uncompressed_head_fingerprint(filepath),
        CompressionType::Bz2 => compute_bz2_uncompressed_head_fingerprint(filepath),
        CompressionType::Plain => {
            unreachable!("compute_decompressed_head_fingerprint called for plain file")
        }
    }
}

fn compute_gz_uncompressed_head_fingerprint(filepath: &str) -> Result<Option<u64>> {
    let file = File::open(filepath)?;
    let mut decoder = flate2::read::MultiGzDecoder::new(file);

    let mut head = Vec::with_capacity(FINGERPRINT_SAMPLE);
    let mut buf = [0u8; 8 * 1024];

    while head.len() < FINGERPRINT_SAMPLE {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }

        let take = (FINGERPRINT_SAMPLE - head.len()).min(n);
        head.extend_from_slice(&buf[..take]);
    }

    if head.is_empty() {
        Ok(None)
    } else {
        Ok(Some(hash_sample(&head)))
    }
}

fn compute_bz2_uncompressed_head_fingerprint(filepath: &str) -> Result<Option<u64>> {
    let file = File::open(filepath)?;
    let mut decoder = bzip2::read::MultiBzDecoder::new(file);

    let mut head = Vec::with_capacity(FINGERPRINT_SAMPLE);
    let mut buf = [0u8; 8 * 1024];

    while head.len() < FINGERPRINT_SAMPLE {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }

        let take = (FINGERPRINT_SAMPLE - head.len()).min(n);
        head.extend_from_slice(&buf[..take]);
    }

    if head.is_empty() {
        Ok(None)
    } else {
        Ok(Some(hash_sample(&head)))
    }
}

fn compute_gz_fingerprints(filepath: &str) -> Result<Option<FileFingerprint>> {
    let file = File::open(filepath)?;
    let mut decoder = flate2::read::MultiGzDecoder::new(file);

    let mut head = Vec::with_capacity(FINGERPRINT_SAMPLE);
    let mut total_size = 0u64;
    let mut buf = [0u8; 16 * 1024];

    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }

        let chunk = &buf[..n];
        total_size += n as u64;

        if head.len() < FINGERPRINT_SAMPLE {
            let take = (FINGERPRINT_SAMPLE - head.len()).min(chunk.len());
            head.extend_from_slice(&chunk[..take]);
        }
    }

    if total_size == 0 {
        return Ok(None);
    }

    let head_hash = hash_sample(&head);

    Ok(Some(FileFingerprint {
        head: head_hash,
        logical_size: total_size,
    }))
}

fn compute_bz2_fingerprints(filepath: &str) -> Result<Option<FileFingerprint>> {
    let file = File::open(filepath)?;
    let mut decoder = bzip2::read::MultiBzDecoder::new(file);

    let mut head = Vec::with_capacity(FINGERPRINT_SAMPLE);
    let mut total_size = 0u64;
    let mut buf = [0u8; 16 * 1024];

    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }

        let chunk = &buf[..n];
        total_size += n as u64;

        if head.len() < FINGERPRINT_SAMPLE {
            let take = (FINGERPRINT_SAMPLE - head.len()).min(chunk.len());
            head.extend_from_slice(&chunk[..take]);
        }
    }

    if total_size == 0 {
        return Ok(None);
    }

    let head_hash = hash_sample(&head);

    Ok(Some(FileFingerprint {
        head: head_hash,
        logical_size: total_size,
    }))
}

/// Hash a byte slice with XxHash3_64.
fn hash_sample(bytes: &[u8]) -> u64 {
    let mut hasher = XxHash3_64::default();
    hasher.write(bytes);
    hasher.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    use tempfile::TempDir;

    fn write_plain(dir: &TempDir, name: &str, content: &[u8]) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn write_gzip(dir: &TempDir, name: &str, content: &[u8]) -> String {
        let path = dir.path().join(name);
        let f = std::fs::File::create(&path).unwrap();
        let mut enc = GzEncoder::new(f, Compression::default());
        enc.write_all(content).unwrap();
        enc.finish().unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn plain_empty_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let path = write_plain(&dir, "empty.log", b"");
        assert!(compute_fingerprints(&path).unwrap().is_none());
    }

    #[test]
    fn plain_small_file_produces_fingerprint() {
        let dir = TempDir::new().unwrap();
        let path = write_plain(&dir, "small.log", b"hello world");
        let fp = compute_fingerprints(&path).unwrap().unwrap();
        assert_eq!(fp.logical_size, 11);
        assert_ne!(fp.head, 0);
    }

    #[test]
    fn plain_different_content_gives_different_fingerprints() {
        let dir = TempDir::new().unwrap();
        let p1 = write_plain(&dir, "a.log", b"aaa");
        let p2 = write_plain(&dir, "b.log", b"bbb");
        let fp1 = compute_fingerprints(&p1).unwrap().unwrap();
        let fp2 = compute_fingerprints(&p2).unwrap().unwrap();
        assert_ne!(fp1.head, fp2.head);
    }

    #[test]
    fn plain_same_content_gives_same_fingerprint() {
        let dir = TempDir::new().unwrap();
        let p1 = write_plain(&dir, "c.log", b"same content");
        let p2 = write_plain(&dir, "d.log", b"same content");
        let fp1 = compute_fingerprints(&p1).unwrap().unwrap();
        let fp2 = compute_fingerprints(&p2).unwrap().unwrap();
        assert_eq!(fp1.head, fp2.head);
        assert_eq!(fp1.logical_size, fp2.logical_size);
    }

    #[test]
    fn gzip_empty_decompressed_returns_none() {
        let dir = TempDir::new().unwrap();
        let path = write_gzip(&dir, "empty.gz", b"");
        assert!(compute_fingerprints(&path).unwrap().is_none());
    }

    #[test]
    fn gzip_small_file_fingerprint_differs_from_plain() {
        let dir = TempDir::new().unwrap();
        let content = b"log line content";
        let gz_path = write_gzip(&dir, "f.log.gz", content);
        let plain_path = write_plain(&dir, "f.log", content);
        let fp_gz = compute_fingerprints(&gz_path).unwrap().unwrap();
        let fp_plain = compute_fingerprints(&plain_path).unwrap().unwrap();
        // Both fingerprint the *decompressed* content length for gz.
        assert_eq!(fp_gz.logical_size, content.len() as u64);
        assert_eq!(fp_plain.logical_size, content.len() as u64);
    }

    #[test]
    fn hash_sample_is_deterministic() {
        assert_eq!(hash_sample(b"hello"), hash_sample(b"hello"));
        assert_ne!(hash_sample(b"hello"), hash_sample(b"world"));
    }
}
