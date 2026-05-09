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
pub fn hash_sample(bytes: &[u8]) -> u64 {
    let mut hasher = XxHash3_64::default();
    hasher.write(bytes);
    hasher.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
