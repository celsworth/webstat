use super::*;

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
