// CompressionType enum (Plain, Gz, Bz2): detection by file extension and decoder construction.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    Plain,
    Gz,
    Bz2,
    Br,
}

impl CompressionType {
    pub fn from_path(path: &str) -> Self {
        if path.ends_with(".gz") {
            Self::Gz
        } else if path.ends_with(".bz2") {
            Self::Bz2
        } else if path.ends_with(".br") {
            Self::Br
        } else {
            Self::Plain
        }
    }

    pub fn is_compressed(self) -> bool {
        !matches!(self, Self::Plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_path_detects_gz() {
        assert_eq!(
            CompressionType::from_path("access.log.gz"),
            CompressionType::Gz
        );
        assert_eq!(CompressionType::from_path("file.gz"), CompressionType::Gz);
    }

    #[test]
    fn from_path_detects_bz2() {
        assert_eq!(
            CompressionType::from_path("access.log.bz2"),
            CompressionType::Bz2
        );
        assert_eq!(CompressionType::from_path("file.bz2"), CompressionType::Bz2);
    }

    #[test]
    fn from_path_detects_br() {
        assert_eq!(
            CompressionType::from_path("access.log.br"),
            CompressionType::Br
        );
        assert_eq!(CompressionType::from_path("file.br"), CompressionType::Br);
    }

    #[test]
    fn from_path_plain_for_unrecognised_extensions() {
        assert_eq!(
            CompressionType::from_path("access.log"),
            CompressionType::Plain
        );
        assert_eq!(
            CompressionType::from_path("data.zip"),
            CompressionType::Plain
        );
        assert_eq!(
            CompressionType::from_path("archive.tar"),
            CompressionType::Plain
        );
    }

    #[test]
    fn from_path_plain_for_empty_string() {
        assert_eq!(CompressionType::from_path(""), CompressionType::Plain);
    }

    #[test]
    fn from_path_case_sensitive() {
        assert_eq!(
            CompressionType::from_path("access.log.GZ"),
            CompressionType::Plain
        );
        assert_eq!(
            CompressionType::from_path("access.log.BZ2"),
            CompressionType::Plain
        );
    }

    #[test]
    fn is_compressed_gz_and_bz2_are_true() {
        assert!(CompressionType::Gz.is_compressed());
        assert!(CompressionType::Bz2.is_compressed());
        assert!(CompressionType::Br.is_compressed());
    }

    #[test]
    fn is_compressed_plain_is_false() {
        assert!(!CompressionType::Plain.is_compressed());
    }

    #[test]
    fn copy_and_clone_preserve_value() {
        let ct = CompressionType::Gz;
        let ct2 = ct;
        let ct3 = ct2.clone();
        assert_eq!(ct, ct3);
    }

    #[test]
    fn equality_reflexive() {
        assert_eq!(CompressionType::Gz, CompressionType::Gz);
        assert_eq!(CompressionType::Bz2, CompressionType::Bz2);
        assert_eq!(CompressionType::Br, CompressionType::Br);
        assert_eq!(CompressionType::Plain, CompressionType::Plain);
        assert_ne!(CompressionType::Gz, CompressionType::Bz2);
        assert_ne!(CompressionType::Gz, CompressionType::Br);
        assert_ne!(CompressionType::Gz, CompressionType::Plain);
    }
}
