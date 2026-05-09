#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    Plain,
    Gz,
    Bz2,
}

impl CompressionType {
    pub fn from_path(path: &str) -> Self {
        if path.ends_with(".gz") {
            Self::Gz
        } else if path.ends_with(".bz2") {
            Self::Bz2
        } else {
            Self::Plain
        }
    }

    pub fn is_compressed(self) -> bool {
        !matches!(self, Self::Plain)
    }
}
