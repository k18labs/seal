use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Sha256,
    Blake3,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Blake3 => "blake3",
        }
    }
}

impl std::str::FromStr for Algorithm {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sha256" => Ok(Self::Sha256),
            "blake3" => Ok(Self::Blake3),
            _ => Err(format!("unsupported algorithm: {value}")),
        }
    }
}

#[derive(Debug)]
pub enum HashError {
    Io(io::Error),
    UnsupportedType,
    AlgorithmUnavailable,
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::UnsupportedType => write!(f, "input is not a regular file"),
            Self::AlgorithmUnavailable => write!(f, "BLAKE3 support was disabled at build time"),
        }
    }
}

impl std::error::Error for HashError {}

/// Hash a regular file using a fixed-size buffer and return lowercase hexadecimal.
pub fn hash_file(path: impl AsRef<Path>, algorithm: Algorithm) -> Result<String, HashError> {
    hash_file_with_size(path, algorithm).map(|(digest, _)| digest)
}

/// Hash a regular file and count bytes from the same opened stream.
pub fn hash_file_with_size(
    path: impl AsRef<Path>,
    algorithm: Algorithm,
) -> Result<(String, u64), HashError> {
    let path = path.as_ref();
    if !std::fs::metadata(path).map_err(HashError::Io)?.is_file() {
        return Err(HashError::UnsupportedType);
    }
    let mut file = File::open(path).map_err(HashError::Io)?;
    if !file.metadata().map_err(HashError::Io)?.is_file() {
        return Err(HashError::UnsupportedType);
    }
    hash_reader_with_size(&mut file, algorithm)
}

/// Hash any reader with bounded memory. The caller is responsible for choosing
/// an appropriate source; this function does not infer filesystem object type.
pub fn hash_reader(reader: &mut impl Read, algorithm: Algorithm) -> Result<String, HashError> {
    hash_reader_with_size(reader, algorithm).map(|(digest, _)| digest)
}

pub fn hash_reader_with_size(
    reader: &mut impl Read,
    algorithm: Algorithm,
) -> Result<(String, u64), HashError> {
    hash_reader_with_size_and_progress(reader, algorithm, |_| {})
}

pub(crate) fn hash_reader_with_size_and_progress(
    reader: &mut impl Read,
    algorithm: Algorithm,
    mut progress: impl FnMut(u64),
) -> Result<(String, u64), HashError> {
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut size = 0u64;
    match algorithm {
        Algorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            loop {
                let count = reader.read(&mut buffer).map_err(HashError::Io)?;
                if count == 0 {
                    break;
                }
                size = size
                    .checked_add(count as u64)
                    .ok_or_else(|| HashError::Io(io::Error::other("input size overflow")))?;
                hasher.update(&buffer[..count]);
                progress(size);
            }
            Ok((encode_hex(&hasher.finalize()), size))
        }
        Algorithm::Blake3 => {
            #[cfg(feature = "blake3")]
            {
                let mut hasher = blake3::Hasher::new();
                loop {
                    let count = reader.read(&mut buffer).map_err(HashError::Io)?;
                    if count == 0 {
                        break;
                    }
                    size = size
                        .checked_add(count as u64)
                        .ok_or_else(|| HashError::Io(io::Error::other("input size overflow")))?;
                    hasher.update(&buffer[..count]);
                    progress(size);
                }
                Ok((encode_hex(hasher.finalize().as_bytes()), size))
            }
            #[cfg(not(feature = "blake3"))]
            {
                let _ = reader;
                Err(HashError::AlgorithmUnavailable)
            }
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn sha256_empty_known_vector() {
        assert_eq!(
            hash_reader(&mut Cursor::new(b""), Algorithm::Sha256).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc_known_vector() {
        assert_eq!(
            hash_reader(&mut Cursor::new(b"abc"), Algorithm::Sha256).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_empty_known_vector() {
        assert_eq!(
            hash_reader(&mut Cursor::new(b""), Algorithm::Blake3).unwrap(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }
}
