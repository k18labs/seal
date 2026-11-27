use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use ssh_key::{Algorithm as KeyAlgorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

use crate::hash::{self, Algorithm};

const NAMESPACE: &str = "seal-file-v1";
const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
pub enum SignatureError {
    Io(io::Error),
    InvalidInput(String),
    InvalidPrivateKey,
    EncryptedPrivateKey,
    InvalidPublicKey,
    UnsupportedKey,
    InvalidSignature,
    UnsupportedSignature,
    UntrustedKey,
    IntegrityMismatch,
}

impl SignatureError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Io(_) => 5,
            Self::InvalidInput(_) => 4,
            Self::InvalidPrivateKey | Self::EncryptedPrivateKey => 4,
            Self::InvalidPublicKey | Self::UntrustedKey => 3,
            Self::UnsupportedKey | Self::UnsupportedSignature => 7,
            Self::InvalidSignature => 2,
            Self::IntegrityMismatch => 1,
        }
    }
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::InvalidInput(message) => f.write_str(message),
            Self::InvalidPrivateKey => f.write_str("invalid OpenSSH private key"),
            Self::EncryptedPrivateKey => {
                f.write_str("encrypted private keys are not supported by this version")
            }
            Self::InvalidPublicKey => f.write_str("invalid OpenSSH public key"),
            Self::UnsupportedKey => f.write_str("unsupported key algorithm; Ed25519 is required"),
            Self::InvalidSignature => f.write_str("signature is invalid"),
            Self::UnsupportedSignature => f.write_str("unsupported signature version or algorithm"),
            Self::UntrustedKey => {
                f.write_str("signature key does not match the explicitly selected public key")
            }
            Self::IntegrityMismatch => {
                f.write_str("artifact size or SHA-256 digest does not match")
            }
        }
    }
}

impl std::error::Error for SignatureError {}

impl From<io::Error> for SignatureError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn keygen(private_path: &Path) -> Result<String, SignatureError> {
    let mut rng = ssh_key::rand_core::OsRng;
    let key = PrivateKey::random(&mut rng, KeyAlgorithm::Ed25519)
        .map_err(|_| SignatureError::InvalidPrivateKey)?;
    let public = key.public_key();
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    let private_text = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| SignatureError::InvalidPrivateKey)?;
    let public_text = format!(
        "{}\n",
        public
            .to_openssh()
            .map_err(|_| SignatureError::InvalidPublicKey)?
    );
    let public_path = public_path_for(private_path);

    write_new_file(private_path, private_text.as_bytes(), true)?;
    if let Err(error) = write_new_file(&public_path, public_text.as_bytes(), false) {
        let _ = fs::remove_file(private_path);
        return Err(error);
    }
    Ok(fingerprint)
}

pub fn fingerprint(public_path: &Path) -> Result<String, SignatureError> {
    let public = read_public_key(public_path)?;
    if public.algorithm() != KeyAlgorithm::Ed25519 {
        return Err(SignatureError::UnsupportedKey);
    }
    Ok(public.fingerprint(HashAlg::Sha256).to_string())
}

pub fn inspect_public_key(public_path: &Path) -> Result<(String, String), SignatureError> {
    let public = read_public_key(public_path)?;
    if public.algorithm() != KeyAlgorithm::Ed25519 {
        return Err(SignatureError::UnsupportedKey);
    }
    Ok((
        "Ed25519".to_owned(),
        public.fingerprint(HashAlg::Sha256).to_string(),
    ))
}

pub fn sign_file(
    artifact_path: &Path,
    private_path: &Path,
    signature_path: &Path,
) -> Result<String, SignatureError> {
    let private_text = zeroize::Zeroizing::new(read_bounded(private_path, MAX_KEY_BYTES)?);
    let private =
        PrivateKey::from_openssh(&private_text).map_err(|_| SignatureError::InvalidPrivateKey)?;
    if private.is_encrypted() {
        return Err(SignatureError::EncryptedPrivateKey);
    }
    if private.algorithm() != KeyAlgorithm::Ed25519 {
        return Err(SignatureError::UnsupportedKey);
    }

    let (digest, size) =
        hash::hash_file_with_size(artifact_path, Algorithm::Sha256).map_err(map_hash_error)?;
    let message = signed_message(size, &digest)?;
    let signature = private
        .sign(NAMESPACE, HashAlg::Sha256, &message)
        .map_err(|_| SignatureError::InvalidPrivateKey)?;
    let pem = signature
        .to_pem(LineEnding::LF)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let record =
        format!("SEAL-SIGNATURE 1\nobject file\nhash sha256\nsize {size}\ndigest {digest}\n{pem}");
    write_new_file(signature_path, record.as_bytes(), false)?;
    Ok(private
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string())
}

pub fn verify_file(
    artifact_path: &Path,
    signature_path: &Path,
    public_path: &Path,
) -> Result<String, SignatureError> {
    let public = read_public_key(public_path)?;
    if public.algorithm() != KeyAlgorithm::Ed25519 {
        return Err(SignatureError::UnsupportedKey);
    }

    let record = read_bounded(signature_path, MAX_SIGNATURE_BYTES)?;
    let (expected_size, expected_digest, pem) = parse_signature_record(&record)?;
    let signature = SshSig::from_pem(pem)
        .map_err(|_| SignatureError::InvalidInput("malformed SSHSIG signature".to_owned()))?;
    if signature.version() != 1
        || signature.algorithm() != KeyAlgorithm::Ed25519
        || signature.namespace() != NAMESPACE
        || signature.hash_alg() != HashAlg::Sha256
    {
        return Err(SignatureError::UnsupportedSignature);
    }
    let message = signed_message(expected_size, expected_digest)?;
    let signature_public: PublicKey = signature.public_key().clone().into();
    signature_public
        .verify(NAMESPACE, &message, &signature)
        .map_err(|_| SignatureError::InvalidSignature)?;
    if signature.public_key() != public.key_data() {
        return Err(SignatureError::UntrustedKey);
    }

    let (actual_digest, actual_size) =
        hash::hash_file_with_size(artifact_path, Algorithm::Sha256).map_err(map_hash_error)?;
    if actual_size != expected_size || actual_digest != expected_digest {
        return Err(SignatureError::IntegrityMismatch);
    }
    Ok(public.fingerprint(HashAlg::Sha256).to_string())
}

fn signed_message(size: u64, digest_hex: &str) -> Result<Vec<u8>, SignatureError> {
    let digest = decode_sha256(digest_hex)?;
    let mut message = b"SEAL-FILE-V1\0sha256\0".to_vec();
    message.extend_from_slice(&size.to_be_bytes());
    message.extend_from_slice(&digest);
    Ok(message)
}

fn parse_signature_record(record: &[u8]) -> Result<(u64, &str, &str), SignatureError> {
    let text = std::str::from_utf8(record)
        .map_err(|_| SignatureError::InvalidInput("signature record is not UTF-8".to_owned()))?;
    let mut remaining = text;
    for header in ["SEAL-SIGNATURE 1\n", "object file\n", "hash sha256\n"] {
        remaining = remaining
            .strip_prefix(header)
            .ok_or(SignatureError::UnsupportedSignature)?;
    }
    let (size_line, rest) = remaining
        .split_once('\n')
        .ok_or_else(|| SignatureError::InvalidInput("missing signed size".to_owned()))?;
    let size_text = size_line
        .strip_prefix("size ")
        .ok_or_else(|| SignatureError::InvalidInput("invalid signed size".to_owned()))?;
    if size_text.is_empty()
        || (size_text.len() > 1 && size_text.starts_with('0'))
        || !size_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SignatureError::InvalidInput(
            "non-canonical signed size".to_owned(),
        ));
    }
    let size = size_text
        .parse::<u64>()
        .map_err(|_| SignatureError::InvalidInput("signed size is out of range".to_owned()))?;
    let (digest_line, pem) = rest
        .split_once('\n')
        .ok_or_else(|| SignatureError::InvalidInput("missing signed digest".to_owned()))?;
    let digest = digest_line
        .strip_prefix("digest ")
        .ok_or_else(|| SignatureError::InvalidInput("invalid signed digest".to_owned()))?;
    let _ = decode_sha256(digest)?;
    if !pem.starts_with("-----BEGIN SSH SIGNATURE-----\n")
        || !pem.ends_with("-----END SSH SIGNATURE-----\n")
    {
        return Err(SignatureError::InvalidInput(
            "malformed SSHSIG armor".to_owned(),
        ));
    }
    Ok((size, digest, pem))
}

fn decode_sha256(hex: &str) -> Result<[u8; 32], SignatureError> {
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SignatureError::InvalidInput(
            "SHA-256 digest must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }
    let mut digest = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = nibble(pair[0])
            .ok_or_else(|| SignatureError::InvalidInput("invalid digest".to_owned()))?;
        let low = nibble(pair[1])
            .ok_or_else(|| SignatureError::InvalidInput("invalid digest".to_owned()))?;
        digest[index] = high << 4 | low;
    }
    Ok(digest)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn read_public_key(path: &Path) -> Result<PublicKey, SignatureError> {
    let encoded = read_bounded(path, MAX_KEY_BYTES)?;
    let text = std::str::from_utf8(&encoded).map_err(|_| SignatureError::InvalidPublicKey)?;
    PublicKey::from_openssh(text.trim_end_matches(['\r', '\n']))
        .map_err(|_| SignatureError::InvalidPublicKey)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, SignatureError> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(SignatureError::InvalidInput(
            "key and signature inputs must be regular files".to_owned(),
        ));
    }
    if metadata.len() > limit {
        return Err(SignatureError::InvalidInput(
            "input exceeds the documented size limit".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(SignatureError::InvalidInput(
            "input exceeds the documented size limit".to_owned(),
        ));
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8], private: bool) -> Result<(), SignatureError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(path)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(SignatureError::Io(error));
    }
    Ok(())
}

fn public_path_for(private_path: &Path) -> PathBuf {
    let mut name = private_path.as_os_str().to_os_string();
    name.push(".pub");
    PathBuf::from(name)
}

fn map_hash_error(error: hash::HashError) -> SignatureError {
    match error {
        hash::HashError::Io(error) => SignatureError::Io(error),
        hash::HashError::UnsupportedType => {
            SignatureError::InvalidInput("artifact must be a regular file".to_owned())
        }
        hash::HashError::AlgorithmUnavailable => SignatureError::UnsupportedSignature,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_sha256, parse_signature_record, signed_message};

    #[test]
    fn envelope_is_fixed_and_domain_separated() {
        let message = signed_message(
            3,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .unwrap();
        assert_eq!(&message[..20], b"SEAL-FILE-V1\0sha256\0");
        assert_eq!(&message[20..28], &3u64.to_be_bytes());
        assert_eq!(message.len(), 60);
    }

    #[test]
    fn rejects_noncanonical_digest() {
        assert!(decode_sha256(&"A".repeat(64)).is_err());
    }

    #[test]
    fn rejects_unknown_record_version() {
        assert!(parse_signature_record(b"SEAL-SIGNATURE 2\n").is_err());
    }
}
