use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use argon2::{Algorithm as KdfAlgorithm, Argon2, Params, Version as KdfVersion};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ssh_key::{Algorithm as KeyAlgorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

use crate::hash::{self, Algorithm};

const NAMESPACE: &str = "seal-file-v1";
const MANIFEST_NAMESPACE: &str = "seal-manifest-v1";
const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
const PRIVATE_MAGIC: &[u8] = b"SEAL-PRIVATE-KEY 1\n";
const PRIVATE_HEADER_LEN: usize = PRIVATE_MAGIC.len() + 16 + 24;

#[derive(Debug)]
pub enum SignatureError {
    Io(io::Error),
    InvalidInput(String),
    InvalidPrivateKey,
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
            Self::InvalidPrivateKey => 4,
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

pub fn keygen(private_path: &Path, passphrase: &[u8]) -> Result<String, SignatureError> {
    validate_passphrase(passphrase)?;
    let mut rng = ssh_key::rand_core::OsRng;
    let key = PrivateKey::random(&mut rng, KeyAlgorithm::Ed25519)
        .map_err(|_| SignatureError::InvalidPrivateKey)?;
    let public = key.public_key();
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    let private_text = zeroize::Zeroizing::new(
        key.to_openssh(LineEnding::LF)
            .map_err(|_| SignatureError::InvalidPrivateKey)?,
    );
    let encrypted = encrypt_private(private_text.as_bytes(), passphrase)?;
    let public_text = format!(
        "{}\n",
        public
            .to_openssh()
            .map_err(|_| SignatureError::InvalidPublicKey)?
    );
    let public_path = public_path_for(private_path);

    write_new_file(private_path, &encrypted, true)?;
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
    passphrase: &[u8],
) -> Result<String, SignatureError> {
    let private = read_private_key(private_path, passphrase)?;
    if private.algorithm() != KeyAlgorithm::Ed25519 {
        return Err(SignatureError::UnsupportedKey);
    }

    let (digest, size) =
        hash::hash_file_with_size(artifact_path, Algorithm::Sha256).map_err(map_hash_error)?;
    let message = signed_message(SignatureObject::File, size, &digest)?;
    let signature = private
        .sign(NAMESPACE, HashAlg::Sha256, &message)
        .map_err(|_| SignatureError::InvalidPrivateKey)?;
    let pem = signature
        .to_pem(LineEnding::LF)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let record = signature_record("file", size, &digest, &pem);
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
    let (object, expected_size, expected_digest, pem) = parse_signature_record(&record)?;
    if object != SignatureObject::File {
        return Err(SignatureError::UnsupportedSignature);
    }
    let signature = SshSig::from_pem(pem)
        .map_err(|_| SignatureError::InvalidInput("malformed SSHSIG signature".to_owned()))?;
    if signature.version() != 1
        || signature.algorithm() != KeyAlgorithm::Ed25519
        || signature.namespace() != NAMESPACE
        || signature.hash_alg() != HashAlg::Sha256
    {
        return Err(SignatureError::UnsupportedSignature);
    }
    let message = signed_message(object, expected_size, expected_digest)?;
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

pub fn sign_manifest(
    manifest_path: &Path,
    private_path: &Path,
    signature_path: &Path,
    passphrase: &[u8],
) -> Result<String, SignatureError> {
    let payload = read_bounded(manifest_path, crate::manifest::MAX_MANIFEST_BYTES as u64)?;
    crate::manifest::Manifest::parse(&payload)
        .map_err(|error| SignatureError::InvalidInput(format!("invalid manifest: {error}")))?;
    sign_bytes(
        &payload,
        private_path,
        signature_path,
        SignatureObject::Manifest,
        passphrase,
    )
}

pub fn verify_manifest_signature(
    manifest_path: &Path,
    signature_path: &Path,
    public_path: &Path,
) -> Result<(String, crate::manifest::Manifest), SignatureError> {
    let payload = read_bounded(manifest_path, crate::manifest::MAX_MANIFEST_BYTES as u64)?;
    let manifest = crate::manifest::Manifest::parse(&payload)
        .map_err(|error| SignatureError::InvalidInput(format!("invalid manifest: {error}")))?;
    let signer = verify_bytes(
        &payload,
        signature_path,
        public_path,
        SignatureObject::Manifest,
    )?;
    Ok((signer, manifest))
}

fn sign_bytes(
    payload: &[u8],
    private_path: &Path,
    signature_path: &Path,
    object: SignatureObject,
    passphrase: &[u8],
) -> Result<String, SignatureError> {
    let private = read_private_key(private_path, passphrase)?;
    if private.algorithm() != KeyAlgorithm::Ed25519 {
        return Err(SignatureError::UnsupportedKey);
    }
    let (digest, size) =
        hash::hash_reader_with_size(&mut io::Cursor::new(payload), Algorithm::Sha256)
            .map_err(map_hash_error)?;
    let message = signed_message(object, size, &digest)?;
    let signature = private
        .sign(object.namespace(), HashAlg::Sha256, &message)
        .map_err(|_| SignatureError::InvalidPrivateKey)?;
    let pem = signature
        .to_pem(LineEnding::LF)
        .map_err(|_| SignatureError::InvalidSignature)?;
    write_new_file(
        signature_path,
        signature_record(object.label(), size, &digest, &pem).as_bytes(),
        false,
    )?;
    Ok(private
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string())
}

fn verify_bytes(
    payload: &[u8],
    signature_path: &Path,
    public_path: &Path,
    expected_object: SignatureObject,
) -> Result<String, SignatureError> {
    let public = read_public_key(public_path)?;
    if public.algorithm() != KeyAlgorithm::Ed25519 {
        return Err(SignatureError::UnsupportedKey);
    }
    let record = read_bounded(signature_path, MAX_SIGNATURE_BYTES)?;
    let (object, expected_size, expected_digest, pem) = parse_signature_record(&record)?;
    if object != expected_object {
        return Err(SignatureError::UnsupportedSignature);
    }
    let signature = SshSig::from_pem(pem)
        .map_err(|_| SignatureError::InvalidInput("malformed SSHSIG signature".to_owned()))?;
    if signature.version() != 1
        || signature.algorithm() != KeyAlgorithm::Ed25519
        || signature.namespace() != expected_object.namespace()
        || signature.hash_alg() != HashAlg::Sha256
    {
        return Err(SignatureError::UnsupportedSignature);
    }
    let message = signed_message(object, expected_size, expected_digest)?;
    let signature_public: PublicKey = signature.public_key().clone().into();
    signature_public
        .verify(expected_object.namespace(), &message, &signature)
        .map_err(|_| SignatureError::InvalidSignature)?;
    if signature.public_key() != public.key_data() {
        return Err(SignatureError::UntrustedKey);
    }
    let (actual_digest, actual_size) =
        hash::hash_reader_with_size(&mut io::Cursor::new(payload), Algorithm::Sha256)
            .map_err(map_hash_error)?;
    if actual_size != expected_size || actual_digest != expected_digest {
        return Err(SignatureError::IntegrityMismatch);
    }
    Ok(public.fingerprint(HashAlg::Sha256).to_string())
}

fn signature_record(object: &str, size: u64, digest: &str, pem: &str) -> String {
    format!("SEAL-SIGNATURE 1\nobject {object}\nhash sha256\nsize {size}\ndigest {digest}\n{pem}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignatureObject {
    File,
    Manifest,
}

impl SignatureObject {
    fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Manifest => "manifest",
        }
    }

    fn namespace(self) -> &'static str {
        match self {
            Self::File => NAMESPACE,
            Self::Manifest => MANIFEST_NAMESPACE,
        }
    }
}

fn signed_message(
    object: SignatureObject,
    size: u64,
    digest_hex: &str,
) -> Result<Vec<u8>, SignatureError> {
    let digest = decode_sha256(digest_hex)?;
    let mut message = match object {
        SignatureObject::File => b"SEAL-FILE-V1\0sha256\0".to_vec(),
        SignatureObject::Manifest => b"SEAL-MANIFEST-V1\0sha256\0".to_vec(),
    };
    message.extend_from_slice(&size.to_be_bytes());
    message.extend_from_slice(&digest);
    Ok(message)
}

fn parse_signature_record(
    record: &[u8],
) -> Result<(SignatureObject, u64, &str, &str), SignatureError> {
    let text = std::str::from_utf8(record)
        .map_err(|_| SignatureError::InvalidInput("signature record is not UTF-8".to_owned()))?;
    let mut remaining = text;
    remaining = remaining
        .strip_prefix("SEAL-SIGNATURE 1\n")
        .ok_or(SignatureError::UnsupportedSignature)?;
    let (object_line, rest) = remaining
        .split_once('\n')
        .ok_or(SignatureError::UnsupportedSignature)?;
    let object = match object_line {
        "object file" => SignatureObject::File,
        "object manifest" => SignatureObject::Manifest,
        _ => return Err(SignatureError::UnsupportedSignature),
    };
    remaining = rest
        .strip_prefix("hash sha256\n")
        .ok_or(SignatureError::UnsupportedSignature)?;
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
    Ok((object, size, digest, pem))
}

/// Validate the bounded textual and SSHSIG structure of a detached signature record.
pub fn validate_signature_record(record: &[u8]) -> Result<(), SignatureError> {
    let (object, _, _, pem) = parse_signature_record(record)?;
    let signature = SshSig::from_pem(pem)
        .map_err(|_| SignatureError::InvalidInput("malformed SSHSIG signature".to_owned()))?;
    let expected_namespace = object.namespace();
    if signature.version() != 1
        || signature.algorithm() != KeyAlgorithm::Ed25519
        || signature.namespace() != expected_namespace
        || signature.hash_alg() != HashAlg::Sha256
    {
        return Err(SignatureError::UnsupportedSignature);
    }
    Ok(())
}

/// Validate an OpenSSH public-key encoding and require Ed25519.
pub fn validate_public_key_bytes(encoded: &[u8]) -> Result<(), SignatureError> {
    if encoded.len() as u64 > MAX_KEY_BYTES {
        return Err(SignatureError::InvalidInput(
            "input exceeds the documented size limit".to_owned(),
        ));
    }
    let text = std::str::from_utf8(encoded).map_err(|_| SignatureError::InvalidPublicKey)?;
    let public = PublicKey::from_openssh(text.trim_end_matches(['\r', '\n']))
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    if public.algorithm() != KeyAlgorithm::Ed25519 {
        return Err(SignatureError::UnsupportedKey);
    }
    Ok(())
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

fn validate_passphrase(passphrase: &[u8]) -> Result<(), SignatureError> {
    if !(12..=1024).contains(&passphrase.len()) || std::str::from_utf8(passphrase).is_err() {
        return Err(SignatureError::InvalidInput(
            "passphrase must be 12 to 1024 UTF-8 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
) -> Result<zeroize::Zeroizing<[u8; 32]>, SignatureError> {
    let params =
        Params::new(65536, 3, 1, Some(32)).map_err(|_| SignatureError::InvalidPrivateKey)?;
    let argon = Argon2::new(KdfAlgorithm::Argon2id, KdfVersion::V0x13, params);
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|_| SignatureError::InvalidPrivateKey)?;
    Ok(key)
}

fn encrypt_private(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, SignatureError> {
    use ssh_key::rand_core::RngCore;
    validate_passphrase(passphrase)?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    let mut rng = ssh_key::rand_core::OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let nonce = XNonce::from(nonce);
    let mut header = Vec::with_capacity(PRIVATE_HEADER_LEN);
    header.extend_from_slice(PRIVATE_MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| SignatureError::InvalidPrivateKey)?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

fn read_private_key(path: &Path, passphrase: &[u8]) -> Result<PrivateKey, SignatureError> {
    validate_passphrase(passphrase)?;
    let encoded = read_bounded(path, MAX_KEY_BYTES)?;
    if encoded.len() < PRIVATE_HEADER_LEN + 16 || !encoded.starts_with(PRIVATE_MAGIC) {
        return Err(SignatureError::InvalidPrivateKey);
    }
    let salt_start = PRIVATE_MAGIC.len();
    let nonce_start = salt_start + 16;
    let salt = &encoded[salt_start..nonce_start];
    let nonce: [u8; 24] = encoded[nonce_start..PRIVATE_HEADER_LEN]
        .try_into()
        .map_err(|_| SignatureError::InvalidPrivateKey)?;
    let nonce = XNonce::from(nonce);
    let key = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let clear = zeroize::Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &encoded[PRIVATE_HEADER_LEN..],
                    aad: &encoded[..PRIVATE_HEADER_LEN],
                },
            )
            .map_err(|_| SignatureError::InvalidPrivateKey)?,
    );
    let private =
        PrivateKey::from_openssh(&clear).map_err(|_| SignatureError::InvalidPrivateKey)?;
    if private.is_encrypted() {
        return Err(SignatureError::InvalidPrivateKey);
    }
    Ok(private)
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
    #[cfg(windows)]
    if private {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
        // WRITE_DAC is needed to apply the restrictive DACL before writing ciphertext.
        options.access_mode(0x4000_0000 | 0x0004_0000);
    }
    #[cfg(not(unix))]
    let _ = private;
    #[cfg(windows)]
    let mut file = options.open(path)?;
    #[cfg(not(windows))]
    let file = options.open(path)?;
    #[cfg(windows)]
    if private {
        use windows_permissions::{
            SecurityDescriptor,
            constants::{SeObjectType, SecurityInformation},
            wrappers::{GetSecurityInfo, SetSecurityInfo},
        };
        let desired: windows_permissions::LocalBox<SecurityDescriptor> =
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)".parse()?;
        let dacl = desired
            .dacl()
            .ok_or_else(|| io::Error::other("private key DACL could not be parsed"))?;
        SetSecurityInfo(
            &mut file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            Some(dacl),
            None,
        )?;
        let actual = GetSecurityInfo(
            &file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl,
        )?;
        let sddl = actual.as_sddl()?.to_string_lossy().into_owned();
        let actual_dacl = sddl.split_once("D:").map(|(_, dacl)| dacl);
        if actual_dacl != Some("PAI(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)") {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(SignatureError::Io(io::Error::other(
                "private key DACL did not match the required protected ACL",
            )));
        }
    }
    write_file_with_rollback(path, file, |file| {
        file.write_all(bytes).and_then(|()| file.sync_all())
    })
}

fn write_file_with_rollback(
    path: &Path,
    mut file: File,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> Result<(), SignatureError> {
    if let Err(error) = write(&mut file) {
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
    use std::{
        fs::OpenOptions,
        io::{self, Write},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        SignatureObject, decode_sha256, parse_signature_record, signed_message,
        write_file_with_rollback,
    };

    static NEXT_ROLLBACK_TEST_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn envelope_is_fixed_and_domain_separated() {
        let message = signed_message(
            SignatureObject::File,
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

    #[test]
    fn removes_partially_written_file_after_write_failure() {
        let path = std::env::temp_dir().join(format!(
            "seal-partial-write-rollback-{}-{}",
            std::process::id(),
            NEXT_ROLLBACK_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();

        let result = write_file_with_rollback(&path, file, |file| {
            file.write_all(b"partial secret bytes")?;
            Err(io::Error::other("injected write failure"))
        });

        assert!(result.is_err());
        assert!(!path.exists(), "partial file remains after write failure");
    }
}
