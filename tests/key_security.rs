use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn encrypts_generated_private_keys_and_uses_them_for_signing() {
    let key = unique_path("encrypted-key");
    let public = public_path(&key);
    let passphrase_file = unique_path("passphrase");
    let artifact = unique_path("signed-artifact");
    let signature = unique_path("detached-signature");
    fs::write(&passphrase_file, b"correct horse battery staple\n").unwrap();
    fs::write(&artifact, b"release payload").unwrap();

    let generated = run(&[
        "keygen",
        "--out",
        key.to_str().unwrap(),
        "--passphrase-file",
        passphrase_file.to_str().unwrap(),
    ]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    let private_bytes = fs::read(&key).unwrap();
    assert!(private_bytes.starts_with(b"SEAL-PRIVATE-KEY 1\n"));
    assert!(
        !private_bytes
            .windows(b"BEGIN OPENSSH PRIVATE KEY".len())
            .any(|window| window == b"BEGIN OPENSSH PRIVATE KEY")
    );

    let signed = run(&[
        "sign",
        artifact.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
        "--passphrase-file",
        passphrase_file.to_str().unwrap(),
    ]);
    assert!(signed.status.success(), "{}", stderr(&signed));
    let verified = run(&[
        "verify",
        artifact.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        public.to_str().unwrap(),
    ]);
    assert!(verified.status.success(), "{}", stderr(&verified));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(windows)]
    {
        use std::fs::File;
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::wrappers::GetSecurityInfo;

        let file = File::open(&key).unwrap();
        let descriptor = GetSecurityInfo(
            &file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl,
        )
        .unwrap();
        let sddl = descriptor.as_sddl().unwrap().to_string_lossy().into_owned();
        assert!(sddl.contains("D:P"), "DACL is not protected: {sddl}");
        assert!(
            !sddl.contains(";;;WD)"),
            "DACL grants access to Everyone: {sddl}"
        );
    }

    remove_all([&key, &public, &passphrase_file, &artifact, &signature]);
}

#[test]
fn wrong_passphrase_and_corrupted_encrypted_keys_fail_closed() {
    let key = unique_path("wrong-pass-key");
    let public = public_path(&key);
    let correct = unique_path("correct-passphrase");
    let wrong = unique_path("wrong-passphrase");
    let artifact = unique_path("wrong-pass-artifact");
    let signature = unique_path("wrong-pass-signature");
    fs::write(&correct, b"right password\n").unwrap();
    fs::write(&wrong, b"wrong password\n").unwrap();
    fs::write(&artifact, b"artifact").unwrap();
    let generated = run(&[
        "keygen",
        "--out",
        key.to_str().unwrap(),
        "--passphrase-file",
        correct.to_str().unwrap(),
    ]);
    assert!(generated.status.success(), "{}", stderr(&generated));

    let wrong_passphrase = run(&[
        "sign",
        artifact.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
        "--passphrase-file",
        wrong.to_str().unwrap(),
    ]);
    assert_eq!(wrong_passphrase.status.code(), Some(4));
    assert!(!signature.exists());

    let mut encrypted = fs::read(&key).unwrap();
    let last = encrypted.len() - 1;
    encrypted[last] ^= 1;
    fs::write(&key, encrypted).unwrap();
    let corrupted = run(&[
        "sign",
        artifact.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
        "--passphrase-file",
        correct.to_str().unwrap(),
    ]);
    assert_eq!(corrupted.status.code(), Some(4));
    assert!(!signature.exists());

    remove_all([&key, &public, &correct, &wrong, &artifact, &signature]);
}

#[test]
fn rejects_passphrase_file_over_1024_bytes() {
    let key = unique_path("oversized-pass-key");
    let public = public_path(&key);
    let passphrase_file = unique_path("oversized-passphrase");
    fs::write(&passphrase_file, vec![b'x'; 1025]).unwrap();

    let generated = run(&[
        "keygen",
        "--out",
        key.to_str().unwrap(),
        "--passphrase-file",
        passphrase_file.to_str().unwrap(),
    ]);
    assert_eq!(generated.status.code(), Some(4));
    assert!(!key.exists());
    assert!(!public.exists());

    remove_all([&key, &public, &passphrase_file]);
}

#[test]
fn removes_private_key_when_public_key_creation_fails() {
    let key = unique_path("rollback-key");
    let public = public_path(&key);
    let passphrase_file = unique_path("rollback-passphrase");
    fs::write(&public, b"keep existing public file\n").unwrap();
    fs::write(&passphrase_file, b"test rollback passphrase\n").unwrap();

    let generated = run(&[
        "keygen",
        "--out",
        key.to_str().unwrap(),
        "--passphrase-file",
        passphrase_file.to_str().unwrap(),
    ]);
    assert_eq!(generated.status.code(), Some(5));
    assert!(!key.exists(), "orphaned private key remains after failure");
    assert_eq!(fs::read(&public).unwrap(), b"keep existing public file\n");

    remove_all([&key, &public, &passphrase_file]);
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn unique_path(suffix: &str) -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("seal-{suffix}-{}-{id}", std::process::id()))
}

fn public_path(private: &std::path::Path) -> PathBuf {
    let mut value = private.as_os_str().to_os_string();
    value.push(".pub");
    PathBuf::from(value)
}

fn remove_all<const N: usize>(paths: [&PathBuf; N]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}
