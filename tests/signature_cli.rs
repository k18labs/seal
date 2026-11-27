use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn keygen_sign_and_verify_round_trip() {
    let base = unique_path("key");
    let artifact = unique_path("artifact");
    let signature = unique_path("signature");
    fs::write(&artifact, vec![0x5a; 8 * 1024 * 1024]).unwrap();

    let generated = run(&["keygen", "--out", base.to_str().unwrap()]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    let public = public_path(&base);
    assert!(base.is_file());
    assert!(public.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&base).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let fingerprint = run(&[
        "key",
        "fingerprint",
        "--public-key",
        public.to_str().unwrap(),
    ]);
    assert!(fingerprint.status.success());
    let fingerprint = String::from_utf8(fingerprint.stdout).unwrap();
    let inspected = run(&["key", "inspect", "--public-key", public.to_str().unwrap()]);
    assert!(inspected.status.success());
    assert!(
        String::from_utf8(inspected.stdout)
            .unwrap()
            .contains(fingerprint.trim())
    );

    let signed = run(&[
        "sign",
        artifact.to_str().unwrap(),
        "--key",
        base.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
    ]);
    assert!(signed.status.success(), "{}", stderr(&signed));

    let verified = run(&[
        "verify",
        artifact.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        public.to_str().unwrap(),
        "--json",
    ]);
    assert!(verified.status.success(), "{}", stderr(&verified));
    let result: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(result["verified"], true);
    assert_eq!(result["signature_valid"], true);
    assert_eq!(result["signer_trusted"], true);
    assert_eq!(result["integrity_valid"], true);

    remove_all([&base, &public, &artifact, &signature]);
}

#[test]
fn modified_artifact_fails_integrity_check() {
    let base = unique_path("key");
    let artifact = unique_path("artifact");
    let signature = unique_path("signature");
    fs::write(&artifact, b"original").unwrap();
    let generated = run(&["keygen", "--out", base.to_str().unwrap()]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    let public = public_path(&base);
    let signed = run(&[
        "sign",
        artifact.to_str().unwrap(),
        "--key",
        base.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
    ]);
    assert!(signed.status.success(), "{}", stderr(&signed));
    fs::write(&artifact, b"modified").unwrap();

    let verified = run(&[
        "verify",
        artifact.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        public.to_str().unwrap(),
    ]);
    assert_eq!(verified.status.code(), Some(1));
    assert!(stderr(&verified).contains("does not match"));
    remove_all([&base, &public, &artifact, &signature]);
}

#[test]
fn tampered_signed_metadata_is_rejected_as_invalid_signature() {
    let base = unique_path("key");
    let artifact = unique_path("artifact");
    let signature = unique_path("signature");
    fs::write(&artifact, b"release").unwrap();
    let generated = run(&["keygen", "--out", base.to_str().unwrap()]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    let public = public_path(&base);
    let signed = run(&[
        "sign",
        artifact.to_str().unwrap(),
        "--key",
        base.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
    ]);
    assert!(signed.status.success(), "{}", stderr(&signed));

    let mut record = fs::read_to_string(&signature).unwrap();
    let digest_line = record
        .lines()
        .position(|line| line.starts_with("digest "))
        .unwrap();
    let mut lines: Vec<String> = record.lines().map(str::to_owned).collect();
    let digest = lines[digest_line].strip_prefix("digest ").unwrap();
    let replacement = if digest.starts_with('0') { '1' } else { '0' };
    lines[digest_line] = format!("digest {replacement}{}", &digest[1..]);
    record = format!("{}\n", lines.join("\n"));
    fs::write(&signature, record).unwrap();

    let verified = run(&[
        "verify",
        artifact.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        public.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(verified.status.code(), Some(2));
    assert!(stderr(&verified).contains("signature is invalid"));
    let result: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(result["signature_valid"], false);
    assert!(result["signer_trusted"].is_null());
    remove_all([&base, &public, &artifact, &signature]);
}

#[test]
fn a_different_explicit_public_key_is_untrusted() {
    let first = unique_path("first-key");
    let second = unique_path("second-key");
    let artifact = unique_path("artifact");
    let signature = unique_path("signature");
    fs::write(&artifact, b"release").unwrap();
    let one = run(&["keygen", "--out", first.to_str().unwrap()]);
    let two = run(&["keygen", "--out", second.to_str().unwrap()]);
    assert!(one.status.success(), "{}", stderr(&one));
    assert!(two.status.success(), "{}", stderr(&two));
    let signed = run(&[
        "sign",
        artifact.to_str().unwrap(),
        "--key",
        first.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
    ]);
    assert!(signed.status.success(), "{}", stderr(&signed));
    let wrong_key = public_path(&second);
    let verified = run(&[
        "verify",
        artifact.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        wrong_key.to_str().unwrap(),
    ]);
    assert_eq!(verified.status.code(), Some(3));
    remove_all([
        &first,
        &public_path(&first),
        &second,
        &wrong_key,
        &artifact,
        &signature,
    ]);
}

#[test]
fn key_and_signature_outputs_do_not_overwrite() {
    let base = unique_path("key");
    let artifact = unique_path("artifact");
    let signature = unique_path("signature");
    fs::write(&artifact, b"release").unwrap();
    let generated = run(&["keygen", "--out", base.to_str().unwrap()]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    let public = public_path(&base);
    let second_keygen = run(&["keygen", "--out", base.to_str().unwrap()]);
    assert!(!second_keygen.status.success());
    let signed = run(&[
        "sign",
        artifact.to_str().unwrap(),
        "--key",
        base.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
    ]);
    assert!(signed.status.success(), "{}", stderr(&signed));
    let second_sign = run(&[
        "sign",
        artifact.to_str().unwrap(),
        "--key",
        base.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
    ]);
    assert!(!second_sign.status.success());
    remove_all([&base, &public, &artifact, &signature]);
}

fn run(args: &[&str]) -> Output {
    let mut owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let key_flag = match args.first().copied() {
        Some("keygen") => "--out",
        Some("sign") => "--key",
        _ => "",
    };
    if !key_flag.is_empty() && !args.contains(&"--passphrase-file") {
        if let Some(index) = args.iter().position(|arg| *arg == key_flag) {
            let mut pass = PathBuf::from(args[index + 1]);
            pass.set_extension("test-passphrase");
            fs::write(&pass, b"test passphrase for seal\n").unwrap();
            owned.extend([
                "--passphrase-file".to_owned(),
                pass.to_string_lossy().into_owned(),
            ]);
        }
    }
    Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(owned)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn unique_path(suffix: &str) -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("seal-{suffix}-{}-{nonce}-{id}", std::process::id()))
}

fn public_path(private: &Path) -> PathBuf {
    let mut value = private.as_os_str().to_os_string();
    value.push(".pub");
    PathBuf::from(value)
}

fn remove_all<const N: usize>(paths: [&PathBuf; N]) {
    for path in paths {
        let _ = fs::remove_file(path);
        let mut pass = path.clone();
        pass.set_extension("test-passphrase");
        let _ = fs::remove_file(pass);
    }
}
