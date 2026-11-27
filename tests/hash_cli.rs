use std::{fs, process::Command, time::SystemTime};

#[test]
fn hashes_empty_file_as_sha256() {
    let path = unique_path();
    fs::write(&path, []).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["hash", path.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = fs::remove_file(&path);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ")
    );
}

#[test]
fn json_output_is_machine_readable() {
    let path = unique_path();
    fs::write(&path, b"abc").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["hash", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    let _ = fs::remove_file(&path);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["algorithm"], "sha256");
    assert_eq!(
        value["digest"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn rejects_directory_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["hash", "."])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a regular file"));
}

#[test]
fn unsupported_algorithm_has_stable_exit_code() {
    let path = unique_path();
    fs::write(&path, b"abc").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["hash", path.to_str().unwrap(), "--algorithm", "md5"])
        .output()
        .unwrap();
    let _ = fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn large_file_is_hashed_correctly() {
    let path = unique_path();
    let bytes = vec![0x5au8; 8 * 1024 * 1024];
    fs::write(&path, &bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["hash", path.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = fs::remove_file(&path);
    assert!(output.status.success());
    use sha2::Digest;
    let expected = format!("{:x}", sha2::Sha256::digest(&bytes));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with(&expected)
    );
}

fn unique_path() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("seal-test-{}-{nanos}", std::process::id()))
}
