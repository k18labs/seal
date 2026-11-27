use std::{
    fs,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

mod common;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn hashes_empty_file_as_sha256() {
    let path = unique_path();
    fs::write(&path, []).unwrap();
    let output = common::run(
        Command::new(env!("CARGO_BIN_EXE_seal")).args(["hash", path.to_str().unwrap()]),
    );
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
    let output = common::run(Command::new(env!("CARGO_BIN_EXE_seal")).args([
        "hash",
        path.to_str().unwrap(),
        "--json",
    ]));
    let _ = fs::remove_file(&path);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["algorithm"], "sha256");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(
        value["digest"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn completion_scripts_cover_bash_zsh_fish_and_powershell_command_tree() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let output =
            common::run(Command::new(env!("CARGO_BIN_EXE_seal")).args(["completions", shell]));
        assert!(
            output.status.success(),
            "{shell} completion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let script = String::from_utf8(output.stdout).unwrap();
        assert!(
            script.contains("seal"),
            "{shell} completion has no command name"
        );
        for command in ["hash", "manifest", "verify"] {
            assert!(
                script.contains(command),
                "{shell} completion is missing {command}"
            );
        }
    }
}

#[test]
fn manifest_create_accepts_optional_progress_flag() {
    let root = unique_path();
    let output_path = unique_path();
    fs::create_dir_all(&root).unwrap();
    let output = common::run(Command::new(env!("CARGO_BIN_EXE_seal")).args([
        "manifest",
        "create",
        root.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
        "--progress",
        "--json",
    ]));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_file(&output_path);
}

#[test]
fn hashes_standard_input_with_bounded_reader() {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["hash", "-", "--json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"abc").unwrap();
    let output = common::wait_with_timeout(child, std::time::Duration::from_secs(60));
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["path"], "-");
    assert_eq!(
        value["digest"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn rejects_directory_input() {
    let output = common::run(Command::new(env!("CARGO_BIN_EXE_seal")).args(["hash", "."]));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a regular file"));
}

#[test]
fn unsupported_algorithm_has_stable_exit_code() {
    let path = unique_path();
    fs::write(&path, b"abc").unwrap();
    let output = common::run(Command::new(env!("CARGO_BIN_EXE_seal")).args([
        "hash",
        path.to_str().unwrap(),
        "--algorithm",
        "md5",
    ]));
    let _ = fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn large_file_is_hashed_correctly() {
    let path = unique_path();
    let bytes = vec![0x5au8; 8 * 1024 * 1024];
    fs::write(&path, &bytes).unwrap();
    let output = common::run(
        Command::new(env!("CARGO_BIN_EXE_seal")).args(["hash", path.to_str().unwrap()]),
    );
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
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("seal-test-{}-{nonce}-{id}", std::process::id()))
}
