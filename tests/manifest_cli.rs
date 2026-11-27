use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

mod common;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn creates_canonical_sorted_manifest() {
    let root = unique_path("root");
    let output_path = unique_path("manifest");
    fs::create_dir_all(root.join("nested")).unwrap();
    fs::write(root.join("z.txt"), b"z").unwrap();
    fs::write(root.join("nested/a.txt"), b"abc").unwrap();

    let result = run(&[
        "manifest",
        "create",
        root.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
    ]);

    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(
        fs::read(&output_path).unwrap(),
        concat!(
            "{\"version\":1,\"algorithm\":\"sha256\",\"files\":[",
            "{\"path\":\"nested/a.txt\",\"size\":3,\"digest\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"},",
            "{\"path\":\"z.txt\",\"size\":1,\"digest\":\"594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06\"}",
            "]}\n"
        )
        .as_bytes()
    );
    remove_all([&root, &output_path]);
}

#[cfg(unix)]
#[test]
fn reports_unreadable_file_as_an_operational_failure() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_path("unreadable-root");
    let output_path = unique_path("unreadable-manifest");
    fs::create_dir_all(&root).unwrap();
    let file = root.join("private.dat");
    fs::write(&file, b"not readable by the test process").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o0)).unwrap();

    let result = run(&[
        "manifest",
        "create",
        root.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
    ]);

    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(result.status.code(), Some(5), "{}", stderr(&result));
    assert!(!output_path.exists());
    remove_all([&root, &output_path]);
}

#[cfg(unix)]
#[test]
fn concurrent_file_to_symlink_replacement_never_hashes_outside_target() {
    use sha2::Digest;
    use std::{
        os::unix::fs::symlink,
        sync::{Arc, atomic::AtomicBool},
        thread,
        time::Duration,
    };

    let root = unique_path("race-root");
    let outside_dir = unique_path("race-outside");
    let output_path = unique_path("race-manifest");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();
    let path = root.join("subject.bin");
    let outside_path = outside_dir.join("outside.bin");
    let inside_bytes = vec![b'I'; 2 * 1024 * 1024];
    let outside_bytes = vec![b'O'; 2 * 1024 * 1024];
    fs::write(&path, &inside_bytes).unwrap();
    fs::write(&outside_path, &outside_bytes).unwrap();
    let outside_digest = format!("{:x}", sha2::Sha256::digest(&outside_bytes));

    let stop = Arc::new(AtomicBool::new(false));
    let racer_stop = Arc::clone(&stop);
    let racer_path = path.clone();
    let racer_target = outside_path.clone();
    let racer_bytes = inside_bytes.clone();
    let racer = thread::spawn(move || {
        while !racer_stop.load(Ordering::Relaxed) {
            let _ = fs::remove_file(&racer_path);
            let _ = symlink(&racer_target, &racer_path);
            thread::sleep(Duration::from_micros(100));
            let _ = fs::remove_file(&racer_path);
            let _ = fs::write(&racer_path, &racer_bytes);
            thread::sleep(Duration::from_micros(100));
        }
    });

    let mut outcomes = Vec::new();
    for attempt in 0..8 {
        let output = output_path.with_extension(format!("{attempt}.json"));
        outcomes.push((
            run_with_timeout(
                &[
                    "manifest",
                    "create",
                    root.to_str().unwrap(),
                    "--output",
                    output.to_str().unwrap(),
                ],
                Duration::from_secs(5),
            ),
            output,
        ));
    }
    stop.store(true, Ordering::Relaxed);
    racer.join().unwrap();

    for (result, output) in outcomes {
        assert!(
            result.status.success() || matches!(result.status.code(), Some(4 | 5)),
            "unexpected exit status {:?}: {}",
            result.status.code(),
            stderr(&result)
        );
        if result.status.success() {
            let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap())
                .expect("successful manifest must be valid JSON");
            assert!(
                manifest["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|file| { file["digest"].as_str() != Some(outside_digest.as_str()) }),
                "manifest followed a symlink to content outside its root"
            );
        }
        let _ = fs::remove_file(output);
    }
    remove_all([&root, &outside_dir, &output_path]);
}

#[cfg(unix)]
fn run_with_timeout(args: &[&str], timeout: std::time::Duration) -> std::process::Output {
    common::output_with_timeout(Command::new(env!("CARGO_BIN_EXE_seal")).args(args), timeout)
}

#[test]
fn verifies_empty_directory_and_reports_success_as_json() {
    let root = unique_path("empty-root");
    let manifest = unique_path("empty-manifest");
    let signature = unique_path("empty-signature");
    let key = unique_path("empty-key");
    fs::create_dir_all(&root).unwrap();

    let created = run(&[
        "manifest",
        "create",
        root.to_str().unwrap(),
        "--output",
        manifest.to_str().unwrap(),
    ]);
    assert!(created.status.success(), "{}", stderr(&created));
    let generated = run(&["keygen", "--out", key.to_str().unwrap()]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    let signed = run(&[
        "manifest",
        "sign",
        manifest.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--output",
        signature.to_str().unwrap(),
    ]);
    assert!(signed.status.success(), "{}", stderr(&signed));
    let public = public_path(&key);
    let verified = run(&[
        "manifest",
        "verify",
        manifest.to_str().unwrap(),
        "--root",
        root.to_str().unwrap(),
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
    assert_eq!(result["matched_files"], 0);

    remove_all([&root, &manifest, &signature, &key, &public]);
}

#[test]
fn verification_fails_on_missing_modified_and_unexpected_files() {
    let root = unique_path("verify-root");
    let manifest = unique_path("verify-manifest");
    let signature = unique_path("verify-signature");
    let key = unique_path("verify-key");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("keep.txt"), b"expected").unwrap();
    fs::write(root.join("change.txt"), b"before").unwrap();
    fs::write(root.join("missing.txt"), b"gone").unwrap();
    assert!(
        run(&[
            "manifest",
            "create",
            root.to_str().unwrap(),
            "--output",
            manifest.to_str().unwrap(),
        ])
        .status
        .success()
    );
    assert!(
        run(&["keygen", "--out", key.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        run(&[
            "manifest",
            "sign",
            manifest.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
            signature.to_str().unwrap(),
        ])
        .status
        .success()
    );

    fs::remove_file(root.join("missing.txt")).unwrap();
    fs::write(root.join("change.txt"), b"after!").unwrap();
    fs::write(root.join("extra.txt"), b"extra").unwrap();
    let public = public_path(&key);
    let verified = run(&[
        "manifest",
        "verify",
        manifest.to_str().unwrap(),
        "--root",
        root.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        public.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(verified.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(result["verified"], false);
    assert_eq!(result["signature_valid"], true);
    assert_eq!(result["signer_trusted"], true);
    assert_eq!(result["integrity_valid"], false);
    assert_eq!(result["missing_files"], 1);
    assert_eq!(result["modified_files"], 1);
    assert_eq!(result["unexpected_files"], 1);

    remove_all([&root, &manifest, &signature, &key, &public]);
}

#[test]
fn rejects_manifest_and_signature_output_inside_scanned_root() {
    let root = unique_path("contained-output-root");
    fs::create_dir_all(&root).unwrap();
    let inside_manifest = root.join("release.manifest");
    let result = run(&[
        "manifest",
        "create",
        root.to_str().unwrap(),
        "--output",
        inside_manifest.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(4));
    assert!(!inside_manifest.exists());
    remove_all([&root]);
}

#[test]
fn canonical_manifest_tampering_fails_the_manifest_signature_check() {
    let root = unique_path("tamper-root");
    let manifest = unique_path("tamper-manifest");
    let signature = unique_path("tamper-signature");
    let key = unique_path("tamper-key");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("payload.bin"), b"x").unwrap();
    assert!(
        run(&[
            "manifest",
            "create",
            root.to_str().unwrap(),
            "--output",
            manifest.to_str().unwrap(),
        ])
        .status
        .success()
    );
    assert!(
        run(&["keygen", "--out", key.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        run(&[
            "manifest",
            "sign",
            manifest.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
            signature.to_str().unwrap(),
        ])
        .status
        .success()
    );

    let manifest_bytes = fs::read_to_string(&manifest).unwrap();
    assert!(manifest_bytes.contains("\"size\":1"));
    fs::write(
        &manifest,
        manifest_bytes.replace("\"size\":1", "\"size\":2"),
    )
    .unwrap();
    let public = public_path(&key);
    let result = run(&[
        "manifest",
        "verify",
        manifest.to_str().unwrap(),
        "--root",
        root.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        public.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["signature_valid"], true);
    assert_eq!(result["signer_trusted"], true);
    assert_eq!(result["integrity_valid"], false);

    remove_all([&root, &manifest, &signature, &key, &public]);
}

#[test]
fn file_signature_cannot_be_reused_as_a_manifest_signature() {
    let root = unique_path("object-root");
    let manifest = unique_path("object-manifest");
    let artifact = unique_path("object-artifact");
    let signature = unique_path("object-signature");
    let key = unique_path("object-key");
    fs::create_dir_all(&root).unwrap();
    fs::write(&artifact, b"file object").unwrap();
    assert!(
        run(&[
            "manifest",
            "create",
            root.to_str().unwrap(),
            "--output",
            manifest.to_str().unwrap(),
        ])
        .status
        .success()
    );
    assert!(
        run(&["keygen", "--out", key.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        run(&[
            "sign",
            artifact.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
            signature.to_str().unwrap(),
        ])
        .status
        .success()
    );
    let public = public_path(&key);

    let result = run(&[
        "manifest",
        "verify",
        manifest.to_str().unwrap(),
        "--root",
        root.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        public.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(7));

    remove_all([&root, &manifest, &artifact, &signature, &key, &public]);
}

#[test]
fn malformed_public_key_leaves_trust_status_unknown_in_json() {
    let root = unique_path("invalid-key-root");
    let manifest = unique_path("invalid-key-manifest");
    let signature = unique_path("invalid-key-signature");
    let key = unique_path("invalid-key-private");
    let public = public_path(&key);
    let bad_public = unique_path("invalid-key-public");
    fs::create_dir_all(&root).unwrap();
    assert!(
        run(&[
            "manifest",
            "create",
            root.to_str().unwrap(),
            "--output",
            manifest.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(
        run(&["keygen", "--out", key.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        run(&[
            "manifest",
            "sign",
            manifest.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
            signature.to_str().unwrap()
        ])
        .status
        .success()
    );
    fs::write(&bad_public, b"not a key\n").unwrap();
    let verified = run(&[
        "manifest",
        "verify",
        manifest.to_str().unwrap(),
        "--root",
        root.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        bad_public.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(verified.status.code(), Some(3));
    let output: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert!(output["signature_valid"].is_null());
    assert!(output["signer_trusted"].is_null());
    remove_all([&root, &manifest, &signature, &key, &public, &bad_public]);
}

#[cfg(unix)]
#[test]
fn rejects_symlinks_without_reading_the_target() {
    use std::os::unix::fs::symlink;

    let root = unique_path("symlink-root");
    let output_path = unique_path("symlink-manifest");
    fs::create_dir_all(&root).unwrap();
    let outside = unique_path("outside-target");
    fs::write(&outside, b"must not read").unwrap();
    symlink(&outside, root.join("link.txt")).unwrap();

    let result = run(&[
        "manifest",
        "create",
        root.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(4));
    assert!(!output_path.exists());
    remove_all([&root, &outside, &output_path]);
}

#[cfg(unix)]
#[test]
fn rejects_a_symbolic_link_as_the_scanned_root() {
    use std::os::unix::fs::symlink;
    let target = unique_path("root-link-target");
    let root_link = unique_path("root-link");
    let output_path = unique_path("root-link-manifest");
    fs::create_dir_all(&target).unwrap();
    symlink(&target, &root_link).unwrap();
    let result = run(&[
        "manifest",
        "create",
        root_link.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(4));
    assert!(!output_path.exists());
    remove_all([&target, &root_link, &output_path]);
}

#[cfg(windows)]
#[test]
fn rejects_directory_junctions() {
    let root = unique_path("junction-root");
    let target = unique_path("junction-target");
    let output_path = unique_path("junction-manifest");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("outside.txt"), b"not part of the root").unwrap();
    let junction = root.join("linked-dir");
    let linked = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            junction.to_str().unwrap(),
            target.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(linked.success(), "could not create test junction");

    let result = run(&[
        "manifest",
        "create",
        root.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(4));
    assert!(!output_path.exists());
    remove_all([&root, &target, &output_path]);
}

#[test]
fn inspects_canonical_manifest_as_versioned_json() {
    let root = unique_path("inspect-root");
    let manifest = unique_path("inspect-manifest");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("note.txt"), b"abc").unwrap();
    let created = run(&[
        "manifest",
        "create",
        root.to_str().unwrap(),
        "--output",
        manifest.to_str().unwrap(),
    ]);
    assert!(created.status.success(), "{}", stderr(&created));

    let inspected = run(&[
        "manifest",
        "inspect",
        manifest.to_str().unwrap(),
        "--json",
    ]);
    assert!(inspected.status.success(), "{}", stderr(&inspected));
    assert!(inspected.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["manifest_version"], 1);
    assert_eq!(value["algorithm"], "sha256");
    assert_eq!(value["files"], 1);
    assert_eq!(value["total_bytes"], 3);
    assert_eq!(value["entries"][0]["path"], "note.txt");
    assert_eq!(value["entries"][0]["size"], 3);
    assert_eq!(value["entries"][0]["digest"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    remove_all([&root, &manifest]);
}

#[test]
fn compares_manifests_with_sorted_added_removed_and_changed_paths() {
    let left_root = unique_path("compare-left-root");
    let right_root = unique_path("compare-right-root");
    let left_manifest = unique_path("compare-left-manifest");
    let right_manifest = unique_path("compare-right-manifest");
    fs::create_dir_all(&left_root).unwrap();
    fs::create_dir_all(&right_root).unwrap();
    fs::write(left_root.join("a.txt"), b"keep").unwrap();
    fs::write(left_root.join("b.txt"), b"before").unwrap();
    fs::write(right_root.join("b.txt"), b"after").unwrap();
    fs::write(right_root.join("c.txt"), b"new").unwrap();
    for (root, manifest) in [
        (&left_root, &left_manifest),
        (&right_root, &right_manifest),
    ] {
        let created = run(&[
            "manifest",
            "create",
            root.to_str().unwrap(),
            "--output",
            manifest.to_str().unwrap(),
        ]);
        assert!(created.status.success(), "{}", stderr(&created));
    }

    let compared = run(&[
        "manifest",
        "compare",
        left_manifest.to_str().unwrap(),
        right_manifest.to_str().unwrap(),
        "--json",
    ]);
    assert!(compared.status.success(), "{}", stderr(&compared));
    let value: serde_json::Value = serde_json::from_slice(&compared.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["identical"], false);
    assert_eq!(value["added"], serde_json::json!(["c.txt"]));
    assert_eq!(value["removed"], serde_json::json!(["a.txt"]));
    assert_eq!(value["changed"], serde_json::json!(["b.txt"]));
    assert_eq!(value["verifies_files_on_disk"], false);
    remove_all([&left_root, &right_root, &left_manifest, &right_manifest]);
}

#[test]
fn inspect_rejects_noncanonical_manifest() {
    let manifest = unique_path("inspect-invalid-manifest");
    fs::write(
        &manifest,
        br#"{ "version":1,"algorithm":"sha256","files":[]}"#,
    )
    .unwrap();
    let inspected = run(&["manifest", "inspect", manifest.to_str().unwrap()]);
    assert_eq!(inspected.status.code(), Some(4));
    assert!(stderr(&inspected).contains("canonical"));
    remove_all([&manifest]);
}

#[test]
fn inspect_rejects_manifest_larger_than_the_documented_limit() {
    let manifest = unique_path("inspect-oversized-manifest");
    fs::write(&manifest, vec![b' '; 16 * 1024 * 1024 + 1]).unwrap();
    let inspected = run(&["manifest", "inspect", manifest.to_str().unwrap()]);
    assert_eq!(inspected.status.code(), Some(4));
    assert!(stderr(&inspected).contains("16 MiB"));
    remove_all([&manifest]);
}

fn run(args: &[&str]) -> std::process::Output {
    let mut owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let key_flag = match args.first().copied() {
        Some("keygen") => "--out",
        Some("sign") => "--key",
        Some("manifest") if args.get(1) == Some(&"sign") => "--key",
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
    common::run(Command::new(env!("CARGO_BIN_EXE_seal")).args(owned))
}

fn stderr(output: &std::process::Output) -> String {
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

fn public_path(private: &std::path::Path) -> PathBuf {
    let mut value = private.as_os_str().to_os_string();
    value.push(".pub");
    PathBuf::from(value)
}

fn remove_all<const N: usize>(paths: [&PathBuf; N]) {
    for path in paths {
        if path.is_dir() {
            let _ = fs::remove_dir_all(path);
        } else {
            let _ = fs::remove_file(path);
        }
        let mut pass = path.clone();
        pass.set_extension("test-passphrase");
        let _ = fs::remove_file(pass);
    }
}
