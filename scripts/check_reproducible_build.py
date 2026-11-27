import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import platform

triple = sys.argv[1]
toolchain = sys.argv[2] if len(sys.argv) > 2 else "1.96.0"
exe = "seal.exe" if "windows" in triple else "seal"
binary = pathlib.Path("target") / triple / "release" / exe
cargo = ["cargo", f"+{toolchain}"]
subprocess.run(
    cargo + ["build", "--release", "--locked", "--target", triple],
    check=True,
    stdout=subprocess.DEVNULL,
)
with tempfile.TemporaryDirectory(prefix="seal-repro-") as temp:
    first = pathlib.Path(temp) / exe
    shutil.copyfile(binary, first)
    subprocess.run(cargo + ["clean", "--target", triple], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(
        cargo + ["build", "--release", "--locked", "--target", triple],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    first_bytes = first.read_bytes()
    second_bytes = binary.read_bytes()
    first_hash = hashlib.sha256(first_bytes).hexdigest()
    second_hash = hashlib.sha256(second_bytes).hexdigest()
    differing_offsets = [
        index
        for index, (first_byte, second_byte) in enumerate(zip(first_bytes, second_bytes))
        if first_byte != second_byte
    ][:32]
    result = {
        "target": triple,
        "host": platform.platform(),
        "host_machine": platform.machine(),
        "rustc": subprocess.check_output(["rustc", f"+{toolchain}", "-Vv"], text=True).strip(),
        "first_sha256": first_hash,
        "second_sha256": second_hash,
        "binary_bytes": len(second_bytes),
        "differing_offsets_sample": differing_offsets,
        "reproducible": first_bytes == second_bytes,
        "scope": "Two clean release builds on one runner image with Rust 1.96.0 and one target; this does not establish cross-host reproducibility.",
    }
    pathlib.Path(f"reproducibility-{triple}.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if first_bytes != second_bytes:
        shutil.copyfile(first, binary.with_name(f"{binary.stem}.first{binary.suffix}"))
        raise SystemExit("release binaries differ between clean builds")
