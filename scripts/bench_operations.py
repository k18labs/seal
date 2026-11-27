import argparse
import hashlib
import json
import pathlib
import platform
import random
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--runs", type=int, default=7)
parser.add_argument("--binary", default="target/release/seal")
parser.add_argument("--large-mib", type=int, default=128)
parser.add_argument("--small-files", type=int, default=1000)
args = parser.parse_args()
if args.runs < 3 or args.large_mib < 1 or args.small_files < 1:
    raise SystemExit("runs, large-mib, and small-files must be positive; runs must be at least 3")

binary = str(pathlib.Path(args.binary).resolve())
work = pathlib.Path("operation-benchmark")
shutil.rmtree(work, ignore_errors=True)
work.mkdir()
many = work / "many"
many.mkdir()
for index in range(args.small_files):
    (many / f"item-{index:05}.dat").write_bytes(f"benchmark item {index}\n".encode())

large_root = work / "large-tree"
large_root.mkdir()
large = large_root / "large.bin"
block = random.Random(20261127).randbytes(1024 * 1024)
with large.open("wb") as output:
    remaining = args.large_mib * 1024 * 1024
    while remaining:
        chunk = block[: min(len(block), remaining)]
        output.write(chunk)
        remaining -= len(chunk)

artifact = work / "artifact.bin"
artifact.write_bytes(b"seal benchmark signature input\n")
passphrase = work / "passphrase.txt"
passphrase.write_text("benchmark-only-passphrase\n", encoding="utf-8")
key = work / "key"
subprocess.run(
    [binary, "keygen", "--out", str(key), "--passphrase-file", str(passphrase)],
    check=True,
    stdout=subprocess.DEVNULL,
)
public = pathlib.Path(f"{key}.pub")

many_manifest = work / "many.json"
large_manifest = work / "large.json"
manifest_signature = work / "many.sig"
file_signature = work / "artifact.sig"
commands = {
    "startup_version": f"{binary} version",
    "file_sign": f"{binary} sign {artifact} --key {key} --output {file_signature} --passphrase-file {passphrase}",
    "file_verify": f"{binary} verify {artifact} --signature {file_signature} --public-key {public}",
    "manifest_create_many_small": f"{binary} manifest create {many} --output {many_manifest}",
    "manifest_create_large_file": f"{binary} manifest create {large_root} --output {large_manifest}",
    "manifest_sign": f"{binary} manifest sign {many_manifest} --key {key} --output {manifest_signature} --passphrase-file {passphrase}",
    "manifest_verify": f"{binary} manifest verify {many_manifest} --root {many} --signature {manifest_signature} --public-key {public}",
}
prepares = {
    "file_sign": f"rm -f {file_signature}",
    "manifest_create_many_small": f"rm -f {many_manifest}",
    "manifest_create_large_file": f"rm -f {large_manifest}",
    "manifest_sign": f"rm -f {manifest_signature}",
}
for name in ("file_verify", "manifest_verify"):
    if name == "file_verify":
        subprocess.run(commands["file_sign"], shell=True, check=True, stdout=subprocess.DEVNULL)
    else:
        subprocess.run(commands["manifest_sign"], shell=True, check=True, stdout=subprocess.DEVNULL)

results = {}
for name, command in commands.items():
    hyperfine = ["hyperfine", "--warmup", "1", "--runs", str(args.runs)]
    if name in prepares:
        hyperfine += ["--prepare", prepares[name]]
    result_file = work / f"{name}.json"
    subprocess.run(hyperfine + ["--export-json", str(result_file), command], check=True)
    results[name] = json.loads(result_file.read_text(encoding="utf-8"))["results"][0]

peak_rss_kib = {}
for name, command in commands.items():
    if name in prepares:
        subprocess.run(prepares[name], shell=True, check=True)
    rss_file = work / f"{name}.rss"
    subprocess.run(
        ["/usr/bin/time", "-f", "%M", "-o", str(rss_file), "sh", "-c", command],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    peak_rss_kib[name] = int(rss_file.read_text(encoding="utf-8").strip())

metadata = {
    "os": platform.platform(),
    "machine": platform.machine(),
    "processor": platform.processor(),
    "rustc": subprocess.check_output(["rustc", "-Vv"], text=True).strip(),
    "seal_version": subprocess.check_output([binary, "version"], text=True).strip(),
    "runs": args.runs,
    "large_file_mib": args.large_mib,
    "many_small_file_count": args.small_files,
    "many_tree_manifest_sha256": hashlib.sha256(many_manifest.read_bytes()).hexdigest(),
    "binary_bytes": pathlib.Path(binary).stat().st_size,
    "timings": results,
    "peak_child_rss_kib": peak_rss_kib,
    "commands": commands,
    "notes": "Single-run peak RSS is a coarse process high-water measurement; timings use warm cache and include process startup.",
}
pathlib.Path("operation-benchmark.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
print(json.dumps(metadata, indent=2))
