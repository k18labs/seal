"""Portable, process-startup-inclusive Seal operation benchmark."""
import argparse
import hashlib
import json
import pathlib
import platform
import random
import shutil
import subprocess
import sys
import threading
import time

try:
    import psutil
except ImportError as error:
    raise SystemExit("install psutil before running this benchmark") from error

parser = argparse.ArgumentParser()
parser.add_argument("--runs", type=int, default=7)
parser.add_argument("--binary", default="target/release/seal")
parser.add_argument("--large-mib", type=int, default=128)
parser.add_argument("--small-files", type=int, default=1000)
args = parser.parse_args()
if args.runs < 3 or args.large_mib < 1 or args.small_files < 1:
    raise SystemExit("runs must be >=3; large-mib and small-files must be positive")

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
block = random.Random(20261127).randbytes(1024 * 1024)
with (large_root / "large.bin").open("wb") as output:
    remaining = args.large_mib * 1024 * 1024
    while remaining:
        chunk = block[:min(len(block), remaining)]
        output.write(chunk)
        remaining -= len(chunk)
artifact = work / "artifact.bin"
artifact.write_bytes(b"seal benchmark signature input\n")
passphrase = work / "passphrase.txt"
passphrase.write_text("benchmark-only-passphrase\n", encoding="utf-8")
key = work / "key"
subprocess.run([binary, "keygen", "--out", str(key), "--passphrase-file", str(passphrase)], check=True, stdout=subprocess.DEVNULL)
public = pathlib.Path(f"{key}.pub")
many_manifest, large_manifest = work / "many.json", work / "large.json"
manifest_signature, file_signature = work / "many.sig", work / "artifact.sig"
subprocess.run([binary, "manifest", "create", str(many), "--output", str(many_manifest)], check=True, stdout=subprocess.DEVNULL)
subprocess.run([binary, "manifest", "sign", str(many_manifest), "--key", str(key), "--output", str(manifest_signature), "--passphrase-file", str(passphrase)], check=True, stdout=subprocess.DEVNULL)
subprocess.run([binary, "sign", str(artifact), "--key", str(key), "--output", str(file_signature), "--passphrase-file", str(passphrase)], check=True, stdout=subprocess.DEVNULL)

operations = {
    "startup_version": [binary, "version"],
    "file_sign": [binary, "sign", str(artifact), "--key", str(key), "--output", str(file_signature), "--passphrase-file", str(passphrase)],
    "file_verify": [binary, "verify", str(artifact), "--signature", str(file_signature), "--public-key", str(public)],
    "manifest_create_many_small": [binary, "manifest", "create", str(many), "--output", str(many_manifest)],
    "manifest_create_large_file": [binary, "manifest", "create", str(large_root), "--output", str(large_manifest)],
    "manifest_sign": [binary, "manifest", "sign", str(many_manifest), "--key", str(key), "--output", str(manifest_signature), "--passphrase-file", str(passphrase)],
    "manifest_verify": [binary, "manifest", "verify", str(many_manifest), "--root", str(many), "--signature", str(manifest_signature), "--public-key", str(public)],
}
outputs = {"file_sign": file_signature, "manifest_create_many_small": many_manifest, "manifest_create_large_file": large_manifest, "manifest_sign": manifest_signature}

def measure(command, output=None):
    times, peaks = [], []
    for iteration in range(args.runs + 1):
        if output is not None:
            output.unlink(missing_ok=True)
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process = psutil.Process(proc.pid)
        peak = 0
        start = time.perf_counter()
        while proc.poll() is None:
            try:
                peak = max(peak, process.memory_info().rss)
            except psutil.NoSuchProcess:
                break
            time.sleep(0.01)
        elapsed = time.perf_counter() - start
        if proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, command)
        if iteration:
            times.append(elapsed)
            peaks.append(peak // 1024)
    ordered = sorted(times)
    return {"median_seconds": ordered[len(ordered)//2], "min_seconds": ordered[0], "max_seconds": ordered[-1], "peak_rss_kib_max": max(peaks)}

results = {}
for name, command in operations.items():
    results[name] = measure(command, outputs.get(name))

try:
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
except (OSError, subprocess.CalledProcessError):
    revision = "unknown"
metadata = {
    "source_revision": revision,
    "target": subprocess.check_output(["rustc", "-vV"], text=True).split("host: ")[-1].splitlines()[0],
    "build_profile": "release",
    "os": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
    "rustc": subprocess.check_output(["rustc", "-Vv"], text=True).strip(),
    "seal_version": subprocess.check_output([binary, "version"], text=True).strip(),
    "runs": args.runs, "warmups": 1, "large_file_mib": args.large_mib,
    "many_small_file_count": args.small_files,
    "many_tree_manifest_sha256": hashlib.sha256(many_manifest.read_bytes()).hexdigest(),
    "binary_bytes": pathlib.Path(binary).stat().st_size,
    "timings_and_peak_child_rss": results,
    "measurement": "warm cache, includes startup; peak RSS sampled every 10 ms and may miss brief peaks",
}
pathlib.Path("operation-benchmark.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
print(json.dumps(metadata, indent=2))
