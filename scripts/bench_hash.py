import argparse
import json
import os
import pathlib
import platform
import random
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--size-mib", type=int, default=256)
parser.add_argument("--runs", type=int, default=7)
parser.add_argument("--binary", default="target/release/seal")
args = parser.parse_args()
if args.size_mib < 1 or args.runs < 3:
    raise SystemExit("size must be positive and runs must be at least 3")
file = pathlib.Path("benchmark-input.bin")
length = args.size_mib * 1024 * 1024
block = random.Random(20261126).randbytes(1024 * 1024)
with file.open("wb") as out:
    while out.tell() < length:
        out.write(block[: min(len(block), length - out.tell())])
commands = [
    f"{args.binary} hash benchmark-input.bin --algorithm sha256",
    "sha256sum benchmark-input.bin",
]
if shutil.which("b3sum"):
    commands.extend([
        f"{args.binary} hash benchmark-input.bin --algorithm blake3",
        "b3sum benchmark-input.bin",
    ])
hyperfine = ["hyperfine", "--warmup", "2", "--runs", str(args.runs), "--export-json", "hash-bench.json", *commands]
subprocess.run(hyperfine, check=True)
metadata = {
    "os": platform.platform(),
    "machine": platform.machine(),
    "processor": platform.processor(),
    "python": sys.version,
    "rustc": subprocess.check_output(["rustc", "-Vv"], text=True).strip(),
    "seal_version": subprocess.check_output([args.binary, "version"], text=True).strip(),
    "input_mib": args.size_mib,
    "input_sha256": subprocess.check_output(["sha256sum", str(file)], text=True).split()[0],
    "runs": args.runs,
    "commands": commands,
    "notes": "Warm-cache hash throughput and process startup; RSS and signature operation comparisons are not measured by this workflow.",
}
pathlib.Path("benchmark-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
