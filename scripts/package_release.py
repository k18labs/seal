import gzip
import hashlib
import io
import pathlib
import stat
import sys
import tarfile
import zipfile

artifact_target, archive_format = sys.argv[1:]
root = pathlib.Path("dist") / "seal"
root.mkdir(parents=True, exist_ok=True)
binary = pathlib.Path("target") / artifact_target / "release" / ("seal.exe" if "windows" in artifact_target else "seal")
for source in (binary, pathlib.Path("LICENSE"), pathlib.Path("README.md")):
    (root / source.name).write_bytes(source.read_bytes())
archive = pathlib.Path(f"seal-{artifact_target}.{archive_format}")
files = sorted(root.iterdir(), key=lambda path: path.name.encode("utf-8"))
if archive_format == "zip":
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for file in files:
            info = zipfile.ZipInfo(f"seal/{file.name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | (0o755 if file == root / binary.name else 0o644)) << 16
            out.writestr(info, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
else:
    with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as out:
            for file in files:
                info = tarfile.TarInfo(f"seal/{file.name}")
                info.size = file.stat().st_size
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o755 if file == root / binary.name else 0o644
                out.addfile(info, io.BytesIO(file.read_bytes()))
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_name(archive.name + ".sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")