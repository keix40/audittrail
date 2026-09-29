"""Safe extraction of uploaded scan archives."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Literal

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
MAX_FILE_COUNT = 10_000
MAX_COMPRESSION_RATIO = 100


class UnsafeArchiveError(ValueError):
    pass


def _safe_member_path(name: str) -> Path:
    pure = PurePosixPath(name.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts:
        raise UnsafeArchiveError(f"Unsafe path in archive: {name}")
    return Path(*pure.parts)


def _check_limits(total_uncompressed: int, file_count: int, compressed_size: int) -> None:
    if file_count > MAX_FILE_COUNT:
        raise UnsafeArchiveError("Archive contains too many files")
    if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
        raise UnsafeArchiveError("Uncompressed size exceeds limit")
    if compressed_size > 0 and total_uncompressed / compressed_size > MAX_COMPRESSION_RATIO:
        raise UnsafeArchiveError("Archive compression ratio exceeds safe limit")


def extract_zip(raw: bytes, dest: Path) -> None:
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise UnsafeArchiveError("Archive exceeds maximum upload size")
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member_path = _safe_member_path(info.filename)
            total += info.file_size
            count += 1
            _check_limits(total, count, len(raw))
            target = dest / member_path
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                out.write(src.read())


def extract_tar(raw: bytes, dest: Path, *, gzip: bool) -> None:
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise UnsafeArchiveError("Archive exceeds maximum upload size")
    dest.mkdir(parents=True, exist_ok=True)
    tar_mode: Literal["r:gz", "r:"] = "r:gz" if gzip else "r:"
    total = 0
    count = 0
    file_members: list[tarfile.TarInfo] = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode=tar_mode) as tf:
        for member in tf.getmembers():
            if member.issym() or member.islnk():
                raise UnsafeArchiveError("Symlinks and hardlinks are not allowed")
            if not member.isfile():
                continue
            _safe_member_path(member.name)
            total += member.size
            count += 1
            _check_limits(total, count, len(raw))
            file_members.append(member)
        tf.extractall(path=dest, members=file_members, filter="data")


def extract_upload(filename: str, raw: bytes, dest: Path) -> None:
    lower = filename.lower()
    if lower.endswith(".zip"):
        extract_zip(raw, dest)
    elif lower.endswith((".tar.gz", ".tgz")):
        extract_tar(raw, dest, gzip=True)
    else:
        raise UnsafeArchiveError("Unsupported archive format")
