import io
import tarfile
import zipfile
from pathlib import Path

import pytest
from audittrail.services.archive_extract import UnsafeArchiveError, extract_upload


def test_zip_path_traversal_rejected(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.txt", "bad")
    with pytest.raises(UnsafeArchiveError):
        extract_upload("bad.zip", buf.getvalue(), tmp_path / "out")


def test_tar_symlink_rejected(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    with pytest.raises(UnsafeArchiveError):
        extract_upload("bad.tar.gz", buf.getvalue(), tmp_path / "out")


def test_zip_extracts_safe_file(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/app.py", "x = 1\n")
    dest = tmp_path / "out"
    extract_upload("sample.zip", buf.getvalue(), dest)
    assert (dest / "src" / "app.py").read_text(encoding="utf-8") == "x = 1\n"
