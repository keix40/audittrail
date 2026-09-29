from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from audittrail.services import github_client


def test_clone_repository_at_sha_uses_token_head_repo_and_detached_sha(tmp_path: Path) -> None:
    dest = tmp_path / "workspace"
    calls: list[tuple[list[str], Path | None]] = []

    def fake_run(
        cmd: list[str],
        *,
        check: bool = False,
        capture_output: bool = False,
        timeout: float | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del check, capture_output, timeout
        calls.append((cmd, cwd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    with (
        patch.object(github_client, "_installation_token", return_value="inst-token-secret"),
        patch.object(github_client.subprocess, "run", side_effect=fake_run),
    ):
        github_client.clone_repository_at_sha(
            "contributor/fork-repo",
            "abc123deadbeef",
            4242,
            dest,
        )

    assert len(calls) == 3
    clone_cmd, clone_cwd = calls[0]
    assert clone_cwd is None
    assert clone_cmd[0:3] == ["git", "clone", "--no-checkout"]
    assert clone_cmd[-1] == str(dest)
    assert "x-access-token:inst-token-secret@github.com/contributor/fork-repo.git" in clone_cmd[-2]

    fetch_cmd, fetch_cwd = calls[1]
    assert fetch_cwd == dest
    assert fetch_cmd == ["git", "fetch", "--depth", "1", "origin", "abc123deadbeef"]

    checkout_cmd, checkout_cwd = calls[2]
    assert checkout_cwd == dest
    assert checkout_cmd == ["git", "checkout", "--detach", "abc123deadbeef"]
