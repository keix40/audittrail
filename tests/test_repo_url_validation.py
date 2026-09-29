import pytest
from audittrail.services.repo_url_validation import InvalidRepoUrlError, validate_repo_url


def test_rejects_http() -> None:
    with pytest.raises(InvalidRepoUrlError):
        validate_repo_url("http://github.com/org/repo.git")


def test_rejects_unknown_host() -> None:
    with pytest.raises(InvalidRepoUrlError):
        validate_repo_url("https://evil.example.com/org/repo.git")


def test_accepts_github_https() -> None:
    assert validate_repo_url("https://github.com/org/repo.git") == "github.com"
