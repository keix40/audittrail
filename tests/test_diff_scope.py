from audittrail.schemas.finding import NormalizedFinding, ScannerName, Severity
from audittrail.services.diff_scope import (
    FileDiff,
    LineRange,
    filter_findings_to_diff,
    finding_in_diff,
    line_ranges_from_patch,
)

SAMPLE_PATCH = """\
@@ -1,3 +1,4 @@
 context
-old
+added line
 unchanged
"""


def test_line_ranges_from_patch() -> None:
    ranges = line_ranges_from_patch(SAMPLE_PATCH)
    assert ranges == (LineRange(start=2, end=2),)


def test_finding_in_diff_matches_line_and_file() -> None:
    scope = (FileDiff(filename="app.py", line_ranges=(LineRange(9, 9),)),)
    in_scope = NormalizedFinding(
        scanner=ScannerName.BANDIT,
        severity=Severity.HIGH,
        title="eval",
        description="",
        file_path="app.py",
        line_start=9,
    )
    out_scope = NormalizedFinding(
        scanner=ScannerName.GITLEAKS,
        severity=Severity.HIGH,
        title="secret",
        description="",
        file_path="app.py",
        line_start=5,
    )
    assert finding_in_diff(in_scope, scope) is True
    assert finding_in_diff(out_scope, scope) is False


def test_whole_file_when_patch_missing() -> None:
    scope = (FileDiff(filename="requirements.txt", line_ranges=()),)
    finding = NormalizedFinding(
        scanner=ScannerName.TRIVY,
        severity=Severity.HIGH,
        title="CVE",
        description="",
        file_path="requirements.txt",
    )
    assert finding_in_diff(finding, scope) is True


def test_normalize_repo_path_preserves_dotfiles() -> None:
    from audittrail.services.diff_scope import normalize_repo_path

    assert normalize_repo_path("./.env") == ".env"
    assert normalize_repo_path(".github/workflows/ci.yml") == ".github/workflows/ci.yml"


def test_filter_findings_to_diff() -> None:
    scope = (FileDiff(filename="app.py", line_ranges=(LineRange(9, 10),)),)
    findings = [
        NormalizedFinding(
            scanner=ScannerName.SEMGREP,
            severity=Severity.HIGH,
            title="a",
            description="",
            file_path="app.py",
            line_start=9,
        ),
        NormalizedFinding(
            scanner=ScannerName.GITLEAKS,
            severity=Severity.HIGH,
            title="b",
            description="",
            file_path="app.py",
            line_start=2,
        ),
    ]
    filtered = filter_findings_to_diff(findings, scope)
    assert len(filtered) == 1
    assert filtered[0].title == "a"
