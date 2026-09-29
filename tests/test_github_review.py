from unittest.mock import patch

import httpx
from audittrail.schemas.finding import NormalizedFinding, ScannerName, Severity
from audittrail.services.diff_scope import FileDiff, LineRange
from audittrail.services.github_client import post_review_comments


def test_review_strips_workspace_prefix_and_skips_out_of_diff() -> None:
    findings = [
        NormalizedFinding(
            scanner=ScannerName.BANDIT,
            severity=Severity.HIGH,
            title="in diff",
            description="d",
            file_path="/workspace/app.py",
            line_start=9,
        ),
        NormalizedFinding(
            scanner=ScannerName.GITLEAKS,
            severity=Severity.HIGH,
            title="out of diff",
            description="d",
            file_path="workspace/app.py",
            line_start=5,
        ),
    ]
    scope = (FileDiff(filename="app.py", line_ranges=(LineRange(9, 9),)),)
    captured: dict[str, object] = {}

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        captured["json"] = kwargs["json"]
        request = httpx.Request("POST", url)
        return httpx.Response(200, json={"id": 1}, request=request)

    with (
        patch("audittrail.services.github_client._installation_token", return_value="tok"),
        patch("audittrail.services.github_client.httpx.post", side_effect=fake_post),
    ):
        post_review_comments(
                "org/repo",
                1,
                99,
                "abc123",
                findings,
                "summary",
                diff_scope=scope,
        )

    body = captured["json"]
    assert isinstance(body, dict)
    assert body["comments"] == [
        {
            "path": "app.py",
            "line": 9,
            "body": "**[high] in diff**\n\nd",
        }
    ]
    assert "out of diff" in str(body["body"])
