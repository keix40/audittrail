"""Optional LLM summary with deterministic fallback."""

from __future__ import annotations

import json

import httpx
from audittrail.config import get_settings
from audittrail.schemas.finding import NormalizedFinding, Severity


def _fallback_summary(findings: list[NormalizedFinding]) -> tuple[str, bool]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    if not findings:
        return "No security findings detected. Scan passed.", False
    top = findings[:5]
    lines = [
        f"Scan found {len(findings)} issue(s): "
        + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
        "",
        "Top findings:",
    ]
    for i, f in enumerate(top, 1):
        loc = f"{f.file_path}:{f.line_start}" if f.file_path else "n/a"
        lines.append(f"{i}. [{f.severity.value}] {f.title} ({loc})")
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
        lines.append("")
        lines.append("Recommendation: address critical/high items before merge.")
    return "\n".join(lines), False


def generate_summary(findings: list[NormalizedFinding]) -> tuple[str, bool]:
    settings = get_settings()
    if not settings.llm_provider or not settings.llm_api_key:
        return _fallback_summary(findings)

    prompt = (
        "Summarize these security scan findings for a pull request review in 3-5 sentences. "
        "Include suggested fixes.\n\n"
        + json.dumps(
            [
                {
                    "severity": f.severity.value,
                    "title": f.title,
                    "file": f.file_path,
                    "line": f.line_start,
                }
                for f in findings[:20]
            ],
            indent=2,
        )
    )

    try:
        if settings.llm_provider == "openai":
            base = settings.llm_base_url or "https://api.openai.com/v1"
            resp = httpx.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {settings.llm_api_key}"},
                json={
                    "model": settings.llm_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a senior application security engineer.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 500,
                },
                timeout=30.0,
            )
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"]
            return text.strip(), True
    except Exception:
        pass

    return _fallback_summary(findings)
