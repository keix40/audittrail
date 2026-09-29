"""Filter findings to lines changed in a pull request."""

from __future__ import annotations

import re
from dataclasses import dataclass

from audittrail.schemas.finding import NormalizedFinding

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class LineRange:
    start: int
    end: int


@dataclass(frozen=True)
class FileDiff:
    filename: str
    line_ranges: tuple[LineRange, ...]


def normalize_repo_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _merge_ranges(ranges: list[LineRange]) -> tuple[LineRange, ...]:
    if not ranges:
        return ()
    sorted_ranges = sorted(ranges, key=lambda r: r.start)
    merged: list[LineRange] = [sorted_ranges[0]]
    for current in sorted_ranges[1:]:
        last = merged[-1]
        if current.start <= last.end + 1:
            merged[-1] = LineRange(last.start, max(last.end, current.end))
        else:
            merged.append(current)
    return tuple(merged)


def line_ranges_from_patch(patch: str) -> tuple[LineRange, ...]:
    """Return line numbers on the PR head (new) side that were touched."""
    if not patch.strip():
        return ()

    touched: list[int] = []
    new_line = 0
    for raw in patch.splitlines():
        line = raw.rstrip("\n")
        if line.startswith("@@"):
            match = HUNK_RE.match(line)
            if match:
                new_line = int(match.group(1))
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            touched.append(new_line)
            new_line += 1
        elif line.startswith("-"):
            continue
        else:
            new_line += 1

    if not touched:
        return ()

    touched.sort()
    ranges: list[LineRange] = []
    start = touched[0]
    prev = touched[0]
    for num in touched[1:]:
        if num == prev + 1:
            prev = num
            continue
        ranges.append(LineRange(start, prev))
        start = num
        prev = num
    ranges.append(LineRange(start, prev))
    return _merge_ranges(ranges)


def file_diffs_from_github_files(files: list[dict[str, object]]) -> tuple[FileDiff, ...]:
    diffs: list[FileDiff] = []
    for entry in files:
        filename = str(entry.get("filename") or "")
        if not filename:
            continue
        patch = entry.get("patch")
        if isinstance(patch, str) and patch.strip():
            line_ranges = line_ranges_from_patch(patch)
        else:
            # Large or binary diffs omit patch — treat whole file as in scope.
            line_ranges = ()
        diffs.append(FileDiff(filename=normalize_repo_path(filename), line_ranges=line_ranges))
    return tuple(diffs)


def _finding_path(finding: NormalizedFinding) -> str | None:
    if not finding.file_path:
        return None
    return normalize_repo_path(finding.file_path)


def _line_in_ranges(line: int | None, ranges: tuple[LineRange, ...]) -> bool:
    if line is None:
        return True
    if not ranges:
        return True
    return any(r.start <= line <= r.end for r in ranges)


def finding_in_diff(finding: NormalizedFinding, scope: tuple[FileDiff, ...]) -> bool:
    path = _finding_path(finding)
    if path is None:
        target = (finding.raw or {}).get("Target") or finding.title
        path = normalize_repo_path(str(target)) if target else None
    if path is None:
        return False

    for file_diff in scope:
        if path != file_diff.filename and not path.endswith("/" + file_diff.filename):
            continue
        if not file_diff.line_ranges:
            return True
        start = finding.line_start
        end = finding.line_end or start
        if start is None and end is None:
            return True
        if start is not None and _line_in_ranges(start, file_diff.line_ranges):
            return True
        if end is not None and _line_in_ranges(end, file_diff.line_ranges):
            return True
        if start is not None and end is not None:
            return any(
                r.start <= end and r.end >= start for r in file_diff.line_ranges
            )
    return False


def filter_findings_to_diff(
    findings: list[NormalizedFinding],
    scope: tuple[FileDiff, ...],
) -> list[NormalizedFinding]:
    if not scope:
        return []
    return [f for f in findings if finding_in_diff(f, scope)]
