"""Validate security-review JSONL findings and export SARIF 2.1.0."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

TOOL_NAME = "llm-source-security-review"
TOOL_VERSION = "0.2.0"
SARIF_VERSION = "2.1.0"

FINDING_STATUSES = frozenset({"candidate", "candidate_with_poc", "weak_candidate"})
CONFIDENCE_LABELS = frozenset({"low", "medium", "high"})
VERDICTS = frozenset(
    {
        "true_positive",
        "probable_true_positive",
        "unproven",
        "false_positive",
        "duplicate",
    }
)
EXPLOITABILITY = frozenset({"confirmed", "plausible", "not_shown", "disproved"})
POC_RESULTS = frozenset({"reproduced", "failed", "not_available", "not_run"})

REQUIRED_FINDING_KEYS = frozenset(
    {
        "id",
        "title",
        "category",
        "status",
        "locations",
        "entry_point",
        "trust_boundary",
        "attacker_control",
        "source_to_sink",
        "impact",
        "preconditions",
        "existing_mitigations_checked",
        "confidence",
        "reasoning_summary",
    }
)

REQUIRED_VERIFIED_KEYS = frozenset(
    {
        "finding_id",
        "verdict",
        "exploitability",
        "evidence",
        "disproof_attempts",
        "mitigations_found",
        "poc_result",
        "notes",
    }
)

CWE_PATTERN = re.compile(r"^CWE-\d+$")


@dataclass(frozen=True)
class ValidationIssue:
    line: int
    message: str


def _parse_jsonl(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], list[ValidationIssue]]:
    issues: list[ValidationIssue] = []
    records: list[tuple[int, dict[str, Any]]] = []
    if not path.exists() or path.stat().st_size == 0:
        return records, issues
    text = path.read_text(encoding="utf-8")
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            issues.append(ValidationIssue(line_no, f"invalid JSON: {exc.msg}"))
            continue
        if not isinstance(obj, dict):
            issues.append(ValidationIssue(line_no, "each line must be a JSON object"))
            continue
        records.append((line_no, obj))
    return records, issues


def _check_locations(locations: Any, line_no: int, issues: list[ValidationIssue]) -> None:
    if not isinstance(locations, list) or not locations:
        issues.append(ValidationIssue(line_no, "locations must be a non-empty list"))
        return
    for item in locations:
        if not isinstance(item, dict) or "file" not in item:
            issues.append(ValidationIssue(line_no, "each location must include file"))
            return


def _check_string_list(value: Any, field: str, line_no: int, issues: list[ValidationIssue]) -> None:
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        issues.append(ValidationIssue(line_no, f"{field} must be a list of strings"))


def _check_cwe_ids(value: Any, line_no: int, issues: list[ValidationIssue]) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        issues.append(ValidationIssue(line_no, "cwe_ids must be a list of CWE-### strings"))
        return
    for cwe in value:
        if not isinstance(cwe, str) or not CWE_PATTERN.match(cwe):
            issues.append(ValidationIssue(line_no, f"invalid CWE id: {cwe!r}"))
            return


def _check_confidence_score(value: Any, line_no: int, issues: list[ValidationIssue]) -> None:
    if value is None:
        return
    if not isinstance(value, (int, float)) or not (0.0 <= float(value) <= 1.0):
        issues.append(ValidationIssue(line_no, "confidence_score must be a number between 0 and 1"))


def validate_finding(obj: dict[str, Any], line_no: int) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    missing = REQUIRED_FINDING_KEYS - obj.keys()
    for key in sorted(missing):
        issues.append(ValidationIssue(line_no, f"missing required field: {key}"))
    if "status" in obj and obj["status"] not in FINDING_STATUSES:
        issues.append(ValidationIssue(line_no, f"invalid status: {obj['status']!r}"))
    if "confidence" in obj and obj["confidence"] not in CONFIDENCE_LABELS:
        issues.append(ValidationIssue(line_no, f"invalid confidence: {obj['confidence']!r}"))
    if "locations" in obj:
        _check_locations(obj["locations"], line_no, issues)
    for field in ("preconditions", "existing_mitigations_checked", "reproduction_steps"):
        if field in obj:
            _check_string_list(obj[field], field, line_no, issues)
    if "source_to_sink" in obj and isinstance(obj["source_to_sink"], str):
        if len(obj["source_to_sink"].strip()) < 10:
            issues.append(
                ValidationIssue(line_no, "source_to_sink must summarize data/control flow (min length)")
            )
    if "reasoning_summary" in obj and isinstance(obj["reasoning_summary"], str):
        if len(obj["reasoning_summary"].strip()) < 12:
            issues.append(
                ValidationIssue(line_no, "reasoning_summary must cite concrete evidence")
            )
    _check_cwe_ids(obj.get("cwe_ids"), line_no, issues)
    _check_confidence_score(obj.get("confidence_score"), line_no, issues)
    return issues


def validate_verified(obj: dict[str, Any], line_no: int) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    missing = REQUIRED_VERIFIED_KEYS - obj.keys()
    for key in sorted(missing):
        issues.append(ValidationIssue(line_no, f"missing required field: {key}"))
    if "verdict" in obj and obj["verdict"] not in VERDICTS:
        issues.append(ValidationIssue(line_no, f"invalid verdict: {obj['verdict']!r}"))
    if "exploitability" in obj and obj["exploitability"] not in EXPLOITABILITY:
        issues.append(ValidationIssue(line_no, f"invalid exploitability: {obj['exploitability']!r}"))
    if "poc_result" in obj and obj["poc_result"] not in POC_RESULTS:
        issues.append(ValidationIssue(line_no, f"invalid poc_result: {obj['poc_result']!r}"))
    for field in ("evidence", "disproof_attempts", "mitigations_found", "reproduction_steps"):
        if field in obj:
            _check_string_list(obj[field], field, line_no, issues)
    if obj.get("verdict") in {"true_positive", "probable_true_positive"}:
        evidence = obj.get("evidence", [])
        if not evidence:
            issues.append(
                ValidationIssue(line_no, "positive verdicts require non-empty evidence list")
            )
    _check_confidence_score(obj.get("confidence_score"), line_no, issues)
    return issues


def validate_findings_file(path: Path) -> list[ValidationIssue]:
    records, issues = _parse_jsonl(path)
    for line_no, obj in records:
        issues.extend(validate_finding(obj, line_no))
    return issues


def validate_verified_file(path: Path) -> list[ValidationIssue]:
    records, issues = _parse_jsonl(path)
    for line_no, obj in records:
        issues.extend(validate_verified(obj, line_no))
    return issues


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Stable dedup hash from category, locations, and source-to-sink summary."""
    parts: list[str] = [
        str(finding.get("category", "")),
        str(finding.get("source_to_sink", "")),
        str(finding.get("entry_point", "")),
    ]
    for loc in finding.get("locations", []) or []:
        if isinstance(loc, dict):
            parts.append(f"{loc.get('file')}:{loc.get('line')}:{loc.get('function', '')}")
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def severity_to_sarif_level(severity: str | None) -> str:
    if not severity:
        return "warning"
    normalized = severity.strip().lower()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized in {"medium"}:
        return "warning"
    return "note"


def _confidence_from_verdict(verdict: str) -> float:
    return {
        "true_positive": 0.95,
        "probable_true_positive": 0.8,
        "unproven": 0.5,
        "false_positive": 0.1,
        "duplicate": 0.0,
    }.get(verdict, 0.5)


def build_sarif_log(
    findings: Iterable[dict[str, Any]],
    verified_by_id: dict[str, dict[str, Any]],
    *,
    include_unproven: bool = False,
) -> dict[str, Any]:
    """Build SARIF 2.1.0 from findings paired with verification records."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    export_verdicts = {"true_positive", "probable_true_positive"}
    if include_unproven:
        export_verdicts.add("unproven")

    for finding in findings:
        fid = str(finding.get("id", ""))
        verified = verified_by_id.get(fid)
        if not verified:
            continue
        verdict = verified.get("verdict")
        if verdict not in export_verdicts:
            continue

        category = str(finding.get("category", "security"))
        rule_id = re.sub(r"[^a-zA-Z0-9._-]+", "-", category.lower())[:64] or "security-issue"
        if rule_id not in rules:
            cwe_ids = finding.get("cwe_ids") or []
            tags = ["security", "llm-assisted-review"]
            tags.extend(cwe_ids)
            rules[rule_id] = {
                "id": rule_id,
                "name": category,
                "shortDescription": {"text": category},
                "fullDescription": {"text": finding.get("title", category)},
                "defaultConfiguration": {"level": "warning"},
                "properties": {
                    "tags": tags,
                    "precision": "medium",
                },
            }

        locations_payload: list[dict[str, Any]] = []
        for loc in finding.get("locations") or []:
            if not isinstance(loc, dict) or not loc.get("file"):
                continue
            region: dict[str, int] = {}
            line = loc.get("line")
            if isinstance(line, int) and line > 0:
                region["startLine"] = line
            locations_payload.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(loc["file"])},
                        **({"region": region} if region else {}),
                    }
                }
            )

        fingerprint = finding_fingerprint(finding)
        score = verified.get("confidence_score")
        if score is None:
            score = _confidence_from_verdict(str(verdict))

        message_bits = [
            str(finding.get("title", "")),
            str(verified.get("notes", "")),
        ]
        message = " ".join(bit for bit in message_bits if bit).strip() or category

        results.append(
            {
                "ruleId": rule_id,
                "level": severity_to_sarif_level(finding.get("severity")),
                "message": {"text": message[:4000]},
                **({"locations": locations_payload} if locations_payload else {}),
                "partialFingerprints": {"llmSourceSecurityReviewHash": fingerprint},
                "properties": {
                    "finding_id": fid,
                    "verdict": verdict,
                    "exploitability": verified.get("exploitability"),
                    "confidence_score": score,
                    "cwe_ids": finding.get("cwe_ids"),
                    "owasp_category": finding.get("owasp_category"),
                },
            }
        )

    rule_list = list(rules.values())
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/carlok/llm-source-security-review",
                        "rules": rule_list,
                    }
                },
                "results": results,
            }
        ],
    }


def load_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    records, _ = _parse_jsonl(path)
    return [obj for _, obj in records]


def export_sarif(
    findings_path: Path,
    verified_path: Path,
    output_path: Path,
    *,
    include_unproven: bool = False,
) -> int:
    findings = load_jsonl_objects(findings_path)
    verified = load_jsonl_objects(verified_path)
    verified_by_id = {
        str(row.get("finding_id")): row for row in verified if row.get("finding_id")
    }
    sarif = build_sarif_log(findings, verified_by_id, include_unproven=include_unproven)
    output_path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
    return len(sarif["runs"][0]["results"])