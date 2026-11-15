from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "scripts" / "finding_tools.py"
SPEC = importlib.util.spec_from_file_location("finding_tools", TOOLS)
assert SPEC is not None
finding_tools = importlib.util.module_from_spec(SPEC)
assert SPEC.name is not None
sys.modules[SPEC.name] = finding_tools
assert SPEC.loader is not None
SPEC.loader.exec_module(finding_tools)


def sample_finding(**overrides: object) -> dict:
    base = {
        "id": "F-20251115-001",
        "title": "SQL injection in lookup",
        "category": "sql_injection",
        "status": "candidate",
        "focus_area": "api",
        "locations": [{"file": "app/db.py", "line": 12, "function": "lookup"}],
        "entry_point": "HTTP GET /users",
        "trust_boundary": "untrusted query param to database",
        "attacker_control": "id query parameter",
        "source_to_sink": "request.args['id'] -> f-string SQL -> cursor.execute",
        "impact": "read arbitrary rows",
        "preconditions": ["endpoint reachable without auth"],
        "existing_mitigations_checked": ["ORM not used on this path"],
        "poc_path": None,
        "reproduction_steps": [],
        "confidence": "medium",
        "confidence_score": 0.75,
        "cwe_ids": ["CWE-89"],
        "owasp_category": "A03:2021-Injection",
        "reasoning_summary": "User input concatenated into SQL without parameterization",
    }
    base.update(overrides)
    return base


def sample_verified(**overrides: object) -> dict:
    base = {
        "finding_id": "F-20251115-001",
        "verdict": "true_positive",
        "exploitability": "confirmed",
        "evidence": ["f-string includes attacker-controlled id"],
        "disproof_attempts": ["checked for ORM wrapper; none"],
        "mitigations_found": [],
        "poc_result": "reproduced",
        "reproduction_steps": ["send id=1 OR 1=1"],
        "notes": "reachable from public endpoint",
        "confidence_score": 0.92,
    }
    base.update(overrides)
    return base


class FindingToolsTests(unittest.TestCase):
    def test_valid_finding_passes_validation(self) -> None:
        issues = finding_tools.validate_finding(sample_finding(), line_no=1)
        self.assertEqual(issues, [])

    def test_missing_source_to_sink_fails(self) -> None:
        issues = finding_tools.validate_finding(
            sample_finding(source_to_sink="short"), line_no=3
        )
        self.assertTrue(any("source_to_sink" in issue.message for issue in issues))

    def test_positive_verdict_requires_evidence(self) -> None:
        issues = finding_tools.validate_verified(
            sample_verified(evidence=[]), line_no=2
        )
        self.assertTrue(any("evidence" in issue.message for issue in issues))

    def test_fingerprint_is_stable(self) -> None:
        f1 = sample_finding()
        f2 = sample_finding(title="different title only")
        self.assertEqual(
            finding_tools.finding_fingerprint(f1),
            finding_tools.finding_fingerprint(f2),
        )

    def test_export_sarif_writes_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "SECURITY_REVIEW"
            root.mkdir()
            findings_path = root / "FINDINGS.jsonl"
            verified_path = root / "VERIFIED.jsonl"
            findings_path.write_text(json.dumps(sample_finding()) + "\n", encoding="utf-8")
            verified_path.write_text(json.dumps(sample_verified()) + "\n", encoding="utf-8")
            out = root / "FINDINGS.sarif"
            count = finding_tools.export_sarif(findings_path, verified_path, out)
            self.assertEqual(count, 1)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], "2.1.0")
            self.assertEqual(len(payload["runs"][0]["results"]), 1)
            self.assertIn("llmSourceSecurityReviewHash", payload["runs"][0]["results"][0]["partialFingerprints"])

    def test_validate_findings_file_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "FINDINGS.jsonl"
            path.write_text(json.dumps(sample_finding()) + "\n", encoding="utf-8")
            self.assertEqual(finding_tools.validate_findings_file(path), [])

    def test_invalid_jsonl_line_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "FINDINGS.jsonl"
            path.write_text("not-json\n", encoding="utf-8")
            issues = finding_tools.validate_findings_file(path)
            self.assertTrue(any("invalid JSON" in issue.message for issue in issues))

    def test_severity_to_sarif_level(self) -> None:
        self.assertEqual(finding_tools.severity_to_sarif_level("critical"), "error")
        self.assertEqual(finding_tools.severity_to_sarif_level("low"), "note")

    def test_build_sarif_skips_false_positives(self) -> None:
        findings = [sample_finding()]
        verified = {findings[0]["id"]: sample_verified(verdict="false_positive")}
        sarif = finding_tools.build_sarif_log(findings, verified)
        self.assertEqual(sarif["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()