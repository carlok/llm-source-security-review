from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.name is not None
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CliScriptTests(unittest.TestCase):
    def test_validate_findings_main_ok_empty(self) -> None:
        mod = load_module("validate_findings_cli", SCRIPTS / "validate_findings.py")
        with tempfile.TemporaryDirectory() as tmp:
            review = Path(tmp) / "SECURITY_REVIEW"
            review.mkdir()
            (review / "FINDINGS.jsonl").write_text("", encoding="utf-8")
            (review / "VERIFIED.jsonl").write_text("", encoding="utf-8")
            with patch.object(sys, "argv", ["validate_findings.py", str(review)]):
                self.assertEqual(mod.main(), 0)

    def test_validate_findings_main_reports_issues(self) -> None:
        mod = load_module("validate_findings_bad", SCRIPTS / "validate_findings.py")
        with tempfile.TemporaryDirectory() as tmp:
            review = Path(tmp) / "SECURITY_REVIEW"
            review.mkdir()
            (review / "FINDINGS.jsonl").write_text("{}\n", encoding="utf-8")
            (review / "VERIFIED.jsonl").write_text("", encoding="utf-8")
            with patch.object(sys, "argv", ["validate_findings.py", str(review)]):
                self.assertEqual(mod.main(), 1)

    def test_export_sarif_main_missing_files(self) -> None:
        mod = load_module("export_sarif_missing", SCRIPTS / "export_sarif.py")
        with tempfile.TemporaryDirectory() as tmp:
            review = Path(tmp) / "SECURITY_REVIEW"
            review.mkdir()
            with patch.object(sys, "argv", ["export_sarif.py", str(review)]):
                self.assertEqual(mod.main(), 2)

    def test_export_sarif_main_success(self) -> None:
        mod = load_module("export_sarif_ok", SCRIPTS / "export_sarif.py")
        with tempfile.TemporaryDirectory() as tmp:
            review = Path(tmp) / "SECURITY_REVIEW"
            review.mkdir()
            finding = {
                "id": "F-20251115-099",
                "title": "Example",
                "category": "xss",
                "status": "candidate",
                "focus_area": "web",
                "locations": [{"file": "app.py", "line": 3, "function": "render"}],
                "entry_point": "/search",
                "trust_boundary": "html response",
                "attacker_control": "q param",
                "source_to_sink": "request -> template -> html sink without escape",
                "impact": "stored xss",
                "preconditions": [],
                "existing_mitigations_checked": [],
                "confidence": "medium",
                "reasoning_summary": "unescaped user content in template output",
            }
            verified = {
                "finding_id": "F-20251115-099",
                "verdict": "true_positive",
                "exploitability": "confirmed",
                "evidence": ["no autoescape on field"],
                "disproof_attempts": ["checked for bleach"],
                "mitigations_found": [],
                "poc_result": "reproduced",
                "reproduction_steps": [],
                "notes": "ok",
            }
            (review / "FINDINGS.jsonl").write_text(json.dumps(finding) + "\n", encoding="utf-8")
            (review / "VERIFIED.jsonl").write_text(json.dumps(verified) + "\n", encoding="utf-8")
            out = review / "FINDINGS.sarif"
            with patch.object(
                sys,
                "argv",
                ["export_sarif.py", str(review), "-o", str(out)],
            ):
                self.assertEqual(mod.main(), 0)
            self.assertTrue(out.is_file())

    def test_init_security_review_main(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "init_security_review.py"), "/tmp/cli-init-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Created:", result.stdout)


if __name__ == "__main__":
    unittest.main()