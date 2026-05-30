from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "init_security_review.py"
SPEC = importlib.util.spec_from_file_location("init_security_review", SCRIPT)
assert SPEC is not None
init_security_review = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(init_security_review)


class InitSecurityReviewTests(unittest.TestCase):
    def test_creates_expected_workspace_artifacts(self) -> None:
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)

            created = init_security_review.init_security_review(repo)
            review = repo / "SECURITY_REVIEW"

            expected_files = {
                "THREAT_MODEL.md",
                "SANDBOX.md",
                "FINDINGS.jsonl",
                "FINDINGS.md",
                "VERIFIED.jsonl",
                "TRIAGE.md",
                "PATCH_PLAN.md",
                "RUN_LOG.md",
            }
            self.assertEqual({path.name for path in created}, expected_files)
            for name in expected_files:
                self.assertTrue((review / name).is_file(), name)
            self.assertTrue((review / "PATCHES").is_dir())
            self.assertTrue((review / "POCS").is_dir())
            self.assertIn("Initialized SECURITY_REVIEW workspace.", (review / "RUN_LOG.md").read_text())

    def test_does_not_overwrite_existing_review_files(self) -> None:
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)
            review = repo / "SECURITY_REVIEW"
            review.mkdir()
            findings = review / "FINDINGS.md"
            run_log = review / "RUN_LOG.md"
            findings.write_text("existing findings\n", encoding="utf-8")
            run_log.write_text("existing log\n", encoding="utf-8")

            created = init_security_review.init_security_review(repo)

            self.assertNotIn(findings, created)
            self.assertNotIn(run_log, created)
            self.assertEqual(findings.read_text(encoding="utf-8"), "existing findings\n")
            self.assertEqual(run_log.read_text(encoding="utf-8"), "existing log\n")


if __name__ == "__main__":
    unittest.main()
