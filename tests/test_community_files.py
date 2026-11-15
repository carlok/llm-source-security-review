from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADVISORY_URL = "https://github.com/carlok/llm-source-security-review/security/advisories/new"

REQUIRED_FILES = (
    "LICENSE",
    "README.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "AGENT.md",
    ".github/pull_request_template.md",
    ".github/dependabot.yml",
    ".github/workflows/ci.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
)


class CommunityFilesTests(unittest.TestCase):
    def test_required_community_files_exist(self) -> None:
        for rel in REQUIRED_FILES:
            path = ROOT / rel
            self.assertTrue(path.is_file(), rel)

    def test_security_md_points_to_private_reporting(self) -> None:
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn(ADVISORY_URL, text)
        self.assertNotRegex(
            text.lower(),
            r"open\s+(a\s+)?(public\s+)?issue",
        )
        self.assertNotRegex(text, r"github\.com/carlok/llm-source-security-review/issues/new")

    def test_issue_template_disables_blank_issues(self) -> None:
        text = (ROOT / ".github/ISSUE_TEMPLATE/config.yml").read_text(encoding="utf-8")
        self.assertIn("blank_issues_enabled: false", text)
        self.assertIn(ADVISORY_URL, text)

    def test_code_of_conduct_enforcement_contact(self) -> None:
        text = (ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
        self.assertIn("@carlok", text)
        self.assertIn("carlo.perassi@gmail.com", text)
        self.assertNotIn("example.com", text)

    def test_agent_md_requires_coverage_before_commit(self) -> None:
        text = (ROOT / "AGENT.md").read_text(encoding="utf-8")
        self.assertRegex(text.lower(), r"coverage.*commit|commit.*coverage")


if __name__ == "__main__":
    unittest.main()