#!/usr/bin/env python3
"""Validate SECURITY_REVIEW JSONL files against the project schema."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from finding_tools import validate_findings_file, validate_verified_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "review_dir",
        nargs="?",
        default="SECURITY_REVIEW",
        help="Path to SECURITY_REVIEW directory (default: SECURITY_REVIEW)",
    )
    args = parser.parse_args()
    root = Path(args.review_dir).resolve()
    findings = root / "FINDINGS.jsonl"
    verified = root / "VERIFIED.jsonl"

    issues = []
    issues.extend(validate_findings_file(findings))
    issues.extend(validate_verified_file(verified))

    if issues:
        print(f"Validation failed ({len(issues)} issue(s)):", file=sys.stderr)
        for issue in issues:
            print(f"  line {issue.line}: {issue.message}", file=sys.stderr)
        return 1

    print("Validation OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())