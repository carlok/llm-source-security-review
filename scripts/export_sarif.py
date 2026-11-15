#!/usr/bin/env python3
"""Export verified findings to SARIF 2.1.0 for GitHub code scanning uploads."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from finding_tools import export_sarif


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "review_dir",
        nargs="?",
        default="SECURITY_REVIEW",
        help="Path to SECURITY_REVIEW directory (default: SECURITY_REVIEW)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output SARIF path (default: <review_dir>/FINDINGS.sarif)",
    )
    parser.add_argument(
        "--include-unproven",
        action="store_true",
        help="Include unproven verdicts in SARIF output",
    )
    args = parser.parse_args()
    root = Path(args.review_dir).resolve()
    findings = root / "FINDINGS.jsonl"
    verified = root / "VERIFIED.jsonl"
    output = Path(args.output) if args.output else root / "FINDINGS.sarif"

    if not findings.is_file():
        print(f"Missing {findings}", file=sys.stderr)
        return 2
    if not verified.is_file():
        print(f"Missing {verified}", file=sys.stderr)
        return 2

    count = export_sarif(findings, verified, output, include_unproven=args.include_unproven)
    print(f"Wrote {count} result(s) to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())