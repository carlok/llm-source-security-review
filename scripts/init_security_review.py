#!/usr/bin/env python3
"""Initialize SECURITY_REVIEW artifacts without overwriting existing files."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path


FILES = {
    "THREAT_MODEL.md": "# Threat Model\n\n",
    "SANDBOX.md": "# Sandbox\n\n",
    "FINDINGS.jsonl": "",
    "FINDINGS.md": "# Findings\n\n",
    "VERIFIED.jsonl": "",
    "TRIAGE.md": "# Triage\n\n",
    "PATCH_PLAN.md": "# Patch Plan\n\n",
}


def append_run_log(path: Path) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_log = path / "RUN_LOG.md"
    if run_log.exists():
        return
    run_log.write_text(
        "# Run Log\n\n"
        f"- {timestamp}: Initialized SECURITY_REVIEW workspace.\n",
        encoding="utf-8",
    )


def init_security_review(repo: Path) -> list[Path]:
    root = repo.resolve() / "SECURITY_REVIEW"
    root.mkdir(parents=True, exist_ok=True)
    (root / "PATCHES").mkdir(exist_ok=True)
    (root / "POCS").mkdir(exist_ok=True)

    created: list[Path] = []
    for name, contents in FILES.items():
        target = root / name
        if not target.exists():
            target.write_text(contents, encoding="utf-8")
            created.append(target)

    if not (root / "RUN_LOG.md").exists():
        append_run_log(root)
        created.append(root / "RUN_LOG.md")

    return created


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Repository root where SECURITY_REVIEW should be created.",
    )
    args = parser.parse_args()

    created = init_security_review(Path(args.repo))
    if created:
        print("Created:")
        for path in created:
            print(f"  {path}")
    else:
        print("SECURITY_REVIEW already initialized; no files overwritten.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
