# Guidance for coding agents

When changing code in this repository:

1. Run the full test suite before each commit: `python3 -m coverage run -m unittest discover -s tests -v` then `python3 -m coverage report`.
2. **Always try to increase line coverage** with focused unit tests for new or changed logic. Do not commit without running coverage; add or update tests until coverage does not regress.
3. Keep `SECURITY_REVIEW/` artifacts out of this repository unless the user explicitly requests committing review output.
4. Do not commit secrets, personal infrastructure details, or production credentials.
5. Match existing style in `scripts/` and `references/`; prefer small, verifiable diffs.
6. Update `docs/TODO-handoff.md` when you make claims that the next agent should verify.

Community policy files under `.github/`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md` must stay compliant with `tests/test_community_files.py`.