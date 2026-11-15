# Contributing

Thanks for helping improve LLM Source Security Review.

## Getting started

1. Fork the repository and create a branch from `main`.
2. Install Python 3.10+ (3.11+ recommended).
3. Run tests locally:

```bash
python3 -m pip install coverage
python3 -m coverage run -m unittest discover -s tests -v
python3 -m coverage report
```

## Pull requests

- Keep changes focused; tie prompt or schema changes to evidence-based security review practice.
- Update `references/schemas-and-rubrics.md` when JSONL fields change.
- Add or extend unit tests for any new Python helpers.
- Do not include secrets or customer-specific data in examples.

Use the pull request template when opening a PR.

## Security vulnerabilities in this project

Please **do not** open public GitHub issues for vulnerabilities. Report them through [private vulnerability reporting](https://github.com/carlok/llm-source-security-review/security/advisories/new).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Participating means agreeing to uphold that code.