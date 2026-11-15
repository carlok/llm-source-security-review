# Handoff for the next agent

Use this checklist to verify claims from the tuning PR. Run commands from the repository root unless noted.

## Verify environment

```bash
python3 --version   # expect 3.10+
git status          # clean tree after checkout
```

## Unit tests and coverage

```bash
python3 -m pip install coverage
python3 -m coverage run -m unittest discover -s tests -v
python3 -m coverage report --fail-under=85
```

**Expected:** all tests pass; total coverage ≥ 85% on `scripts/`.

## Init workspace smoke test

```bash
rm -rf /tmp/handoff-review
python3 scripts/init_security_review.py /tmp/handoff-review
ls /tmp/handoff-review/SECURITY_REVIEW
```

**Expected:** eight files plus `PATCHES/` and `POCS/` directories; `RUN_LOG.md` mentions initialization.

## JSONL validation and SARIF export

```bash
python3 -m unittest tests.test_finding_tools -v
python3 scripts/validate_findings.py /tmp/handoff-review/SECURITY_REVIEW
# after adding fixture JSONL from test_finding_tools or CI workflow snippet:
python3 scripts/export_sarif.py /tmp/handoff-review/SECURITY_REVIEW --include-unproven
```

**Expected:** `Validation OK` on empty JSONL; SARIF file exists when fixtures present.

## Community files test

```bash
python3 -m unittest tests.test_community_files -v
```

**Expected:** `SECURITY.md` contains only private advisory URL; no public issue reporting.

## CI (if you have network)

Confirm GitHub Actions workflow `.github/workflows/ci.yml` passes on the PR branch.

---

## Prioritized TODO (not implemented or partial)

| Priority | Item | Acceptance criteria |
| --- | --- | --- |
| P1 | GitHub Action wrapper | Workflow calls this skill's prompts on `pull_request`; documents trusted-PR requirement like Anthropic action |
| P1 | Prompt-injection eval fixtures | Corpora of malicious comments; regression test that agents still emit `false_positive` appropriately |
| P2 | Integrate osv-scanner / pip-audit in supply-chain pass | Optional CI job populates `FINDINGS.md` supply chain section with scanner output |
| P2 | SARIF upload example workflow | Sample `upload-sarif` job with `category: llm-security-review` |
| P3 | JSON Schema files | Machine-readable schemas for FINDINGS/VERIFIED alongside markdown docs |
| P3 | Semgrep/CodeQL rule crosswalk | Map common rules to CWE for hybrid human+SAST workflows |

---

## Untested claims (explicit)

- **End-to-end LLM runs** of updated prompts on a real large repo — not executed in the tuning PR; only prompt/schema changes and Python helpers are tested.
- **SARIF upload to GitHub** — export format is tested in unit tests; upload to GitHub Code Scanning was not performed in this environment.
- **Coverage of prompt text** — prompts are not unit-tested; correctness is documentation-only.

---

## Starter prompt for the next agent

```text
You are continuing work on github.com/carlok/llm-source-security-review.

1. Read AGENT.md, SKILL.md, references/phase-prompts.md, references/schemas-and-rubrics.md, and docs/TODO-handoff.md.
2. Run the verification commands in docs/TODO-handoff.md and fix any failures.
3. Pick the highest-priority TODO row you can complete in one PR without scope creep.
4. Keep community file tests passing; increase scripts/ coverage before each commit.
5. Open a PR with links to sources for any new security guidance you add.
```