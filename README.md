# LLM Source Security Review

A Codex skill and standalone playbook for defensive source-code security reviews with LLM coding agents.

The workflow separates threat modeling, sandboxing, discovery, independent verification, triage, and patching so candidate vulnerabilities are not rubber-stamped by the same context that found them.

## Use as a Codex Skill

Install this directory under your Codex skills directory:

```bash
cp -R llm-source-security-review ~/.codex/skills/
```

Then invoke it as:

```text
Use $llm-source-security-review to run a defensive source-code security review of this repository.
```

The skill entrypoint is [`SKILL.md`](SKILL.md). Detailed phase prompts live in [`references/phase-prompts.md`](references/phase-prompts.md), and JSONL schemas plus rubrics live in [`references/schemas-and-rubrics.md`](references/schemas-and-rubrics.md).

## Use as a Plain Repository

From a target repository, initialize the review workspace:

```bash
python3 /path/to/llm-source-security-review/scripts/init_security_review.py .
```

This creates:

```text
SECURITY_REVIEW/
  THREAT_MODEL.md
  SANDBOX.md
  FINDINGS.jsonl
  FINDINGS.md
  VERIFIED.jsonl
  TRIAGE.md
  PATCH_PLAN.md
  PATCHES/
  POCS/
  RUN_LOG.md
```

Start with threat modeling before discovery. Patch only verified findings, or probable true positives with explicit human approval.

## Safety

Use this only for codebases you own or are explicitly authorized to test. Run proofs of concept only against local sandbox targets. Do not expose production credentials, host SSH keys, real `.env` files, cloud tokens, browser cookies, or deployment keys to agents.
