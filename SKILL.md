---
name: llm-source-security-review
description: Defensive source-code security review workflow for LLM coding agents. Use when reviewing a repository for vulnerabilities, creating a SECURITY_REVIEW workspace, building a threat model, designing a local sandbox, discovering candidate findings, independently verifying findings, triaging security issues, patching verified vulnerabilities, or running PR-mode security review. Use only for codebases the user owns or is explicitly authorized to test.
---

# LLM Source Security Review

Use this skill to run an agent-assisted defensive security review without mixing discovery, verification, triage, and patching into one self-confirming pass.

Core rule: discovery optimizes for recall; verification, triage, and patching optimize for precision.

## Safety Boundaries

Proceed only for code the user owns or is authorized to test.

Never expose or use host SSH keys, cloud credentials, production `.env` files, password stores, browser cookies, package tokens, or deployment keys. Do not let autonomous agents access production systems. Run PoCs only against local sandbox targets. Treat prompt instructions as guidance, not isolation; enforce isolation with containers, VMs, network policy, file mounts, and credentials hygiene when execution is involved.

Do not attack third-party services, bypass real access controls, exfiltrate data, persist access, hide activity, or operate outside the local authorized target.

## Review Workspace

Create or update this repository-local directory:

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

Prefer `scripts/init_security_review.py` to initialize these artifacts without overwriting existing work:

```bash
python3 /path/to/skill/scripts/init_security_review.py .
```

Record review assumptions, commands, and major decisions in `SECURITY_REVIEW/RUN_LOG.md`.

## Workflow

1. Build the threat model before scanning.
2. Design or document the sandbox before running PoCs or patch validation.
3. Partition discovery by attack surface and write structured candidates.
4. Verify each candidate from a fresh context that sees only the finding, relevant PoC, codebase, threat model, and sandbox notes.
5. Triage by root cause, evidence, exploitability, and business impact.
6. Patch only verified findings, or probable true positives with explicit human approval.
7. Write a failing test or local PoC first, fix the root cause, run regression tests, confirm the original PoC is blocked, and search for variants.

For exact phase prompts, read `references/phase-prompts.md`. For JSONL schemas and rubrics, read `references/schemas-and-rubrics.md`.

## Role Separation

Use separate sessions, contexts, or agents for each role when possible:

- Threat-model agent: creates `THREAT_MODEL.md`.
- Sandbox agent: documents build, test, reset, secrets, and network controls in `SANDBOX.md`.
- Discovery agent: searches broadly and writes candidate findings.
- Verification agent: assumes each candidate is false until proven.
- Triage agent: deduplicates, ranks, and assigns likely owners/components.
- Patch agent: writes tests, fixes root cause, validates, and searches variants.
- Human owner: approves assumptions, severity, reporting, merging, and deployment.

Do not pass hidden reasoning or full discovery transcripts into verification. Pass raw artifacts and the minimum relevant context.

## Threat Model Gate

Do not start discovery until `THREAT_MODEL.md` defines:

- at least one attacker model;
- entry points;
- trust boundaries;
- trusted and untrusted inputs;
- in-scope vulnerability classes;
- out-of-scope cases.

If any of these are unknown, mark them explicitly and ask the owner only the questions needed to continue.

## Discovery Guidance

Prioritize areas where untrusted input crosses trust boundaries:

- deserialization, parsing, archive extraction, document/image processing;
- file upload, path handling, filesystem writes;
- auth, authorization, tenant isolation, admin-only features;
- template rendering, command execution, query construction;
- SSRF-capable URL fetchers and webhook handlers;
- cache, queue, background job, and dependency integration boundaries;
- cryptography, secrets handling, and supply-chain assumptions.

Write raw candidates to `SECURITY_REVIEW/FINDINGS.jsonl`; summarize in `SECURITY_REVIEW/FINDINGS.md`. Mark uncertainty instead of suppressing weak but plausible candidates during discovery.

## Verification Guidance

For each candidate, try to disprove it:

- Is the vulnerable path reachable from a real entry point?
- Does attacker-controlled input reach the sink intact?
- Are there upstream validators, auth gates, type constraints, feature flags, escaping, sandboxing, or deployment assumptions that block exploitation?
- Does a local PoC reproduce the issue, fail for a meaningful reason, or remain unproven?

Append one result per candidate to `SECURITY_REVIEW/VERIFIED.jsonl`.

## Triage Guidance

Deduplicate by root cause, not by symptom. Score severity only after writing evidence for reachability, attacker control, preconditions, authentication level, impact, blast radius, and existing controls.

Keep unproven findings in a separate section. Exclude false positives and out-of-scope findings from the action list.

## Patching Guidance

Patch only `true_positive` findings, or `probable_true_positive` findings with human approval.

Use this ladder:

1. Write a failing test or local PoC.
2. Fix the root cause with the minimal robust change.
3. Run focused build/tests.
4. Confirm the original PoC or test no longer succeeds.
5. Run relevant regression tests.
6. Search for variants of the same pattern and class.
7. Request independent patch review when the change is security-sensitive or non-trivial.

Document changed files, commands run, validation result, variant search result, residual risk, and human-review notes in `SECURITY_REVIEW/PATCH_PLAN.md`.

## Run Modes

Use minimal interactive mode when no sandbox exists: threat model, static discovery, verification by code inspection, human triage, then patch only high-confidence issues.

Use sandboxed verification mode when the project can run locally: threat model, sandbox, discovery with local PoCs, independent verifier executes PoCs, triage, patch ladder, re-scan.

Use parallel discovery mode for large codebases: partition attack surface, run separate discovery passes per partition, independently verify candidates, deduplicate centrally, then run one system-level pass.

Use pull-request mode for ongoing work: read the threat model, review changed files plus reachable call graph, look for changed trust-boundary crossings and validation logic, and produce a short PR security note.

## Stop Conditions

For a first review, run multiple discovery and verification cycles until net-new verified high/medium findings become rare relative to effort or the owner’s risk tolerance is met.

For maintenance, re-run after meaningful architecture, auth, parser, dependency, or deployment changes; before major releases; and on security-sensitive diffs.
