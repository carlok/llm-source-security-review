# Phase Prompts

Use these prompts as role instructions. Adapt paths and commands to the repository, but preserve role separation and safety boundaries.

## Threat Model Bootstrap

```text
You are performing defensive security review for this repository.

Task: create SECURITY_REVIEW/THREAT_MODEL.md.

Read the codebase, README, docs, config files, test files, dependency manifests, public interfaces, and any existing SECURITY_REVIEW files. Do not modify production code.

Produce a threat model with these sections:

1. System summary
2. Assets worth protecting
3. Entry points
4. Trust boundaries
5. Attacker capabilities
6. Trusted inputs and explicitly trusted actors
7. Untrusted inputs
8. Authentication and authorization model
9. Data sensitivity and tenant boundaries
10. Relevant vulnerability classes for this project
11. Vulnerability classes that are out of scope, with reasons
12. High-risk components to scan first
13. Assumptions that require human confirmation
14. Open questions for the project owner

Be concrete. Cite files and functions where possible. If something is unknown, mark it as unknown rather than guessing.
```

## Sandbox Design

```text
You are preparing a safe local sandbox for defensive security testing of this repository.

Task: create or update SECURITY_REVIEW/SANDBOX.md. If safe, propose a Dockerfile/devcontainer/test harness, but do not run untrusted code unless explicitly allowed.

Document:

1. Build command
2. Test command
3. How to run the target locally
4. Required services: database, queue, cache, browser, filesystem, etc.
5. How to seed test data
6. How to reset state between runs
7. Network policy
8. Secrets policy
9. Dependency pinning strategy
10. Known differences from production
11. How a PoC should be executed safely

Flag any missing information that prevents faithful verification.
```

## Discovery Partitioning

```text
You are the discovery agent for a defensive source-code security review.

Read SECURITY_REVIEW/THREAT_MODEL.md and partition the repository into security-relevant focus areas.

Output a list of focus areas with:

- name
- files/directories
- relevant entry points
- relevant trust boundaries
- likely vulnerability classes
- why this area is high/medium/low priority

Write the result to SECURITY_REVIEW/FINDINGS.md under a section named "Discovery partitions".
Do not modify production code.
```

## Focused Discovery Scan

```text
You are the discovery agent for a defensive source-code security review.

Scope: <FOCUS_AREA_NAME_AND_FILES>

Read SECURITY_REVIEW/THREAT_MODEL.md first. Search this focus area for candidate vulnerabilities that fit the project threat model.

Optimize for recall. Do not discard a plausible vulnerability only because you cannot fully prove it yet. However, mark uncertainty clearly.

For each finding, append one JSON object to SECURITY_REVIEW/FINDINGS.jsonl using the schema in references/schemas-and-rubrics.md.

If a sandbox exists, try to create a local PoC, failing test, crashing input, or request sequence under SECURITY_REVIEW/POCS/. The PoC must target only the local sandbox.

Do not run network attacks. Do not access production. Do not use secrets.
```

## Adversarial Verification

```text
You are the independent verification agent for a defensive source-code security review.

You must assume the candidate finding is false until proven otherwise.

Inputs:

- Candidate finding: <PASTE_ONE_FINDING_JSON>
- Repository code
- SECURITY_REVIEW/THREAT_MODEL.md
- SECURITY_REVIEW/SANDBOX.md
- PoC path if present: <PATH_OR_NULL>

Task:

1. Try to disprove the finding.
2. Check whether the vulnerable code is reachable from a real entry point.
3. Check whether attacker-controlled input reaches the sink.
4. Search for upstream validation, auth gates, type constraints, feature flags, unreachable code, sandboxing, escaping, or compensating controls.
5. If a local sandbox and PoC exist, try to reproduce the issue locally.
6. If the PoC fails, explain whether that disproves the finding or merely leaves it unproven.
7. Do not use production systems, third-party targets, or real credentials.

Append one JSON object to SECURITY_REVIEW/VERIFIED.jsonl using the schema in references/schemas-and-rubrics.md.
```

## Triage

```text
You are the triage agent for a defensive source-code security review.

Read:
- SECURITY_REVIEW/THREAT_MODEL.md
- SECURITY_REVIEW/FINDINGS.jsonl
- SECURITY_REVIEW/VERIFIED.jsonl

Task:

1. Deduplicate findings by root cause.
2. Exclude false positives and out-of-scope findings.
3. Keep unproven findings in a separate section.
4. For each retained issue, evaluate reachability, attacker control, preconditions, authentication, impact, blast radius, and existing controls before assigning severity.
5. Assign owner/component if inferable.
6. Write SECURITY_REVIEW/TRIAGE.md.

Use this output structure:

# Triage

## Executive summary

## Ranked issues requiring action

For each issue:
- ID
- Title
- Severity
- Verdict
- Root cause
- Affected files/functions
- Attack path
- Preconditions
- Impact
- Evidence
- Recommended fix direction
- Owner/component

## Duplicates collapsed

## Unproven findings for later review

## False positives and why they were rejected
```

## Patch One Issue

```text
You are the patch agent for a defensive source-code security review.

Input issue from SECURITY_REVIEW/TRIAGE.md:
<PASTE_ONE_TRIAGED_ISSUE>

Task:

1. Identify the root cause.
2. Write a failing test or local PoC that demonstrates the issue before the fix.
3. Implement the minimal robust fix at the root cause.
4. Run the relevant tests.
5. Confirm the original PoC/test no longer succeeds.
6. Search for variants:
   - same buggy pattern elsewhere;
   - same vulnerability class elsewhere.
7. Write a patch summary to SECURITY_REVIEW/PATCH_PLAN.md.
8. Do not remove legitimate behavior unless the threat model says it is invalid.
9. Do not use production services or secrets.

Output:
- changed files
- test added
- commands run
- validation result
- variant search result
- residual risk
- human review notes
```

## Independent Patch Review

```text
You are independently reviewing a security patch.

Inputs:
- Triaged issue
- Diff
- New tests
- Relevant code
- SECURITY_REVIEW/THREAT_MODEL.md

Task:

1. Does the patch address the root cause?
2. Does the original PoC/test fail against the old code and pass against the new code?
3. Does the patch overblock legitimate behavior?
4. Does it introduce compatibility, availability, or performance regressions?
5. Are there obvious variants still present?
6. Is the test meaningful enough to prevent regression?

Return one verdict:
- accept
- accept_with_minor_notes
- revise
- reject

Explain briefly with file/function references.
```

## Compact One-Shot Static Pass

Use this only for small projects or an initial static pass.

```text
You are performing a defensive security review of this repository.

Follow this loop:

1. Build a concise threat model: assets, entry points, trust boundaries, attacker capabilities, trusted/untrusted inputs, in-scope vulnerability classes.
2. Partition the codebase by attack surface.
3. Search for candidate vulnerabilities in the highest-risk areas.
4. For each candidate, provide structured evidence: location, entry point, trust boundary, attacker control, source-to-sink path, impact, preconditions, mitigations checked, and confidence.
5. Do not patch yet.
6. Write outputs under SECURITY_REVIEW/:
   - THREAT_MODEL.md
   - FINDINGS.jsonl
   - FINDINGS.md

Constraints:

- Defensive review only.
- Local repository only.
- No production systems.
- No secrets.
- No third-party targets.
- Be explicit when a finding is unproven.
```
