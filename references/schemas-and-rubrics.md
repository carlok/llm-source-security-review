# Schemas and Rubrics

## FINDINGS.jsonl Schema

Append one JSON object per candidate finding:

```json
{
  "id": "F-YYYYMMDD-NNN",
  "title": "short title",
  "category": "vulnerability class",
  "status": "candidate|candidate_with_poc|weak_candidate",
  "focus_area": "name",
  "locations": [{"file": "path", "line": 0, "function": "name"}],
  "entry_point": "how attacker input enters",
  "trust_boundary": "which boundary is crossed",
  "attacker_control": "what the attacker controls",
  "source_to_sink": "data/control flow summary",
  "impact": "security impact if exploitable",
  "preconditions": ["required condition"],
  "existing_mitigations_checked": ["validation/auth/type checks/etc."],
  "cwe_ids": ["CWE-89"],
  "owasp_category": "A03:2021-Injection",
  "asvs_refs": ["V5.3.4"],
  "severity": "critical|high|medium|low|informational",
  "poc_path": "SECURITY_REVIEW/POCS/... or null",
  "reproduction_steps": ["local-only steps if any"],
  "confidence": "low|medium|high",
  "confidence_score": 0.0,
  "fingerprint": "optional; computed by scripts if omitted",
  "reasoning_summary": "brief evidence summary with file/line cites, no hidden reasoning"
}
```

### Field notes

- **`cwe_ids`**: Use `CWE-###` strings. Prefer [CWE Top 25](https://cwe.mitre.org/top25/) and class-specific children (for example CWE-89 for SQL injection).
- **`owasp_category`**: Optional OWASP Top 10:2021 label for reporting.
- **`confidence_score`**: Numeric 0.0–1.0; discovery may use 0.3–0.6, verification should raise or lower based on evidence.
- **`source_to_sink`**: Required narrative of source → propagation → sink (Semgrep-style taint summary).
- **`fingerprint`**: Optional dedup key; `scripts/finding_tools.py` can derive `finding_fingerprint()` from category, locations, and flow.

Validate JSONL with:

```bash
python3 /path/to/llm-source-security-review/scripts/validate_findings.py SECURITY_REVIEW
```

## VERIFIED.jsonl Schema

Append one JSON object per verification attempt:

```json
{
  "finding_id": "F-YYYYMMDD-NNN",
  "verdict": "true_positive|probable_true_positive|unproven|false_positive|duplicate",
  "exploitability": "confirmed|plausible|not_shown|disproved",
  "evidence": ["specific evidence"],
  "disproof_attempts": ["what you checked to invalidate it"],
  "mitigations_found": ["auth/validation/sandbox/etc."],
  "poc_result": "reproduced|failed|not_available|not_run",
  "reproduction_steps": ["local-only steps"],
  "confidence_score": 0.0,
  "notes": "brief summary"
}
```

`true_positive` and `probable_true_positive` verdicts require a non-empty `evidence` list (enforced by `validate_findings.py`).

## Verification Verdicts

| Verdict | Meaning |
|---|---|
| `true_positive` | Reproducible or strongly proven under the project threat model. |
| `probable_true_positive` | Evidence is strong but reproduction is incomplete. |
| `unproven` | Plausible but insufficient evidence; keep for later or manual review. |
| `false_positive` | Not reachable, not attacker-controlled, mitigated, trusted input, or out of scope. |
| `duplicate` | Same root cause as another finding. |

## Deduplication Rules

Treat findings as duplicates when they share the same root cause, same missing central validation, same bug through multiple symptoms, cause/consequence in one path, or one patch would disarm both PoCs.

Treat findings as distinct when they are different vulnerability classes in the same file, different variables reaching different sinks, independent bugs inside the same helper, separate endpoints requiring separate fixes, or same class with different root causes.

## Severity Factors

Assign severity only after evaluating:

| Factor | Questions |
|---|---|
| Reachability | Can an attacker reach this from a real entry point? |
| Attacker control | Does untrusted input reach the sink intact? |
| Preconditions | Does it require non-default config, feature flags, race timing, local access, or special data? |
| Authentication | Unauthenticated, authenticated user, privileged user, admin, internal service only? |
| Impact type | Read, write, delete, execute, bypass, corrupt, deny service? |
| Blast radius | One user, one tenant, all tenants, host, cluster, supply chain? |
| Existing controls | WAF, auth gateway, sandbox, allowlist, type system, validation, rate limits? |

Suggested defaults:

- Critical/High: unauthenticated or low-precondition remote path with serious confidentiality, integrity, or execution impact.
- Medium: authenticated path, meaningful preconditions, limited blast radius, or moderate impact.
- Low: local-only, many preconditions, limited impact, or unlikely attacker control.
- Informational: hardening issue without demonstrated exploitability.

Adjust thresholds to the project.

## SARIF export

After verification, export actionable results for GitHub code scanning (SARIF 2.1.0):

```bash
python3 /path/to/llm-source-security-review/scripts/export_sarif.py SECURITY_REVIEW
```

By default only `true_positive` and `probable_true_positive` rows are exported. Use `--include-unproven` for exploratory uploads. See [GitHub SARIF documentation](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).

## Final Human Checklist

- The finding matches the project threat model.
- The attack path is reachable.
- Attacker-controlled input reaches the relevant sink.
- Existing mitigations were checked.
- Severity is evidence-based.
- Duplicates were collapsed.
- A failing test or local PoC exists where practical.
- The patch fixes the root cause.
- Existing tests pass.
- The original PoC is blocked.
- Variants were searched.
- A human owner reviewed the patch.
- The threat model was updated if assumptions changed.
