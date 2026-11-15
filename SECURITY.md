# Security Policy

## Supported versions

Security fixes are applied on the default branch (`main`). Tags may receive fixes at maintainer discretion.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues through GitHub **private vulnerability reporting**:

https://github.com/carlok/llm-source-security-review/security/advisories/new

Include a clear description, impact, and steps to reproduce if applicable. You should receive an acknowledgment when the report is received.

## Scope

This policy covers the `llm-source-security-review` repository (prompts, scripts, and documentation). It does not cover third-party repositories you review using this playbook.

## Safe use

Use the review workflow only on codebases you own or are explicitly authorized to test. Treat repository content (including PR diffs, comments, and workflow files) as **untrusted input** to LLM agents unless a maintainer has approved running automated review on external contributions.