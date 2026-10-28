---
name: implement-test-fix
description: Make a small, scoped code change and verify it with local tests. Use when implementing a feature, fixing a bug, or adding tests in this capstone.
---

# Implement, Test, Fix

1. Use the existing task context and `CLAUDE.md`; do not repeat repository discovery.
2. Inspect only the directly relevant files and tests. State intended file paths briefly before editing.
3. Implement the smallest complete change. Keep generated code outside `wazuh-src/` unless explicitly authorized.
4. Run focused tests or a direct validation command. If a test fails, inspect the relevant failure, fix the cause, and rerun the affected tests.
5. Stop when tests pass or a genuine blocker remains. Do not broaden scope to unrelated refactors, architecture, deployment, or UI.
6. Report only changed files, exact test command and actual outcome, known limitations, and one next step. Never imply unrun integration tests passed.

Token discipline: avoid full-file dumps, repeated searches, speculative alternatives, and long explanations. Show only relevant snippets when necessary.
