# Capstone Project Rules

## Goal
Build the IT Security Configuration Compliance Monitoring System incrementally, reusing Wazuh where practical. Deliver a working, testable prototype before adding integration or UI features.

## Workspace boundaries
- Put new capstone code in `compliance-app/`; do not place it inside the Wazuh source tree.
- Treat `wazuh-src/` as read-only reference material. Never modify it unless I explicitly authorize a specific change.
- If the actual folder names differ, use the existing names; do not rename folders just to match this file.
- The downloaded Wazuh source is not a running installation. Do not claim live integration testing unless a running instance was actually configured and tested.

## Existing analysis — do not rediscover by default
- SCA policy definitions are under `ruleset/sca/`.
- SCA implementation references: `src/wazuh_modules/sca/` and `src/wazuh_modules/src/wm_sca.c`.
- SCA output examples: `docs/ref/modules/sca/output-samples.md`.
- Prior analysis identified SCA state results in the `wazuh-states-sca` index and did not identify a dedicated SCA API controller/route in this source snapshot.
- Start from this summary. Recheck a specific fact only when required for the current task or when evidence contradicts it.

## Coding workflow
- Make the smallest change that completes the current task. Do not implement future phases early.
- Inspect only files directly needed for the task; do not rescan the repository or print large files.
- Prefer existing dependencies and patterns. Do not add a dependency unless necessary.
- After editing, run the narrowest relevant tests, fix failures, and rerun them.
- Never claim a test, integration, or security check passed unless it was actually run.
- Do not use real company data, credentials, tokens, or secrets in code or test fixtures.
- Do not run destructive commands or change environment configuration without approval.

## Token-efficient responses
- Do not repeat repository discovery, restate the full project, or narrate routine actions.
- Do not paste whole files or huge command outputs into chat. Summarize only important errors.
- Finish with: changed files, commands/tests and actual results, limitations, and one next step.
