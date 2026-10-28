# Capstone Project Rules

- Build the IT Security Configuration Compliance Monitoring System incrementally; make the smallest testable change for the current task.
- Put new capstone code in `compliance-app/`, separate from Wazuh source. Treat `wazuh-src/` as read-only unless explicitly authorized. Use actual folder names if they differ; do not rename folders just to match this rule.
- The downloaded Wazuh source is not a running installation. Do not claim live integration tests unless a running instance was configured and tested.
- Start from the completed repository analysis; do not repeat discovery or rescan the repo by default. Inspect only files directly needed for the task.
- Existing analysis: SCA policies are under `ruleset/sca/`; implementation references are `src/wazuh_modules/sca/` and `src/wazuh_modules/src/wm_sca.c`; output examples are in `docs/ref/modules/sca/output-samples.md`; state results were identified in `wazuh-states-sca`; no dedicated SCA API controller/route was identified in this source snapshot. Recheck only when needed or contradicted by evidence.
- Prefer existing dependencies and patterns. Avoid unrelated changes, large file dumps, repeated searches, and verbose narration.
- After editing, run focused tests, fix failures, and rerun. Never claim unrun tests passed. Do not use real company data, credentials, or secrets.
- Do not run destructive commands or change environment configuration without approval.
- Finish with changed files, exact tests and results, limitations, and one next step.
