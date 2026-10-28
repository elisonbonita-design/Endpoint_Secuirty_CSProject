# Capstone coding-agent starter

This pack supports Claude Code, Cline, or both. Copy the chosen configuration files into the **workspace root where you want the agent to work**.

## Suggested workspace layout

```text
capstone-workspace/
├── CLAUDE.md                  # Claude Code only
├── .claude/skills/            # Claude Code only
├── .clinerules/               # Cline only
├── .cline/skills/             # Cline only
├── compliance-app/            # new capstone code goes here
└── wazuh-src/                 # extracted Wazuh source ZIP; reference only
```

If your extracted source or project folders have different names, either rename them yourself or edit the two rule files to match. Do not move new code into the Wazuh source tree.

## Claude Code

Copy `CLAUDE.md` and `.claude/` into the workspace root. Start the terminal in that workspace and run `claude`. Use `/context` to confirm the memory file loaded, and `/implement-test-fix` to invoke the skill.

## Cline

Copy `.clinerules/` and `.cline/` into the workspace root. Cline's rule and skill files are separate from Claude Code's, so do not assume `CLAUDE.md` alone configures Cline. Use the Skills menu or type `/implement-test-fix` to invoke the skill.

## Token-efficiency notes

- Start with this one skill. Its short description is available for matching; its full instructions load when invoked/relevant.
- Do not install several overlapping planning, coding, debugging, and review skills at once.
- Add an API/security-review skill later, when implementing API routes, authorization, or encryption—not for the initial scoring helper.
- Keep agent tasks limited to one testable deliverable and ask for test commands/results, not long explanations.
