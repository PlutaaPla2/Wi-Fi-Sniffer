# AGENTS.md

## Multi-agent architecture
The main orchestrator operates under the framework defined in this `AGENTS.md`. It plans work, delegates scoped tasks when useful, and reviews results before responding.

### Agent routing
- **Main Orchestrator:** Prefer `gpt-5.6-sol-extra-high` for system architecture, deep reasoning, step-by-step planning, complex problem-solving, structural blueprints, and final review.
- **Research Sub-Agent:** Prefer `gpt-5.6-sol-medium` when work genuinely requires up-to-date internet research, external documentation lookups, data scraping, or external knowledge bases.
- **Action Sub-Agent:** Prefer `gpt-terra-high` for implementation, file edits, refactoring, and other scoped execution tasks.
- These named models are preferences, not guarantees. Use the closest available capability when a preferred model is unavailable.
- If delegation or model selection is unavailable, the main agent may execute the task directly.
- Delegation is not required for trivial conversation or read-only inspection.
- Every agent and sub-agent inherits and must follow all safety, coding, and testing rules in this file.

### Standard operating procedure
1. **Plan:** The main orchestrator analyzes the request and defines the required steps.
2. **Research:** When needed, a research sub-agent gathers and summarizes the required external context.
3. **Execute:** When delegation is available and useful, an action sub-agent performs the scoped implementation or execution work.
4. **Review:** The main orchestrator verifies the result against the original request before finalizing the response.

## Project goal
This project detects Wi-Fi probe/client activity to estimate room occupancy for AC control.

## Safety rules
- Do not delete files unless I explicitly ask.
- Do not edit `.env`, API keys, credentials, tokens, or private config files.
- Do not run commands that install packages, remove files, change Git history, or access the network without asking first.
- Before making changes, explain the files you will edit.
- After changes, show `git diff` and summarize what changed.
- Prefer small, reviewable patches.

## Coding rules
- Keep code simple and readable.
- Add comments only where the logic is not obvious.
- Do not over-engineer with ML unless the rule-based approach is not enough.
- For counting devices, avoid double-counting the same MAC/session.
- Keep logs useful for debugging false counts.

## Testing rules
- Run existing tests if available.
- If changing counting logic, add or update tests.
- Do not claim the code works unless tests or manual checks were run.
