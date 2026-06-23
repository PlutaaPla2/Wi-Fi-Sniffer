# AGENTS.md

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
