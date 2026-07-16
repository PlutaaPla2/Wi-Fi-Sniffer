# Night Sniffer

Passive 802.11 WiFi reconnaissance tool. Runs on a Raspberry Pi 4 (Kali Linux)
with an external AR9271 USB adapter (`wlan1`) in monitor mode. Captures 802.11
management frames, fingerprints devices, tracks sessions across MAC-address
randomization, and estimates physical device / people counts in a monitored
area. Python + Scapy. The onboard NIC is management-only (SSH via the company AP);
capture happens exclusively on `wlan1`.

## Ethical hard rules — READ FIRST

These are non-negotiable project constraints, **not** style preferences. Any
change that touches, relaxes, or works around them requires **explicit human
sign-off before you write code**.

- **Passive capture only.** Never add active techniques: no deauth/disassoc
  injection, no frame transmission of any kind, no probe/RTS flooding. The tool
  only listens.
- **Never decrypt payloads** or attempt to. Only 802.11 management-frame
  metadata is in scope.
- **Do not widen collection.** No payload capture, no forwarding of raw captures
  off-device. If a task implies exporting or shipping capture data anywhere,
  stop and flag it.
- **Captured data is PII.** `*.csv` and `*.pcap` outputs are gitignored and must
  stay that way. Do not add code that copies, forwards, or commits capture files.
- If a task seems to require crossing any of these lines, **STOP** and raise it
  under "Suggestions / Issues noticed" instead of implementing it.

## Commands

<!-- Monitor mode + raw sockets + `iw` require root. Fill in the lint/test
     invocations once settled. -->
- Run (no channel hop): `sudo python3 night_sniffer_v3.py`
- Run (rotate channels 1–13): `sudo python3 night_sniffer_v3.py --hop`
- Put `wlan1` in monitor mode manually:
  `sudo ip link set wlan1 down && sudo iw dev wlan1 set type monitor && sudo ip link set wlan1 up`
- Lint: `...` <!-- GitHub Actions lint workflow exists; add the local command (e.g. ruff/flake8) -->
- Test: `...`

## Codebase layout

<!-- Two parallel lineages being progressively merged. -->
- `src/night_sniffer_v3.py` — active development target (capture, fingerprint, session tracking, reporting).
- `src/wifi_sniffer.py` / `src/config.py` / `src/device_estimator.py` — older code; unused for now.
- `scripts/` — shell helpers.
- Data outputs (`*.csv`, `*.pcap`) are gitignored (PII).

## Rules

### Scope of changes
- IMPORTANT: Only modify what the task explicitly asks for. Do NOT touch
  related or nearby code, even if it looks like it needs improvement.
- If you spot a bug, a risky pattern, or a better approach in code you are
  NOT allowed to touch, do not fix it. Instead, mention it in your response
  under a "Suggestions / Issues noticed" section so the human can handle it
  later.
- Make minimal changes. No drive-by refactoring, renaming, or reformatting
  of untouched code.

### Git
- NEVER run `git add`, `git commit`, `git push`, or any command that stages,
  commits, or rewrites history. The human handles all commits personally.
- Read-only git commands are fine and encouraged when useful:
  `git log`, `git diff`, `git show`, `git blame`, `git status`.
- Workflow is GitHub Flow: feature branches + PRs, never work directly on `main`.
  Two people share the Pi account in separate directories, so keep changes
  scoped to the file/branch under discussion to avoid merge conflicts.

### Work log
- After completing each task, append a short entry to `explanation/CLAUDE_LOG.md` in the
  project root. Create the file if it does not exist.
- Log format: follows the format inside what you see in CLAUDE_LOG.md
- Never delete or rewrite existing log entries; append only.

### General
- When unsure between two approaches, explain both and let the human choose.
- Run the project's test/lint commands after making code changes.
- Do not add new dependencies without asking first.
- Ground explanations in the actual current code state, not generic descriptions.

## Conventions

- Python with type hints throughout; thorough inline comments explaining intent,
  not just mechanics.
- Keep configuration separated from logic.
- Use `__file__`-anchored paths, never CWD-relative paths, for anything that
  reads/writes files.
- Prefer `subprocess.run` (with return-code checks) over `os.system`.
- When walking 802.11 IEs, walk the raw TLV bytes directly — Scapy's `Dot11Elt`
  layer chain silently truncates at unrecognized elements and falls back to `Raw`.
